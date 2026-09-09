//! Caches for validated, account-independent API results.

use std::collections::BTreeSet;
use std::future::Future;
use std::hash::Hash;
use std::num::NonZeroUsize;
use std::sync::{Arc, OnceLock};
use std::time::{Duration, SystemTime};

use fedimint_core::PeerId;
use fedimint_core::config::FederationId;
use fedimint_core::core::ModuleInstanceId;
use fedimint_core::module::ApiVersion;
use fedimint_core::time::now;
use lru::LruCache;
use serde::Serialize;
use tokio::sync::Mutex;

/// Prevent an injected cache from being reused with a different validation
/// context.
#[derive(Debug, Default)]
pub struct SharedApiScope(OnceLock<serde_json::Value>);

impl SharedApiScope {
    pub fn bind(
        &self,
        federation: FederationId,
        instance: ModuleInstanceId,
        version: ApiVersion,
        config: &impl Serialize,
        peers: &BTreeSet<PeerId>,
    ) -> anyhow::Result<()> {
        let scope = serde_json::to_value((federation, instance, version, config, peers))?;
        anyhow::ensure!(
            self.0.get_or_init(|| scope.clone()) == &scope,
            "Shared API cache belongs to a different federation, module, or configuration"
        );
        Ok(())
    }
}

type Entry<V> = Arc<Mutex<Option<(SystemTime, Arc<V>)>>>;

/// Shares successful results and concurrent fetches for identical keys.
///
/// Only the per-key lock is held during a fetch. Cancellation or failure leaves
/// the entry retryable by another caller using its own API. Active entries are
/// never evicted; capacity limits idle entries on subsequent accesses.
#[derive(Debug)]
pub struct SharedCache<K: Hash + Eq, V> {
    entries: Mutex<LruCache<K, Entry<V>>>,
    capacity: NonZeroUsize,
    ttl: Option<Duration>,
}

impl<K: Hash + Eq + Clone, V> SharedCache<K, V> {
    pub fn new(capacity: NonZeroUsize, ttl: Option<Duration>) -> Self {
        Self {
            entries: Mutex::new(LruCache::unbounded()),
            capacity,
            ttl,
        }
    }

    pub async fn get_or_try_init<E, F: Future<Output = Result<V, E>>>(
        &self,
        key: K,
        fetch: impl FnOnce() -> F,
    ) -> Result<Arc<V>, E> {
        let entry = {
            let mut entries = self.entries.lock().await;
            // Evict only idle entries, so cache pressure cannot duplicate an
            // in-flight request (including one with waiting callers).
            while entries.len() >= self.capacity.get() {
                let idle = entries
                    .iter()
                    .rev()
                    .find(|(k, v)| *k != &key && Arc::strong_count(v) == 1)
                    .map(|(k, _)| k.clone());
                let Some(idle) = idle else { break };
                entries.pop(&idle);
            }
            entries
                .get_or_insert(key, || Arc::new(Mutex::new(None)))
                .clone()
        };
        let mut value = entry.lock().await;
        if let Some((created, cached)) = &*value
            && self.ttl.is_none_or(|ttl| {
                now()
                    .duration_since(*created)
                    .is_ok_and(|elapsed| elapsed < ttl)
            })
        {
            return Ok(cached.clone());
        }
        let fetched = Arc::new(fetch().await?);
        *value = Some((now(), fetched.clone()));
        Ok(fetched)
    }
}

#[cfg(test)]
mod tests {
    use std::convert::Infallible;
    use std::future::pending;
    use std::task::Poll;

    use futures::{FutureExt, poll};

    use super::*;

    fn cache(ttl: Option<Duration>) -> SharedCache<u64, Vec<u64>> {
        SharedCache::new(NonZeroUsize::new(1).unwrap(), ttl)
    }

    #[tokio::test]
    async fn shares_in_flight_even_under_eviction_pressure() {
        let cache = cache(None);
        let (tx, rx) = tokio::sync::oneshot::channel();
        let first = cache.get_or_try_init(0, || async { Ok::<_, Infallible>(rx.await.unwrap()) });
        let second = cache.get_or_try_init(0, || async { panic!("duplicate fetch") });
        tokio::pin!(first, second);
        assert!(poll!(&mut first).is_pending());
        cache
            .get_or_try_init(1, || async { Ok::<_, Infallible>(vec![1]) })
            .await
            .unwrap();
        assert!(poll!(&mut second).is_pending());
        tx.send(vec![0]).unwrap();
        let first = first.await.unwrap();
        let second: Result<_, Infallible> = second.await;
        assert!(Arc::ptr_eq(&first, &second.unwrap()));
        // Once idle, an entry can be evicted.
        cache
            .get_or_try_init(2, || async { Ok::<_, Infallible>(vec![2]) })
            .await
            .unwrap();
        assert_eq!(cache.entries.lock().await.len(), 1);
    }

    #[tokio::test]
    async fn cancellation_and_errors_are_retryable() {
        let cache = cache(None);
        let mut cancelled = Box::pin(cache.get_or_try_init(0, pending::<Result<Vec<u64>, ()>>));
        assert_eq!(poll!(&mut cancelled), Poll::Pending);
        drop(cancelled);
        assert!(
            cache
                .get_or_try_init(0, || async { Err(()) })
                .await
                .is_err()
        );
        assert_eq!(
            *cache
                .get_or_try_init(0, || async { Ok::<_, ()>(vec![3]) })
                .await
                .unwrap(),
            vec![3]
        );
    }

    #[tokio::test]
    async fn snapshots_expire_including_empty_results() {
        let cache = cache(Some(Duration::ZERO));
        cache
            .get_or_try_init(0, || async { Ok::<_, ()>(vec![]) })
            .await
            .unwrap();
        assert_eq!(
            *cache
                .get_or_try_init(0, || async { Ok::<_, ()>(vec![4]) })
                .await
                .unwrap(),
            vec![4]
        );
        let cache = super::SharedCache::<u64, u64>::new(NonZeroUsize::new(1).unwrap(), None);
        cache
            .get_or_try_init(0, || async { Ok::<_, ()>(5) })
            .await
            .unwrap();
        assert_eq!(
            *cache
                .get_or_try_init(0, || async { Err(()) })
                .now_or_never()
                .unwrap()
                .unwrap(),
            5
        );
    }

    #[test]
    fn rejects_scope_mismatch() {
        let scope = SharedApiScope::default();
        let federation = FederationId::dummy();
        let peers = BTreeSet::from([PeerId::from(0)]);
        scope
            .bind(federation, 0, ApiVersion::new(0, 0), &(), &peers)
            .unwrap();
        scope
            .bind(federation, 0, ApiVersion::new(0, 0), &(), &peers)
            .unwrap();
        assert!(
            scope
                .bind(federation, 1, ApiVersion::new(0, 0), &(), &peers)
                .is_err()
        );
        assert!(
            scope
                .bind(federation, 0, ApiVersion::new(0, 1), &(), &peers)
                .is_err()
        );
        assert!(
            scope
                .bind(federation, 0, ApiVersion::new(0, 0), &1, &peers)
                .is_err()
        );
    }
}
