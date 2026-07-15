//! Encrypted round codec: packs one MPC round's outgoing messages into a
//! single wire payload and unpacks incoming payloads.
//!
//! The broadcast message (if any) is serialized in the clear — every party
//! is meant to see it. Each point-to-point message is serialized and then
//! ECIES-boxed to its recipient: an ephemeral-static ECDH with the
//! recipient's static public key is stretched via HKDF-SHA256 into a
//! ChaCha20-Poly1305 key, which authenticates and encrypts the message
//! (see [`fedimint_aead::encrypt`]). This matches the ephemeral-static ECDH
//! idiom used elsewhere in the workspace (see
//! `fedimint-lnv2-common::tweak::generate`).

use std::collections::BTreeMap;

use anyhow::Context as _;
use fedimint_aead::{LessSafeKey, UnboundKey};
use hkdf::Hkdf;
use hkdf::hashes::Sha256;
use rand::RngCore as _;
use ring::aead::CHACHA20_POLY1305;
use secp256k1::ecdh::SharedSecret;
use secp256k1::{PublicKey, Secp256k1, SecretKey};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use super::PartyIndex;

/// Fixed domain-separation salt for the HKDF that derives per-recipient
/// AEAD keys from ECDH shared secrets. Must be identical across all
/// parties and stable across releases (changing it breaks compatibility
/// with peers still on the old salt).
const P2P_SALT: &[u8] = b"fedimint-threshold-ecdsa/round-p2p/v0";

/// One party's cryptographic material for sealing/opening a single MPC
/// round's outgoing/incoming wire payload.
///
/// `party_pubkeys` is indexed by [`PartyIndex`] (`party_pubkeys[i]` is party
/// `i`'s static public key) and must include every party, including
/// ourselves.
///
/// `domain` is a caller-supplied execution/session context (e.g. the
/// consuming protocol's `ExecutionId` bytes) folded into every p2p box's key
/// derivation alongside the round counter and sender/recipient indexes (see
/// `aead_key`). This ties each box to one specific protocol run, round,
/// and sender-to-recipient pair so it can never be replayed into a different
/// run, round, or misattributed to a different sender.
pub struct EncryptedRoundCodec {
    my_index: PartyIndex,
    my_secret: SecretKey,
    party_pubkeys: Vec<PublicKey>,
    domain: Vec<u8>,
}

/// The messages addressed to us, recovered from a
/// [`EncryptedRoundCodec::open_round`] call.
pub struct OpenedRound<M> {
    /// The sender's broadcast message, if it sent one.
    pub broadcast: Option<M>,
    /// The point-to-point message the sender addressed to us, if any.
    /// `None` both when the sender sent no p2p message at all and when it
    /// addressed a p2p message to some other party but not to us.
    pub p2p_to_me: Option<M>,
}

/// The wire packet produced by [`EncryptedRoundCodec::seal_round`].
#[derive(Serialize, Deserialize)]
struct RoundPacket {
    /// Plaintext-serialized broadcast message, if any.
    broadcast: Option<Vec<u8>>,
    /// Recipient index -> ECIES box, one per p2p recipient.
    p2p: BTreeMap<PartyIndex, EciesBox>,
}

/// An ECIES box: an ephemeral public key plus the ciphertext of the
/// per-recipient ECDH-derived AEAD encryption (nonce-prefixed, see
/// [`fedimint_aead::encrypt`]).
#[derive(Serialize, Deserialize)]
struct EciesBox {
    /// Compressed SEC1 encoding of the ephemeral public key used for this
    /// box's ECDH.
    #[serde(with = "serde_big_array::BigArray")]
    ephemeral_pk: [u8; 33],
    ciphertext: Vec<u8>,
}

/// Serialize `value` with the binary codec used for the wire format.
///
/// Localizes the choice of binary codec (currently `bincode`) so it can be
/// swapped without touching call sites.
fn serde_encode<T: Serialize>(value: &T) -> anyhow::Result<Vec<u8>> {
    bincode::serialize(value).context("failed to serialize round message")
}

/// Deserialize a value previously produced by [`serde_encode`].
fn serde_decode<T: DeserializeOwned>(bytes: &[u8]) -> anyhow::Result<T> {
    bincode::deserialize(bytes).context("failed to deserialize round message")
}

/// Derive the AEAD key protecting a p2p box sent by `sender` to `recipient`
/// during `round` of protocol run `domain`, from the raw ECDH shared secret
/// between sender and recipient.
///
/// The HKDF `info` binds all four values with unambiguous framing (a
/// 4-byte big-endian length prefix on `domain`, since it is
/// variable-length, followed by fixed-width big-endian `round`, `sender`,
/// `recipient`), so that changing any one of them yields a completely
/// different key: a box sealed by party A for party C in round 5 of one
/// execution cannot be decrypted as if it had been sealed by a different
/// sender, in a different round, or in a different protocol run.
fn aead_key(
    shared: [u8; 32],
    domain: &[u8],
    round: u64,
    sender: PartyIndex,
    recipient: PartyIndex,
) -> anyhow::Result<LessSafeKey> {
    let mut info = Vec::with_capacity(4 + domain.len() + 8 + 2 + 2);
    info.extend_from_slice(
        &u32::try_from(domain.len())
            .context("domain too long")?
            .to_be_bytes(),
    );
    info.extend_from_slice(domain);
    info.extend_from_slice(&round.to_be_bytes());
    info.extend_from_slice(&sender.to_be_bytes());
    info.extend_from_slice(&recipient.to_be_bytes());

    let key_bytes = Hkdf::<Sha256>::new(&shared, Some(P2P_SALT)).derive::<32>(&info);
    let unbound = UnboundKey::new(&CHACHA20_POLY1305, &key_bytes)
        .map_err(|_| anyhow::anyhow!("aead key construction failed"))?;
    Ok(LessSafeKey::new(unbound))
}

/// Generate a fresh ephemeral secret key using the thread-local CSPRNG.
///
/// `SecretKey::from_slice` rejects the (astronomically unlikely) case of a
/// scalar outside `1..CURVE_ORDER`; retry rather than panic.
fn generate_ephemeral_secret() -> SecretKey {
    loop {
        let mut bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut bytes);
        if let Ok(sk) = SecretKey::from_slice(&bytes) {
            return sk;
        }
    }
}

impl EncryptedRoundCodec {
    /// `domain` is a caller-supplied execution/session context (e.g. the
    /// consuming protocol's `ExecutionId` bytes) that gets folded into every
    /// p2p box's key derivation; see the struct docs.
    pub fn new(
        my_index: PartyIndex,
        my_secret: SecretKey,
        party_pubkeys: Vec<PublicKey>,
        domain: Vec<u8>,
    ) -> Self {
        Self {
            my_index,
            my_secret,
            party_pubkeys,
            domain,
        }
    }

    /// Serialize and encrypt one round's outgoing messages into a wire
    /// payload: `broadcast` in the clear, each `p2p` entry ECIES-boxed to
    /// its recipient. `round` is the caller's round counter for this
    /// exchange and is bound into every p2p box's key (see `aead_key`).
    pub fn seal_round<M: Serialize>(
        &self,
        round: u64,
        broadcast: Option<&M>,
        p2p: &BTreeMap<PartyIndex, M>,
    ) -> anyhow::Result<Vec<u8>> {
        let broadcast = broadcast.map(serde_encode).transpose()?;

        let secp = Secp256k1::signing_only();
        let mut boxes = BTreeMap::new();
        for (recipient, message) in p2p {
            let recipient_pk = self
                .party_pubkeys
                .get(*recipient as usize)
                .with_context(|| format!("no public key registered for party {recipient}"))?;

            let ephemeral_sk = generate_ephemeral_secret();
            let ephemeral_pk = ephemeral_sk.public_key(&secp);

            let shared = SharedSecret::new(recipient_pk, &ephemeral_sk).secret_bytes();
            let key = aead_key(shared, &self.domain, round, self.my_index, *recipient)?;

            let plaintext = serde_encode(message)?;
            let ciphertext = fedimint_aead::encrypt(plaintext, &key)
                .context("encrypting p2p round message failed")?;

            boxes.insert(
                *recipient,
                EciesBox {
                    ephemeral_pk: ephemeral_pk.serialize(),
                    ciphertext,
                },
            );
        }

        serde_encode(&RoundPacket {
            broadcast,
            p2p: boxes,
        })
    }

    /// Decrypt and deserialize a payload received from `sender` for `round`,
    /// recovering its broadcast message (if any) and the p2p message (if
    /// any) addressed to us.
    ///
    /// `round` and `sender` must match the values [`Self::seal_round`] was
    /// called with on the sending side (see `aead_key`): a box sealed for
    /// a different round, or by a different sender than claimed here, fails
    /// to decrypt rather than being silently accepted or misattributed.
    pub fn open_round<M: DeserializeOwned>(
        &self,
        round: u64,
        sender: PartyIndex,
        payload: &[u8],
    ) -> anyhow::Result<OpenedRound<M>> {
        let packet: RoundPacket = serde_decode(payload)
            .with_context(|| format!("failed to decode round packet from party {sender}"))?;

        let broadcast = packet
            .broadcast
            .map(|bytes| serde_decode(&bytes))
            .transpose()
            .with_context(|| format!("failed to decode broadcast from party {sender}"))?;

        let p2p_to_me = match packet.p2p.get(&self.my_index) {
            Some(EciesBox {
                ephemeral_pk,
                ciphertext,
            }) => {
                let ephemeral_pk = PublicKey::from_slice(ephemeral_pk)
                    .context("invalid ephemeral public key in p2p box")?;
                let shared = SharedSecret::new(&ephemeral_pk, &self.my_secret).secret_bytes();
                let key = aead_key(shared, &self.domain, round, sender, self.my_index)?;

                let mut buf = ciphertext.clone();
                let plaintext = fedimint_aead::decrypt(&mut buf, &key).with_context(|| {
                    format!("decrypting p2p round message from party {sender} failed")
                })?;
                Some(serde_decode(plaintext)?)
            }
            None => None,
        };

        Ok(OpenedRound {
            broadcast,
            p2p_to_me,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use secp256k1::{PublicKey, Secp256k1, SecretKey};

    use super::EncryptedRoundCodec;

    fn keypairs(n: u16) -> (Vec<SecretKey>, Vec<PublicKey>) {
        let secp = Secp256k1::new();
        let sks: Vec<_> = (0..n)
            .map(|i| {
                let mut b = [1u8; 32];
                b[31] = (i + 1) as u8;
                SecretKey::from_slice(&b).unwrap()
            })
            .collect();
        let pks = sks.iter().map(|sk| sk.public_key(&secp)).collect();
        (sks, pks)
    }

    #[test]
    fn broadcast_and_p2p_round_trip() {
        let (sks, pks) = keypairs(3);
        let codec0 = EncryptedRoundCodec::new(0, sks[0], pks.clone(), b"test-domain".to_vec());
        let codec1 = EncryptedRoundCodec::new(1, sks[1], pks.clone(), b"test-domain".to_vec());
        let mut p2p = BTreeMap::new();
        p2p.insert(1u16, "secret-for-1".to_string());
        p2p.insert(2u16, "secret-for-2".to_string());
        let payload = codec0
            .seal_round(0, Some(&"hello-all".to_string()), &p2p)
            .expect("seal");
        let opened = codec1.open_round::<String>(0, 0, &payload).expect("open");
        assert_eq!(opened.broadcast.as_deref(), Some("hello-all"));
        assert_eq!(opened.p2p_to_me.as_deref(), Some("secret-for-1"));
    }

    #[test]
    fn wrong_recipient_cannot_read_others_p2p() {
        let (sks, pks) = keypairs(3);
        let codec0 = EncryptedRoundCodec::new(0, sks[0], pks.clone(), b"test-domain".to_vec());
        let codec2 = EncryptedRoundCodec::new(2, sks[2], pks.clone(), b"test-domain".to_vec());
        let mut p2p = BTreeMap::new();
        p2p.insert(1u16, "only-for-1".to_string());
        let payload = codec0.seal_round::<String>(0, None, &p2p).expect("seal");
        let opened = codec2.open_round::<String>(0, 0, &payload).expect("open");
        assert!(
            opened.p2p_to_me.is_none(),
            "party 2 has no p2p; cannot read party 1's box"
        );
    }

    #[test]
    fn tampered_ciphertext_is_rejected() {
        let (sks, pks) = keypairs(2);
        let codec0 = EncryptedRoundCodec::new(0, sks[0], pks.clone(), b"test-domain".to_vec());
        let codec1 = EncryptedRoundCodec::new(1, sks[1], pks.clone(), b"test-domain".to_vec());
        let mut p2p = BTreeMap::new();
        p2p.insert(1u16, "x".to_string());
        let mut payload = codec0.seal_round::<String>(0, None, &p2p).expect("seal");
        *payload.last_mut().unwrap() ^= 0xff; // flip a byte
        assert!(
            codec1.open_round::<String>(0, 0, &payload).is_err(),
            "AEAD tag must reject tamper"
        );
    }

    /// Regression test for the Critical fix: a p2p box sealed by party A
    /// (sender index `a`) addressed to party C must be decryptable only
    /// when `open_round` is called with `sender == a`. If a malicious party
    /// B copies A's box (verbatim, from the all-to-all exchange) into its
    /// own p2p slot for C and C opens it attributing it to B instead, the
    /// AEAD key derived for (domain, round, B, C) does not match the key
    /// the box was sealed under for (domain, round, A, C), so decryption
    /// must fail rather than silently succeed with C believing the message
    /// came from B.
    #[test]
    fn box_sealed_by_one_sender_cannot_be_reattributed_to_another() {
        let (sks, pks) = keypairs(3);
        let codec_a = EncryptedRoundCodec::new(0, sks[0], pks.clone(), b"test-domain".to_vec());
        // Only used to construct the codec through which C opens the (replayed)
        // box; C's own index/secret is what matters for decryption.
        let codec_c = EncryptedRoundCodec::new(2, sks[2], pks.clone(), b"test-domain".to_vec());

        let mut p2p = BTreeMap::new();
        p2p.insert(2u16, "only-for-c-from-a".to_string());
        let payload_from_a = codec_a
            .seal_round::<String>(0, None, &p2p)
            .expect("seal by A");

        // Honest path: C opens it correctly attributed to A (sender = 0) and
        // succeeds.
        let opened = codec_c
            .open_round::<String>(0, 0, &payload_from_a)
            .expect("C can open the box honestly attributed to A");
        assert_eq!(opened.p2p_to_me.as_deref(), Some("only-for-c-from-a"));

        // Attack: the wire bytes A sent are identical regardless of who claims
        // to have sent them (this is exactly what a malicious B could copy out
        // of the all-to-all exchange and re-submit as its own payload). If C
        // is fooled into opening the same bytes but attributing them to B
        // (sender = 1), the AEAD key derived for (domain, round, sender=1,
        // recipient=2) must not match the key the box was actually sealed
        // under for (domain, round, sender=0, recipient=2), so decryption
        // must fail.
        let reattributed = codec_c.open_round::<String>(0, 1, &payload_from_a);
        assert!(
            reattributed.is_err(),
            "a box sealed by A must not decrypt when opened as if sent by a different party"
        );
    }
}
