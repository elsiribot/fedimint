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
pub struct EncryptedRoundCodec {
    my_index: PartyIndex,
    my_secret: SecretKey,
    party_pubkeys: Vec<PublicKey>,
}

/// The messages addressed to us, recovered from a [`EncryptedRoundCodec::
/// open_round`] call.
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

/// Derive the AEAD key protecting a p2p box addressed to `recipient`, from
/// the raw ECDH shared secret between sender and recipient.
fn aead_key(shared: [u8; 32], recipient: PartyIndex) -> anyhow::Result<LessSafeKey> {
    let key_bytes =
        Hkdf::<Sha256>::new(&shared, Some(P2P_SALT)).derive::<32>(&recipient.to_be_bytes());
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
    pub fn new(my_index: PartyIndex, my_secret: SecretKey, party_pubkeys: Vec<PublicKey>) -> Self {
        Self {
            my_index,
            my_secret,
            party_pubkeys,
        }
    }

    /// Serialize and encrypt one round's outgoing messages into a wire
    /// payload: `broadcast` in the clear, each `p2p` entry ECIES-boxed to
    /// its recipient.
    pub fn seal_round<M: Serialize>(
        &self,
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
            let key = aead_key(shared, *recipient)?;

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

    /// Decrypt and deserialize a payload received from `sender`, recovering
    /// its broadcast message (if any) and the p2p message (if any)
    /// addressed to us.
    pub fn open_round<M: DeserializeOwned>(
        &self,
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
                let key = aead_key(shared, self.my_index)?;

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
        let codec0 = EncryptedRoundCodec::new(0, sks[0], pks.clone());
        let codec1 = EncryptedRoundCodec::new(1, sks[1], pks.clone());
        let mut p2p = BTreeMap::new();
        p2p.insert(1u16, "secret-for-1".to_string());
        p2p.insert(2u16, "secret-for-2".to_string());
        let payload = codec0
            .seal_round(Some(&"hello-all".to_string()), &p2p)
            .expect("seal");
        let opened = codec1.open_round::<String>(0, &payload).expect("open");
        assert_eq!(opened.broadcast.as_deref(), Some("hello-all"));
        assert_eq!(opened.p2p_to_me.as_deref(), Some("secret-for-1"));
    }

    #[test]
    fn wrong_recipient_cannot_read_others_p2p() {
        let (sks, pks) = keypairs(3);
        let codec0 = EncryptedRoundCodec::new(0, sks[0], pks.clone());
        let codec2 = EncryptedRoundCodec::new(2, sks[2], pks.clone());
        let mut p2p = BTreeMap::new();
        p2p.insert(1u16, "only-for-1".to_string());
        let payload = codec0.seal_round::<String>(None, &p2p).expect("seal");
        let opened = codec2.open_round::<String>(0, &payload).expect("open");
        assert!(
            opened.p2p_to_me.is_none(),
            "party 2 has no p2p; cannot read party 1's box"
        );
    }

    #[test]
    fn tampered_ciphertext_is_rejected() {
        let (sks, pks) = keypairs(2);
        let codec0 = EncryptedRoundCodec::new(0, sks[0], pks.clone());
        let codec1 = EncryptedRoundCodec::new(1, sks[1], pks.clone());
        let mut p2p = BTreeMap::new();
        p2p.insert(1u16, "x".to_string());
        let mut payload = codec0.seal_round::<String>(None, &p2p).expect("seal");
        *payload.last_mut().unwrap() ^= 0xff; // flip a byte
        assert!(
            codec1.open_round::<String>(0, &payload).is_err(),
            "AEAD tag must reject tamper"
        );
    }
}
