use fedimint_core::config::FederationId;
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::invite_code::InviteCode;
use fedimint_core::module::AmountUnit;
use fedimint_core::util::SafeUrl;
use fedimint_core::{Amount, PeerId};

use crate::SpendableNote;

#[derive(Clone, Debug, Encodable, Decodable)]
pub struct ECash(Vec<ECashField>);

#[derive(Clone, Debug, Decodable, Encodable)]
enum ECashField {
    Mint(FederationId),
    Note(SpendableNote),
    /// Invite code to join the federation by which the e-cash was issued. This
    /// allows a recipient that has not yet joined the federation to do so
    /// directly from the received ecash.
    Invite {
        peer_apis: Vec<(PeerId, SafeUrl)>,
        federation_id: FederationId,
    },
    ApiSecret(String),
    /// Self-describes the [`AmountUnit`] (Bitcoin vs. a custom unit like
    /// USDT) these notes are denominated in, so apps can display/route
    /// notes from federations the user hasn't joined. Clients predating
    /// this variant skip it via the default field.
    ///
    /// Appended last on purpose: `fedimint-derive` encodes variants by
    /// position, and 2 and 3 are already spoken for upstream. On the
    /// experimint line this sat at 3, so e-cash minted there before this
    /// backport does not decode here.
    Unit(AmountUnit),
    #[encodable_default]
    Default {
        variant: u64,
        bytes: Vec<u8>,
    },
}

impl ECash {
    pub fn new(mint: FederationId, notes: Vec<SpendableNote>) -> Self {
        Self(
            std::iter::once(ECashField::Mint(mint))
                .chain(notes.into_iter().map(ECashField::Note))
                .collect(),
        )
    }

    pub fn new_with_invite(notes: Vec<SpendableNote>, invite: &InviteCode) -> Self {
        let mut fields = vec![ECashField::Mint(invite.federation_id())];

        fields.extend(notes.into_iter().map(ECashField::Note));

        fields.push(ECashField::Invite {
            peer_apis: vec![(invite.peer(), invite.url())],
            federation_id: invite.federation_id(),
        });

        if let Some(api_secret) = invite.api_secret() {
            fields.push(ECashField::ApiSecret(api_secret));
        }

        Self(fields)
    }

    /// Attaches the [`AmountUnit`] these notes are denominated in.
    #[must_use]
    pub fn with_unit(mut self, unit: AmountUnit) -> Self {
        self.0.push(ECashField::Unit(unit));
        self
    }

    pub fn unit(&self) -> Option<AmountUnit> {
        self.0.iter().find_map(|field| match field {
            ECashField::Unit(unit) => Some(*unit),
            _ => None,
        })
    }

    pub fn amount(&self) -> Amount {
        self.0
            .iter()
            .filter_map(|field| match field {
                ECashField::Note(note) => Some(note.amount()),
                _ => None,
            })
            .sum()
    }

    pub fn mint(&self) -> Option<FederationId> {
        self.0.iter().find_map(|field| match field {
            ECashField::Mint(mint) => Some(*mint),
            _ => None,
        })
    }

    pub fn notes(&self) -> Vec<SpendableNote> {
        self.0
            .iter()
            .filter_map(|field| match field {
                ECashField::Note(note) => Some(note.clone()),
                _ => None,
            })
            .collect()
    }

    /// The invite code of the federation by which this ecash was issued, if it
    /// was included by the sender.
    pub fn federation_invite(&self) -> Option<InviteCode> {
        let api_secret = self.api_secret();

        self.0.iter().find_map(|field| {
            let ECashField::Invite {
                peer_apis,
                federation_id,
            } = field
            else {
                return None;
            };

            let (peer_id, api) = peer_apis.first().cloned()?;

            Some(InviteCode::new(
                api,
                peer_id,
                *federation_id,
                api_secret.clone(),
            ))
        })
    }

    fn api_secret(&self) -> Option<String> {
        self.0.iter().find_map(|field| match field {
            ECashField::ApiSecret(api_secret) => Some(api_secret.clone()),
            _ => None,
        })
    }
}

#[cfg(test)]
mod tests {
    use fedimint_core::config::FederationId;
    use fedimint_core::module::AmountUnit;
    use fedimint_core::module::registry::ModuleDecoderRegistry;

    use super::*;

    fn test_ecash() -> ECash {
        ECash::new(FederationId::dummy(), vec![])
    }

    #[test]
    fn unit_field_roundtrips_and_defaults_to_none() {
        let ecash = test_ecash();
        assert_eq!(ecash.unit(), None);
        let decoded = ECash::consensus_decode_whole(
            &ecash.consensus_encode_to_vec(),
            &ModuleDecoderRegistry::default(),
        )
        .unwrap();
        assert_eq!(decoded.unit(), None);
        let with_unit = ecash.clone().with_unit(AmountUnit::new_custom(1));
        let decoded = ECash::consensus_decode_whole(
            &with_unit.consensus_encode_to_vec(),
            &ModuleDecoderRegistry::default(),
        )
        .unwrap();
        assert_eq!(decoded.unit(), Some(AmountUnit::new_custom(1)));
    }
}
