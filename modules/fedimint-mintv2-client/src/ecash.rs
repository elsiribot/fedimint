use fedimint_core::config::FederationId;
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::invite_code::InviteCode;
use fedimint_core::module::AmountUnit;
use fedimint_core::Amount;

use crate::SpendableNote;

#[derive(Clone, Debug, Encodable, Decodable)]
pub struct ECash(Vec<ECashField>);

#[derive(Clone, Debug, Decodable, Encodable)]
enum ECashField {
    Mint(FederationId),
    Note(SpendableNote),
    /// Optional federation invite so a non-member recipient can join and
    /// claim. Clients predating this variant skip it via the default field.
    Invite(InviteCode),
    /// Self-describes the [`AmountUnit`] (Bitcoin vs. a custom unit like
    /// USDT) these notes are denominated in, so apps can display/route
    /// notes from federations the user hasn't joined. Clients predating
    /// this variant skip it via the default field.
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

    /// Embeds a federation invite for join-then-claim by non-members.
    #[must_use]
    pub fn with_invite(mut self, invite: InviteCode) -> Self {
        self.0.push(ECashField::Invite(invite));
        self
    }

    pub fn invite(&self) -> Option<InviteCode> {
        self.0.iter().find_map(|field| match field {
            ECashField::Invite(invite) => Some(invite.clone()),
            _ => None,
        })
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
}

#[cfg(test)]
mod tests {
    use fedimint_core::config::FederationId;
    use fedimint_core::module::registry::ModuleDecoderRegistry;
    use fedimint_core::module::AmountUnit;

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
