use strum_macros::EnumIter;

/// Namespaces DB keys for this module.
///
/// No consensus state is persisted yet; this is a placeholder populated as
/// later tasks add deposit/withdrawal tracking.
#[repr(u8)]
#[derive(Clone, EnumIter, Debug)]
pub enum DbKeyPrefix {
    /// Reserved so the enum (and `dump_database`) compile before this
    /// module has any real persisted state.
    Reserved = 0x01,
}

impl std::fmt::Display for DbKeyPrefix {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}
