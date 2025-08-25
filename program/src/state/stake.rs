use crate::{
    error::*, helpers::*, state::delegation::Delegation, state::stake_history::StakeHistoryGetEntry,
};

#[derive(Debug, Clone, PartialEq)]
#[repr(C)]
pub struct Stake {
    /// Delegation information
    pub delegation: Delegation,
    /// Credits observed during the epoch
    pub credits_observed: u64,
}

// impl Stake {

// }
