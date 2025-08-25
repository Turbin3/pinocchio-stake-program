use pinocchio::{program_error::ProgramError, sysvars::clock::Clock};

use crate::{
    error::{to_program_error, StakeError},
    helpers::bytes_to_u64,
    state::{delegation::Stake, Meta, StakeFlags, StakeHistory, StakeStateV2},
};

#[derive(Clone, Debug, PartialEq)]
pub enum MergeKind {
    Inactive(Meta, u64, StakeFlags),
    ActivationEpoch(Meta, Stake, StakeFlags),
    FullyActive(Meta, Stake),
}

impl MergeKind {
    /// Get metadata from any merge kind
    pub fn meta(&self) -> &Meta {
        match self {
            MergeKind::Inactive(meta, _, _) => meta,
            MergeKind::ActivationEpoch(meta, _, _) => meta,
            MergeKind::FullyActive(meta, _) => meta,
        }
    }

    /// Check if stake state can be merged
    pub fn get_if_mergeable(
        stake_state: &StakeStateV2,
        lamports: u64,
        _clock: &Clock,
        _stake_history: &StakeHistory,
    ) -> Result<Self, ProgramError> {
        match stake_state {
            StakeStateV2::Stake(meta, stake, stake_flags) => {
                // Simplified logic, later => this would check epochs
                if bytes_to_u64(stake.delegation.deactivation_epoch) == u64::MAX {
                    Ok(MergeKind::FullyActive(meta.clone(), stake.clone()))
                } else {
                    Ok(MergeKind::ActivationEpoch(
                        meta.clone(),
                        stake.clone(),
                        stake_flags.clone(),
                    ))
                }
            }
            StakeStateV2::Initialized(meta) => Ok(MergeKind::Inactive(
                meta.clone(),
                lamports,
                StakeFlags::empty(),
            )),
            _ => Err(ProgramError::InvalidAccountData),
        }
    }

    /// Verify metas can be merged (authorities and lockups match)
    pub fn metas_can_merge(stake: &Meta, source: &Meta, clock: &Clock) -> Result<(), ProgramError> {
        // Check authorities match
        if stake.authorized.staker != source.authorized.staker {
            return Err(to_program_error(StakeError::MergeMismatch));
        }

        if stake.authorized.withdrawer != source.authorized.withdrawer {
            return Err(to_program_error(StakeError::MergeMismatch));
        }

        // Check lockups if active
        if i64::from_le_bytes(stake.lockup.unix_timestamp) > clock.unix_timestamp
            || stake.lockup.epoch > clock.epoch.to_le_bytes()
        {
            if stake.lockup.unix_timestamp != source.lockup.unix_timestamp
                || stake.lockup.epoch != source.lockup.epoch
            {
                return Err(to_program_error(StakeError::LockupInForce));
            }
        }

        Ok(())
    }
}
