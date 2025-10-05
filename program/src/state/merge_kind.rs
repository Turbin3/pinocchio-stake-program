use pinocchio::{program_error::ProgramError, sysvars::clock::Clock, ProgramResult};
use crate::error::{to_program_error, StakeError};

use crate::helpers::{
    bytes_to_u64,
    checked_add,
};
use crate::helpers::merge::merge_delegation_stake_and_credits_observed;
use crate::state::{
    delegation::Stake as DelegationStake,
    stake_flag::StakeFlags,
    stake_history::StakeHistoryGetEntry,
    stake_state_v2::StakeStateV2,
    state::Meta,
};
/// Classification of stake accounts for merge compatibility
#[derive(Clone, Debug, PartialEq)]
pub enum MergeKind {
    /// Inactive stake (not delegated) – holds total lamports (for rent math).
    Inactive(Meta, u64, StakeFlags),

    /// Stake is in the activation epoch (has activating stake).
    ActivationEpoch(Meta, DelegationStake, StakeFlags),

    /// Fully active stake (no activating/deactivating, effective == delegated).
    FullyActive(Meta, DelegationStake),
}

impl MergeKind {
    /// Borrow meta from any variant
    pub fn meta(&self) -> &Meta {
        match self {
            Self::Inactive(meta, _, _) => meta,
            Self::ActivationEpoch(meta, _, _) => meta,
            Self::FullyActive(meta, _) => meta,
        }
    }

    /// Borrow the active stake (if any)
    fn active_stake(&self) -> Option<&DelegationStake> {
        match self {
            Self::Inactive(_, _, _) => None,
            Self::ActivationEpoch(_, stake, _) => Some(stake),
            Self::FullyActive(_, stake) => Some(stake),
        }
    }

    /// Classification helper
    pub fn get_if_mergeable<T: StakeHistoryGetEntry>(
        stake_state: &StakeStateV2,
        stake_lamports: u64,
        clock: &Clock,
        stake_history: &T,
    ) -> Result<Self, ProgramError> {
        match stake_state {
            StakeStateV2::Stake(meta, stake, flags) => {
                // Fast path: if delegated > 0, no deactivation scheduled, and activation epoch reached,
                // treat as FullyActive even if stake history can't inform effective/activating metrics.
                let delegated    = crate::helpers::bytes_to_u64(stake.delegation.stake);
                let act_epoch    = crate::helpers::bytes_to_u64(stake.delegation.activation_epoch);
                let deact_epoch  = crate::helpers::bytes_to_u64(stake.delegation.deactivation_epoch);
                // If a deactivation has been scheduled and we're at or before that epoch,
                // this account is considered deactivating and not mergeable for move/merge.
                if deact_epoch != u64::MAX {
                    pinocchio::msg!("mk:deact set");
                    if clock.epoch <= deact_epoch {
                        pinocchio::msg!("mk:deactivating");
                        return Err(to_program_error(StakeError::MergeMismatch));
                    } else {
                        pinocchio::msg!("mk:post-deact -> IN");
                        // Past the deactivation epoch: treat as inactive for merge classification
                        return Ok(Self::Inactive(*meta, stake_lamports, *flags));
                    }
                } else {
                    pinocchio::msg!("mk:not deactivated");
                }
                if delegated > 0 && deact_epoch == u64::MAX && clock.epoch > act_epoch {
                    return Ok(Self::FullyActive(*meta, *stake));
                }
                let status = stake.delegation.stake_activating_and_deactivating(
                    clock.epoch.to_le_bytes(),
                    stake_history,
                    crate::helpers::PERPETUAL_NEW_WARMUP_COOLDOWN_RATE_EPOCH,
                );
                let effective    = crate::helpers::bytes_to_u64(status.effective);
                let activating   = crate::helpers::bytes_to_u64(status.activating);
                let deactivating = crate::helpers::bytes_to_u64(status.deactivating);
                // If any stake is deactivating, treat as not mergeable for move/merge ops
                if deactivating > 0 {
                    return Err(to_program_error(StakeError::MergeMismatch));
                }

                match (effective, activating, deactivating) {
                    (0, 0, 0) => {
                        // History yielded zeros; decide based on epochs.
                        let deact_epoch = bytes_to_u64(stake.delegation.deactivation_epoch);
                        let act_epoch   = bytes_to_u64(stake.delegation.activation_epoch);
                        if delegated > 0 && deact_epoch == u64::MAX {
                            if clock.epoch > act_epoch {
                                Ok(Self::FullyActive(*meta, *stake))
                            } else {
                                // At or before activation epoch: treat as ActivationEpoch (transient)
                                Ok(Self::ActivationEpoch(*meta, *stake, *flags))
                            }
                        } else {
                            // Either no delegation, or delegation but fully deactivated in the past
                            Ok(Self::Inactive(*meta, stake_lamports, *flags))
                        }
                    }
                    (0, _, _) => {
                        // Fallback: if activation is in the past and there's no deactivation scheduled,
                        // but history doesn't report progress, consider it FullyActive for classification.
                        let act_epoch = bytes_to_u64(stake.delegation.activation_epoch);
                        let deact_epoch = bytes_to_u64(stake.delegation.deactivation_epoch);
                        if delegated > 0 && deact_epoch == u64::MAX && clock.epoch > act_epoch {
                            Ok(Self::FullyActive(*meta, *stake))
                        } else {
                            // Only classify as ActivationEpoch when truly activating (not deactivating)
                            if activating > 0 {
                                Ok(Self::ActivationEpoch(*meta, *stake, *flags))
                            } else {
                                Err(to_program_error(StakeError::MergeMismatch))
                            }
                        }
                    }
                    (_, 0, 0) if effective == delegated => Ok(Self::FullyActive(*meta, *stake)),
                    _ => Err(to_program_error(StakeError::MergeMismatch)),
                }
            }
            StakeStateV2::Initialized(meta) => {
                Ok(Self::Inactive(*meta, stake_lamports, crate::state::stake_flag::StakeFlags::empty()))
            }
            _ => Err(to_program_error(StakeError::MergeMismatch)),
        }
    }

    /// Metadata compatibility check for merge
    pub fn metas_can_merge(dest: &Meta, source: &Meta, clock: &Clock) -> ProgramResult {
        // Authorities must match exactly
        let auth_eq = dest.authorized == source.authorized;
        if !auth_eq {
            pinocchio::msg!("metas:auth_eq=0");
            return Err(to_program_error(StakeError::MergeMismatch));
        }
        pinocchio::msg!("metas:auth_eq=1");

        // Lockups may differ, but both must be expired
        let lock_eq = dest.lockup == source.lockup;
        let dest_in_force = dest.lockup.is_in_force(clock, None);
        let src_in_force = source.lockup.is_in_force(clock, None);
        let both_not_in_force = !dest_in_force && !src_in_force;
        if lock_eq { pinocchio::msg!("metas:lock_eq=1"); } else { pinocchio::msg!("metas:lock_eq=0"); }
        if dest_in_force { pinocchio::msg!("metas:dest_in_force=1"); } else { pinocchio::msg!("metas:dest_in_force=0"); }
        if src_in_force { pinocchio::msg!("metas:src_in_force=1"); } else { pinocchio::msg!("metas:src_in_force=0"); }

        if lock_eq || both_not_in_force {
            pinocchio::msg!("metas:lock_ok");
            Ok(())
        } else {
            pinocchio::msg!("metas:lock_mismatch");
            Err(to_program_error(StakeError::MergeMismatch))
        }
    }

    /// Active delegation compatibility
    pub fn active_delegations_can_merge(
        dest: &crate::state::delegation::Delegation,
        source: &crate::state::delegation::Delegation,
    ) -> ProgramResult {
        if dest.voter_pubkey != source.voter_pubkey {
            return Err(to_program_error(StakeError::MergeMismatch));
        }
        let max_epoch = u64::MAX.to_le_bytes();
        if dest.deactivation_epoch == max_epoch && source.deactivation_epoch == max_epoch {
            Ok(())
        } else {
            Err(to_program_error(StakeError::MergeMismatch))
        }
    }

    /// Merge behavior
    pub fn merge(
        self,
        source: Self,
        _clock: &Clock,
    ) -> Result<Option<StakeStateV2>, ProgramError> {
        // validate metas
        // Caller is expected to have run metas_can_merge

        // If both are active kinds, validate active delegations
        if let (Some(dst), Some(src)) = (self.active_stake(), source.active_stake()) {
            Self::active_delegations_can_merge(&dst.delegation, &src.delegation)?;
        }

        let merged = match (self, source) {
            // Inactive + Inactive: no change
            (Self::Inactive(_, _, _), Self::Inactive(_, _, _)) => None,

            // Inactive + ActivationEpoch: allow by moving all inactive lamports into the activating stake
            // Resulting state uses the destination's Meta, the source's Stake, and unioned flags.
            (Self::Inactive(dst_meta, dst_lamports, dst_flags),
             Self::ActivationEpoch(_, mut src_stake, src_flags)) => {
                pinocchio::msg!("mk:merge IN+AE");
                let new_stake = checked_add(bytes_to_u64(src_stake.delegation.stake), dst_lamports)?;
                src_stake.delegation.stake = new_stake.to_le_bytes();
                let merged_flags = dst_flags.union(src_flags);
                Some(StakeStateV2::Stake(dst_meta, src_stake, merged_flags))
            }

            // ActivationEpoch + Inactive: add *all* source lamports (incl. rent) to stake
            (Self::ActivationEpoch(meta, mut stake, dst_flags),
             Self::Inactive(_, src_lamports, src_flags)) =>
            {
                pinocchio::msg!("mk:merge AE+IN");
                let new_stake =
                    checked_add(bytes_to_u64(stake.delegation.stake), src_lamports)?;
                stake.delegation.stake = new_stake.to_le_bytes();

                let merged_flags = dst_flags.union(src_flags);
                Some(StakeStateV2::Stake(meta, stake, merged_flags))
            }

            // ActivationEpoch + ActivationEpoch: add (source stake + source rent_exempt_reserve)
            (Self::ActivationEpoch(meta, mut stake, dst_flags),
             Self::ActivationEpoch(src_meta, src_stake, src_flags)) =>
            {
                let src_stake_lamports = checked_add(
                    bytes_to_u64(src_meta.rent_exempt_reserve),
                    bytes_to_u64(src_stake.delegation.stake),
                )?;
                merge_delegation_stake_and_credits_observed(
                    &mut stake,
                    src_stake_lamports,
                    bytes_to_u64(src_stake.credits_observed),
                )?;

                let merged_flags = dst_flags.union(src_flags);
                Some(StakeStateV2::Stake(meta, stake, merged_flags))
            }

            // FullyActive + FullyActive: add source *stake only* (no rent)
            (Self::FullyActive(meta, mut stake),
             Self::FullyActive(_, src_stake)) =>
            {
                merge_delegation_stake_and_credits_observed(
                    &mut stake,
                    bytes_to_u64(src_stake.delegation.stake),
                    bytes_to_u64(src_stake.credits_observed),
                )?;
                Some(StakeStateV2::Stake(meta, stake, StakeFlags::empty()))
            }

            // any other shape is invalid (native throws StakeError::MergeMismatch)
            _ => {
                pinocchio::msg!("mk:merge default -> mismatch");
                return Err(to_program_error(StakeError::MergeMismatch));
            }
        };

        Ok(merged)
    }
}   
