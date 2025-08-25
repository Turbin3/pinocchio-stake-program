use pinocchio::{
    account_info::AccountInfo,
    program_error::ProgramError,
    sysvars::{clock::Clock, Sysvar},
};

use crate::{
    helpers::{bytes_to_u64, checked_add, get_stake_state},
    state::{delegation::Stake, MergeKind, StakeHistory},
};

pub fn stake_weighted_credits_observed(
    stake: &Stake,
    absorbed_lamports: u64,
    absorbed_credits_observed: u64,
) -> Option<u64> {
    if bytes_to_u64(stake.credits_observed) == absorbed_credits_observed {
        Some(bytes_to_u64(stake.credits_observed))
    } else {
        let total_stake =
            u128::from(bytes_to_u64(stake.delegation.stake).checked_add(absorbed_lamports)?);
        let stake_weighted_credits = u128::from(bytes_to_u64(stake.credits_observed))
            .checked_mul(u128::from(bytes_to_u64(stake.delegation.stake)))?;
        let absorbed_weighted_credits =
            u128::from(absorbed_credits_observed).checked_mul(u128::from(absorbed_lamports))?;
        // Discard fractional credits as a merge side-effect friction by taking
        // the ceiling, done by adding `denominator - 1` to the numerator.
        let total_weighted_credits = stake_weighted_credits
            .checked_add(absorbed_weighted_credits)?
            .checked_add(total_stake)?
            .checked_sub(1)?;
        u64::try_from(total_weighted_credits.checked_div(total_stake)?).ok()
    }
}

pub fn merge_delegation_stake_and_credits_observed(
    stake: &mut Stake,
    lamports_to_merge: u64,
    source_credits_observed: u64,
) -> Result<(), ProgramError> {
    stake.delegation.stake =
        checked_add(bytes_to_u64(stake.delegation.stake), lamports_to_merge)?.to_le_bytes();
    stake.credits_observed =
        stake_weighted_credits_observed(stake, lamports_to_merge, source_credits_observed)
            .ok_or(ProgramError::ArithmeticOverflow)?
            .to_le_bytes();

    Ok(())
}

pub fn move_stake_or_lamports_shared_checks(
    source_stake_account_info: &AccountInfo,
    lamports: u64,
    destination_stake_account_info: &AccountInfo,
    stake_authority_info: &AccountInfo,
) -> Result<(MergeKind, MergeKind), ProgramError> {
    // Authority must sign (simplified check)
    if !stake_authority_info.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }

    // Confirm not the same account
    if *source_stake_account_info.key() == *destination_stake_account_info.key() {
        return Err(ProgramError::InvalidInstructionData);
    }

    // Source and destination must be writable
    if !source_stake_account_info.is_writable() || !destination_stake_account_info.is_writable() {
        return Err(ProgramError::InvalidInstructionData);
    }

    // Must move something
    if lamports == 0 {
        return Err(ProgramError::InvalidArgument);
    }

    let clock = Clock::get()?;
    let stake_history = StakeHistory::new();

    // Get if mergeable ensures accounts are not partly activated or in any form of deactivating
    let source_merge_kind = MergeKind::get_if_mergeable(
        &get_stake_state(source_stake_account_info)?,
        source_stake_account_info.lamports(),
        &clock,
        &stake_history,
    )?;

    let destination_merge_kind = MergeKind::get_if_mergeable(
        &get_stake_state(destination_stake_account_info)?,
        destination_stake_account_info.lamports(),
        &clock,
        &stake_history,
    )?;

    // Ensure all authorities match and lockups match if lockup is in force
    MergeKind::metas_can_merge(
        source_merge_kind.meta(),
        destination_merge_kind.meta(),
        &clock,
    )?;

    Ok((source_merge_kind, destination_merge_kind))
}
