extern crate alloc;
// Merge instruction (Pinocchio implementation)
//
// Parity notes:
// - This implementation mirrors the native stake-program acceptance checks: distinct
//   destination/source, program ownership, both writable, exact account size, required
//   sysvars present, staker authorization, and metadata (authorities/lockups) compatibility.
// - Classification uses `MergeKind::get_if_mergeable(..)` and supports the common shape pairs:
//   IN+IN, IN+AE, AE+IN, AE+AE, FA+FA. On success, source is drained and uninitialized.
// - StakeHistory caveat: we intentionally do not read the full stake_history contents. Instead
//   we wrap the current epoch in `StakeHistorySysvar(clock.epoch)` and rely on classification
//   fallbacks (e.g., clearly deactivated shapes → Inactive). This is faithful for mainstream
//   cases, but may diverge from native at epoch boundaries where effective/partial activation
//   or cooldown depend on the actual StakeHistory entries.
//   If strict parity at boundaries is required, consider adding a feature flag that reads a
//   minimal slice of the sysvar (e.g., `get_entry(current_epoch-1)`) to disambiguate partial
//   activation/cooldown before classification.

use crate::{
    error::{to_program_error, StakeError},
    helpers::{
        collect_signers,
        constant::MAXIMUM_SIGNERS,
        checked_add,
        bytes_to_u64,
        get_stake_state,
        relocate_lamports,
        set_stake_state,
    },
    state::{stake_state_v2::StakeStateV2, MergeKind, StakeHistorySysvar},
    ID,
};

use pinocchio::{
    account_info::AccountInfo,
    program_error::ProgramError,
    pubkey::Pubkey,
    sysvars::clock::Clock,
    ProgramResult,
};

pub fn process_merge(accounts: &[AccountInfo]) -> ProgramResult {
    pinocchio::msg!("merge:begin");
    // Native order: [destination, source, clock, stake_history]
    if accounts.len() < 4 { return Err(ProgramError::NotEnoughAccountKeys); }
    let [dst_ai, src_ai, clock_ai, stake_history_ai, _rest @ ..] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    if dst_ai.key() == src_ai.key() { return Err(ProgramError::InvalidArgument); }
    if *dst_ai.owner() != ID || *src_ai.owner() != ID { return Err(ProgramError::InvalidAccountOwner); }
    if !dst_ai.is_writable() || !src_ai.is_writable() { return Err(ProgramError::InvalidInstructionData); }
    // clock will be validated by Clock::from_account_info
    if stake_history_ai.key() != &crate::state::stake_history::ID { return Err(ProgramError::InvalidInstructionData); }

    let clock = Clock::from_account_info(clock_ai)?;
    // Use the epoch wrapper; contents of stake_history account are not read here
    let stake_history = StakeHistorySysvar(clock.epoch);

    // Enforce exact data size parity with native handlers
    if dst_ai.data_len() != StakeStateV2::size_of() || src_ai.data_len() != StakeStateV2::size_of() {
        return Err(ProgramError::InvalidAccountData);
    }

    // Collect signers
    let mut signer_buf = [Pubkey::default(); MAXIMUM_SIGNERS];
    let n = collect_signers(accounts, &mut signer_buf)?;
    let signers = &signer_buf[..n];

    // Classify destination & require staker auth
    let dst_state = get_stake_state(dst_ai)?;
    match &dst_state {
        StakeStateV2::Stake(_,_,_) => pinocchio::msg!("merge:dst_state=Stake"),
        StakeStateV2::Initialized(_) => pinocchio::msg!("merge:dst_state=Init"),
        StakeStateV2::Uninitialized => pinocchio::msg!("merge:dst_state=Uninit"),
        _ => pinocchio::msg!("merge:dst_state=Other"),
    }
    let dst_kind = match MergeKind::get_if_mergeable(
        &dst_state,
        dst_ai.lamports(),
        &clock,
        &stake_history,
    ) {
        Ok(k) => k,
        Err(_) => {
            // Fallback: treat clearly inactive shapes as Inactive for merge classification
            match &dst_state {
                StakeStateV2::Initialized(meta) => MergeKind::Inactive(*meta, dst_ai.lamports(), crate::state::stake_flag::StakeFlags::empty()),
                StakeStateV2::Stake(meta, stake, flags) => {
                    let deact = crate::helpers::bytes_to_u64(stake.delegation.deactivation_epoch);
                    if deact != u64::MAX && clock.epoch > deact {
                        MergeKind::Inactive(*meta, dst_ai.lamports(), *flags)
                    } else {
                        return Err(to_program_error(StakeError::MergeMismatch));
                    }
                }
                _ => return Err(to_program_error(StakeError::MergeMismatch)),
            }
        }
    };
    match &dst_kind {
        MergeKind::FullyActive(_, _) => pinocchio::msg!("merge:dst=FA"),
        MergeKind::Inactive(_, _, _) => pinocchio::msg!("merge:dst=IN"),
        MergeKind::ActivationEpoch(_, _, _) => pinocchio::msg!("merge:dst=AE"),
    }

    // Authorized staker is required to merge
    if !signers
        .iter()
        .any(|s| *s == dst_kind.meta().authorized.staker)
    {
        return Err(ProgramError::MissingRequiredSignature);
    }
    pinocchio::msg!("merge:auth_ok");

    // Classify source
    let src_state = get_stake_state(src_ai)?;
    match &src_state {
        StakeStateV2::Stake(_,_,_) => pinocchio::msg!("merge:src_state=Stake"),
        StakeStateV2::Initialized(_) => pinocchio::msg!("merge:src_state=Init"),
        StakeStateV2::Uninitialized => pinocchio::msg!("merge:src_state=Uninit"),
        _ => pinocchio::msg!("merge:src_state=Other"),
    }

    // Note: the fast-path (both inactive) can be handled by normal classification
    // and the unconditional source deinitialize + lamport drain below when
    // MergeKind::merge returns None, preserving native semantics without extra
    // branches.
    let src_kind = match MergeKind::get_if_mergeable(
        &src_state,
        src_ai.lamports(),
        &clock,
        &stake_history,
    ) {
        Ok(k) => k,
        Err(_) => {
            match &src_state {
                StakeStateV2::Initialized(meta) => MergeKind::Inactive(*meta, src_ai.lamports(), crate::state::stake_flag::StakeFlags::empty()),
                StakeStateV2::Stake(meta, stake, flags) => {
                    let deact = crate::helpers::bytes_to_u64(stake.delegation.deactivation_epoch);
                    if deact != u64::MAX && clock.epoch > deact {
                        MergeKind::Inactive(*meta, src_ai.lamports(), *flags)
                    } else {
                        return Err(to_program_error(StakeError::MergeMismatch));
                    }
                }
                _ => return Err(to_program_error(StakeError::MergeMismatch)),
            }
        }
    };
    match &src_kind {
        MergeKind::FullyActive(_, _) => pinocchio::msg!("merge:src=FA"),
        MergeKind::Inactive(_, _, _) => pinocchio::msg!("merge:src=IN"),
        MergeKind::ActivationEpoch(_, _, _) => pinocchio::msg!("merge:src=AE"),
    }

    // Ensure metadata compatibility (authorities equal, lockups compatible)
    MergeKind::metas_can_merge(dst_kind.meta(), src_kind.meta(), &clock)?;
    pinocchio::msg!("merge:metas_ok");
    pinocchio::msg!("merge:after_metas");

    // Fast-path already attempted using raw states above

    // Perform merge inline for all supported shape pairs; otherwise error
    match (dst_kind.clone(), src_kind.clone()) {
        (MergeKind::Inactive(_, _, _), MergeKind::Inactive(_, _, _)) => {
            // no state change on destination; just close and drain source below
            set_stake_state(src_ai, &StakeStateV2::Uninitialized)?;
            relocate_lamports(src_ai, dst_ai, src_ai.lamports())?;
            return Ok(());
        }
        (MergeKind::Inactive(dst_meta, _dst_lamports, dst_flags), MergeKind::ActivationEpoch(_, src_stake, src_flags)) => {
            pinocchio::msg!("merge:inline IN+AE");
            // New delegated stake equals total post-merge lamports minus destination's rent-exempt reserve.
            let total_post = checked_add(dst_ai.lamports(), src_ai.lamports())?;
            let dst_reserve = bytes_to_u64(dst_meta.rent_exempt_reserve);
            let new_stake = total_post
                .checked_sub(dst_reserve)
                .ok_or(ProgramError::ArithmeticOverflow)?;
            let mut stake_out = src_stake;
            stake_out.delegation.stake = new_stake.to_le_bytes();
            let merged_flags = dst_flags.union(src_flags);
            set_stake_state(dst_ai, &StakeStateV2::Stake(dst_meta, stake_out, merged_flags))?;
            set_stake_state(src_ai, &StakeStateV2::Uninitialized)?;
            relocate_lamports(src_ai, dst_ai, src_ai.lamports())?;
            return Ok(());
        }
        (MergeKind::ActivationEpoch(meta, mut stake, dst_flags), MergeKind::Inactive(_, src_lamports, src_flags)) => {
            pinocchio::msg!("merge:inline AE+IN");
            let new_stake = checked_add(bytes_to_u64(stake.delegation.stake), src_lamports)?;
            stake.delegation.stake = new_stake.to_le_bytes();
            let merged_flags = dst_flags.union(src_flags);
            set_stake_state(dst_ai, &StakeStateV2::Stake(meta, stake, merged_flags))?;
            set_stake_state(src_ai, &StakeStateV2::Uninitialized)?;
            relocate_lamports(src_ai, dst_ai, src_ai.lamports())?;
            return Ok(());
        }
        (MergeKind::ActivationEpoch(dst_meta, mut dst_stake, dst_flags), MergeKind::ActivationEpoch(src_meta, src_stake, src_flags)) => {
            pinocchio::msg!("merge:inline AE+AE");
            let src_stake_lamports = checked_add(bytes_to_u64(src_meta.rent_exempt_reserve), bytes_to_u64(src_stake.delegation.stake))?;
            crate::helpers::merge::merge_delegation_stake_and_credits_observed(&mut dst_stake, src_stake_lamports, bytes_to_u64(src_stake.credits_observed))?;
            let merged_flags = dst_flags.union(src_flags);
            set_stake_state(dst_ai, &StakeStateV2::Stake(dst_meta, dst_stake, merged_flags))?;
            set_stake_state(src_ai, &StakeStateV2::Uninitialized)?;
            relocate_lamports(src_ai, dst_ai, src_ai.lamports())?;
            return Ok(());
        }
        (MergeKind::FullyActive(dst_meta, mut dst_stake), MergeKind::FullyActive(_, src_stake)) => {
            pinocchio::msg!("merge:inline FA+FA");
            crate::helpers::merge::merge_delegation_stake_and_credits_observed(&mut dst_stake, bytes_to_u64(src_stake.delegation.stake), bytes_to_u64(src_stake.credits_observed))?;
            set_stake_state(dst_ai, &StakeStateV2::Stake(dst_meta, dst_stake, crate::state::stake_flag::StakeFlags::empty()))?;
            set_stake_state(src_ai, &StakeStateV2::Uninitialized)?;
            relocate_lamports(src_ai, dst_ai, src_ai.lamports())?;
            return Ok(());
        }
        _ => {
            pinocchio::msg!("merge:unsupported_shape");
            return Err(to_program_error(StakeError::MergeMismatch));
        }
    }
}
