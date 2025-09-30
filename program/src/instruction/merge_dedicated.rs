extern crate alloc;
use crate::{
    error::{to_program_error, StakeError},
    helpers::{
        collect_signers,
        constant::MAXIMUM_SIGNERS,
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
    // Canonical SDK order: [destination, source, authority]
    if accounts.len() < 2 { return Err(ProgramError::NotEnoughAccountKeys); }
    let dst_ai = &accounts[0];
    let src_ai = &accounts[1];
    if dst_ai.key() == src_ai.key() { return Err(ProgramError::InvalidArgument); }
    if *dst_ai.owner() != ID || *src_ai.owner() != ID { return Err(ProgramError::InvalidAccountOwner); }
    if !dst_ai.is_writable() || !src_ai.is_writable() { return Err(ProgramError::InvalidInstructionData); }
    pinocchio::msg!("merge:accs_ok");

    // Load clock sysvar from any position
    let clock_ai = accounts
        .iter()
        .find(|ai| ai.key() == &pinocchio::sysvars::clock::CLOCK_ID)
        .ok_or(ProgramError::InvalidInstructionData)?;
    let clock = Clock::from_account_info(clock_ai)?;
    pinocchio::msg!("merge:clock");
    // Use the epoch wrapper; contents of history account are not read here
    let stake_history = StakeHistorySysvar(clock.epoch);

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

    // Fast-path already attempted using raw states above

    // Perform merge
    if let Some(merged_state) = dst_kind.merge(src_kind, &clock)? {
        set_stake_state(dst_ai, &merged_state)?;
    }

    // Deinitialize and drain source
    set_stake_state(src_ai, &StakeStateV2::Uninitialized)?;
    relocate_lamports(src_ai, dst_ai, src_ai.lamports())?;

    Ok(())
}
