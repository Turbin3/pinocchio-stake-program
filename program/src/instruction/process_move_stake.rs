
extern crate alloc;
use pinocchio::{account_info::AccountInfo, program_error::ProgramError, ProgramResult, sysvars::Sysvar};

use crate::error::{to_program_error, StakeError};
use crate::helpers::{
    bytes_to_u64,
    get_minimum_delegation,
    relocate_lamports, // use shared helper, not a local copy
    set_stake_state,
    get_stake_state,
};
use crate::helpers::merge::{
    merge_delegation_stake_and_credits_observed,
    move_stake_or_lamports_shared_checks,
};
use crate::state::{MergeKind, StakeFlags, StakeStateV2};

pub fn process_move_stake(accounts: &[AccountInfo], lamports: u64) -> ProgramResult {
    pinocchio::msg!("mvstake:begin");
    // Canonical order: [source_stake, destination_stake, staker]
    if accounts.len() < 3 { return Err(ProgramError::NotEnoughAccountKeys); }
    let [source_stake_account_info, destination_stake_account_info, stake_authority_info, ..] = accounts else {
        return Err(ProgramError::InvalidAccountData);
    };
    if *source_stake_account_info.owner() != crate::ID
        || *destination_stake_account_info.owner() != crate::ID
        || !source_stake_account_info.is_writable()
        || !destination_stake_account_info.is_writable()
    {
        return Err(ProgramError::InvalidAccountOwner);
    }
    pinocchio::msg!("mvstake:accs");
    // Resolve expected staker from source stake meta and ensure signer present
    let src_state = get_stake_state(source_stake_account_info)?;
    let expected_staker = match src_state {
        StakeStateV2::Initialized(meta) | StakeStateV2::Stake(meta, _, _) => meta.authorized.staker,
        _ => return Err(ProgramError::InvalidAccountData),
    };
    if !stake_authority_info.is_signer() || stake_authority_info.key() != &expected_staker {
        return Err(ProgramError::MissingRequiredSignature);
    }
    pinocchio::msg!("mvstake:auth");

    // Verify signer status is provided by the runtime
    if stake_authority_info.is_signer() {
    } else {
    }

    // Early: Uninitialized on either side is invalid for MoveStake
    if let Ok(state) = get_stake_state(source_stake_account_info) {
        if let StakeStateV2::Uninitialized = state {
            return Err(ProgramError::InvalidAccountData);
        }
    }
    if let Ok(state) = get_stake_state(destination_stake_account_info) {
        if let StakeStateV2::Uninitialized = state {
            return Err(ProgramError::InvalidAccountData);
        }
    }

    // Shared checks + classification (auth, writable, nonzero, compatible metas)
    let (source_kind, destination_kind) = move_stake_or_lamports_shared_checks(
        source_stake_account_info,
        lamports,
        destination_stake_account_info,
        stake_authority_info,
        true,  // need meta compat for stake
        true,  // require mergeable classification
    )?;
    pinocchio::msg!("mvstake:classified");

    // Additional explicit guard (post-signer-check): destination must not be deactivating
    if let Ok(StakeStateV2::Stake(_, stake, _)) = get_stake_state(destination_stake_account_info) {
        let deact = bytes_to_u64(stake.delegation.deactivation_epoch);
        let clock = pinocchio::sysvars::clock::Clock::get()?;
        if deact != u64::MAX && clock.epoch <= deact {
            return Err(crate::error::to_program_error(crate::error::StakeError::MergeMismatch));
        }
    }

    // Native safeguard: require exact account data size
    if source_stake_account_info.data_len() != StakeStateV2::size_of()
        || destination_stake_account_info.data_len() != StakeStateV2::size_of()
    {
        return Err(ProgramError::InvalidAccountData);
    }

    // Source must be fully active
    let MergeKind::FullyActive(source_meta, mut source_stake) = source_kind else {
        return Err(crate::error::to_program_error(crate::error::StakeError::MergeMismatch));
    };

    let minimum_delegation = get_minimum_delegation();
    let source_effective_stake = source_stake.delegation.stake;

    // cannot move more stake than the source has (even if it has plenty of lamports)
    let source_final_stake = bytes_to_u64(source_effective_stake)
        .checked_sub(lamports)
        .ok_or(ProgramError::InvalidArgument)?;

    // unless moving all stake, the source must remain at/above the minimum delegation
    if source_final_stake != 0 && source_final_stake < minimum_delegation {
        return Err(ProgramError::InvalidArgument);
    }

    // destination must be fully active or fully inactive
    let destination_meta = match destination_kind {
        MergeKind::FullyActive(destination_meta, mut destination_stake) => {
            // active destination must share the same vote account
            if source_stake.delegation.voter_pubkey != destination_stake.delegation.voter_pubkey {
                return Err(to_program_error(StakeError::VoteAddressMismatch));
            }

            let destination_effective_stake = destination_stake.delegation.stake;
            let destination_final_stake = bytes_to_u64(destination_effective_stake)
                .checked_add(lamports)
                .ok_or(ProgramError::ArithmeticOverflow)?;

            // ensure destination also meets the minimum (relevant if minimum is raised)
            if destination_final_stake < minimum_delegation {
                return Err(ProgramError::InvalidArgument);
            }

            // move stake weight and recompute credits_observed (weighted)
            merge_delegation_stake_and_credits_observed(
                &mut destination_stake,
                lamports,
                bytes_to_u64(source_stake.credits_observed),
            )?;

            set_stake_state(
                destination_stake_account_info,
                &StakeStateV2::Stake(destination_meta, destination_stake, StakeFlags::empty()),
            )?;

            destination_meta
        }
        MergeKind::Inactive(destination_meta, _lamports, _flags) => {
            // inactive destination must receive at least the minimum delegation
            if lamports < minimum_delegation {
                return Err(ProgramError::InvalidArgument);
            }

            // clone source stake shape and set only the moved stake amount
            let mut destination_stake = source_stake;
            destination_stake.delegation.stake = lamports.to_le_bytes();

            set_stake_state(
                destination_stake_account_info,
                &StakeStateV2::Stake(destination_meta, destination_stake, StakeFlags::empty()),
            )?;

            destination_meta
        }
        _ => return Err(crate::error::to_program_error(crate::error::StakeError::MergeMismatch)),
    };

    // write back source: either to Initialized(meta) if emptied, or Stake with reduced stake
    if source_final_stake == 0 {
        set_stake_state(
            source_stake_account_info,
            &StakeStateV2::Initialized(source_meta),
        )?;
    } else {
        source_stake.delegation.stake = source_final_stake.to_le_bytes();
        set_stake_state(
            source_stake_account_info,
            &StakeStateV2::Stake(source_meta, source_stake, StakeFlags::empty()),
        )?;
    }

    // physically move lamports between accounts
    relocate_lamports(
        source_stake_account_info,
        destination_stake_account_info,
        lamports,
    )?;

    // guard against impossible (rent) underflows due to any mismatch in math
    if source_stake_account_info.lamports() < bytes_to_u64(source_meta.rent_exempt_reserve)
        || destination_stake_account_info.lamports()
            < bytes_to_u64(destination_meta.rent_exempt_reserve)
    {
        return Err(ProgramError::InvalidArgument);
    }

    Ok(())
}
