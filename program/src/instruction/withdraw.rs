use pinocchio::{
    account_info::AccountInfo,
    program_error::ProgramError,
    sysvars::clock::Clock,
    ProgramResult,
};

use crate::{
    error::{to_program_error, StakeError},
    helpers::{checked_add, get_stake_state, relocate_lamports, set_stake_state},
    state::{Lockup, StakeAuthorize, StakeHistorySysvar, StakeStateV2},

};
use pinocchio::pubkey::Pubkey;
use pinocchio::sysvars::{rent::Rent, Sysvar};

//

pub fn process_withdraw(accounts: &[AccountInfo], withdraw_lamports: u64) -> ProgramResult {
   
    // [stake, destination, clock, stake_history, withdraw_authority, (optional custodian), ...]
    if accounts.len() < 5 { return Err(ProgramError::NotEnoughAccountKeys); }
    let [
        source_stake_account_info,
        destination_info,
        clock_info,
        stake_history_info,
        withdraw_authority_info,
        rest @ ..
    ] = accounts else { return Err(ProgramError::NotEnoughAccountKeys) };

    // Basic checks on key roles
    if *source_stake_account_info.owner() != crate::ID || !source_stake_account_info.is_writable() {
        return Err(ProgramError::InvalidAccountOwner);
    }
    if !destination_info.is_writable() {
        return Err(ProgramError::InvalidInstructionData);
    }
    if clock_info.key() != &pinocchio::sysvars::clock::CLOCK_ID {
        return Err(ProgramError::InvalidInstructionData);
    }
    // Require stake_history sysvar id (native expects the exact account)
    if stake_history_info.key() != &crate::state::stake_history::ID {
        return Err(ProgramError::InvalidInstructionData);
    }

    #[cfg(feature = "cu-trace")] msg!("Withdraw: load clock");
    let clock = &Clock::from_account_info(clock_info)?;
    let stake_history = &StakeHistorySysvar(clock.epoch);

    // Build restricted signer set: withdrawer MUST sign; custodian is only required if lockup is in force.
    if !withdraw_authority_info.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }
    let mut restricted = [Pubkey::default(); 1];
    restricted[0] = *withdraw_authority_info.key();
    let signers_slice: &[Pubkey] = &restricted[..1];

    // Decide withdrawal constraints based on current stake state
    #[cfg(feature = "cu-trace")] msg!("Withdraw: read state");
    let (lockup, reserve_u64, is_staked) = match get_stake_state(source_stake_account_info)? {
        StakeStateV2::Stake(meta, stake, _stake_flags) => {
            #[cfg(feature = "cu-trace")] msg!("Withdraw: state=Stake");
            // Must have withdraw authority
            meta.authorized
                .check(signers_slice, StakeAuthorize::Withdrawer)
                .map_err(to_program_error)?;

            // At or past deactivation epoch, use dynamic effective stake
            let deact_epoch = u64::from_le_bytes(stake.delegation.deactivation_epoch);
            let staked: u64 = if deact_epoch != u64::MAX && clock.epoch >= deact_epoch {
                stake.delegation.stake(
                    clock.epoch.to_le_bytes(),
                    stake_history,
                    crate::helpers::PERPETUAL_NEW_WARMUP_COOLDOWN_RATE_EPOCH,
                )
            } else {
                u64::from_le_bytes(stake.delegation.stake)
            };

            let rent_reserve = u64::from_le_bytes(meta.rent_exempt_reserve);
            let staked_plus_reserve = checked_add(staked, rent_reserve)?;
            (meta.lockup, staked_plus_reserve, staked != 0)
        }
        StakeStateV2::Initialized(meta) => {
            #[cfg(feature = "cu-trace")] msg!("Withdraw: state=Initialized");
            // Must have withdraw authority
            meta.authorized
                .check(signers_slice, StakeAuthorize::Withdrawer)
                .map_err(to_program_error)?;

            let rent_reserve = u64::from_le_bytes(meta.rent_exempt_reserve);
            (meta.lockup, rent_reserve, false)
        }
        StakeStateV2::Uninitialized => {
            // Native fast-path: only the source stake account must sign
            if !source_stake_account_info.is_signer() {
                return Err(ProgramError::MissingRequiredSignature);
            }
            // Enforce rent reserve for partial withdraws; full withdraw may close the account
            let rent_reserve = Rent::get()?.minimum_balance(source_stake_account_info.data_len());
            (Lockup::default(), rent_reserve, false)
        }
        _ => return Err(ProgramError::InvalidAccountData),
    };

    // Lockup must be expired or bypassed by a custodian signer (scan trailing accounts for matching custodian)
    let custodian = rest
        .iter()
        .find(|ai| ai.is_signer() && ai.key() == &lockup.custodian)
        .map(|ai| ai.key());
    if lockup.is_in_force(clock, custodian) {
        return Err(to_program_error(StakeError::LockupInForce));
    }

    let stake_account_lamports = source_stake_account_info.lamports();

    if withdraw_lamports == stake_account_lamports {
        #[cfg(feature = "cu-trace")] msg!("Withdraw: full");
        // Full withdrawal: can't close if still staked
        if is_staked {
            return Err(ProgramError::InsufficientFunds);
        }
        // Deinitialize state upon zero balance
        set_stake_state(source_stake_account_info, &StakeStateV2::Uninitialized)?;
    } else {
        #[cfg(feature = "cu-trace")] msg!("Withdraw: partial");
        // Partial withdrawal must not deplete the reserve
        let withdraw_plus_reserve = checked_add(withdraw_lamports, reserve_u64)?;
        if withdraw_plus_reserve > stake_account_lamports {
            return Err(ProgramError::InsufficientFunds);
        }
    }

    // Move lamports after state update
    #[cfg(feature = "cu-trace")] msg!("Withdraw: relocate lamports");
    relocate_lamports(
        source_stake_account_info,
        destination_info,
        withdraw_lamports,
    )?;

    #[cfg(feature = "cu-trace")] msg!("Withdraw: ok");
    Ok(())
}
