use pinocchio::{
    account_info::AccountInfo,
    msg,
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

//

pub fn process_withdraw(accounts: &[AccountInfo], withdraw_lamports: u64) -> ProgramResult {
    #[cfg(feature = "cu-trace")] msg!("Withdraw: enter");
    // Discover accounts by role (tolerant to order):
    let mut source_stake_account_info: Option<&AccountInfo> = None;
    let mut destination_info: Option<&AccountInfo> = None;
    let mut clock_info: Option<&AccountInfo> = None;

    // Identify stake and destination
    for ai in accounts.iter() {
        if source_stake_account_info.is_none() && *ai.owner() == crate::ID && ai.is_writable() {
            source_stake_account_info = Some(ai);
            continue;
        }
    }
    // Requires stake to be found to avoid picking it as destination
    let stake_key = source_stake_account_info
        .ok_or(ProgramError::InvalidAccountData)?
        .key();

    for ai in accounts.iter() {
        if clock_info.is_none() && ai.key() == &pinocchio::sysvars::clock::CLOCK_ID {
            clock_info = Some(ai);
            continue;
        }
        // Destination: first writable non-stake and non-sysvar account
        if destination_info.is_none()
            && ai.is_writable()
            && ai.key() != stake_key
            && ai.key() != &pinocchio::sysvars::clock::CLOCK_ID
            && ai.key() != &crate::state::stake_history::ID
        {
            destination_info = Some(ai);
        }
    }

    let source_stake_account_info = source_stake_account_info.ok_or(ProgramError::InvalidAccountData)?;
    let destination_info = destination_info.ok_or(ProgramError::InvalidInstructionData)?;
    let clock_info = clock_info.ok_or(ProgramError::InvalidInstructionData)?;

    // Fast path: Uninitialized source with source signer — no sysvars needed
    match get_stake_state(source_stake_account_info) {
        Ok(StakeStateV2::Uninitialized) => {
            msg!("Withdraw: source=Uninitialized fast path");
            if !source_stake_account_info.is_signer() {
                return Err(ProgramError::MissingRequiredSignature);
            }
            relocate_lamports(
                source_stake_account_info,
                destination_info,
                withdraw_lamports,
            )?;
            return Ok(());
        }
        _ => {}
    }

    #[cfg(feature = "cu-trace")] msg!("Withdraw: load clock");
    let clock = &Clock::from_account_info(clock_info)?;
    let stake_history = &StakeHistorySysvar(clock.epoch);

    // Collect all transaction signers and determine optional custodian by state
    #[cfg(feature = "cu-trace")] msg!("Withdraw: gather signers");
    let mut signers_vec = [Pubkey::default(); crate::helpers::MAXIMUM_SIGNERS];
    let n_signers = crate::helpers::collect_signers(accounts, &mut signers_vec)?;
    let signers_slice: &[Pubkey] = &signers_vec[..n_signers];

    // Decide withdrawal constraints based on current stake state
    #[cfg(feature = "cu-trace")] msg!("Withdraw: read state");
    let (lockup, reserve_u64, is_staked) = match get_stake_state(source_stake_account_info)? {
        StakeStateV2::Stake(meta, stake, _stake_flags) => {
            #[cfg(feature = "cu-trace")] msg!("Withdraw: state=Stake");
            // Must have withdraw authority
            meta.authorized
                .check(signers_slice, StakeAuthorize::Withdrawer)
                .map_err(to_program_error)?;

            // Convert little-endian fields to u64
            let deact_epoch = u64::from_le_bytes(stake.delegation.deactivation_epoch);
            // During the deactivation epoch, stake is still fully effective for withdrawal rules
            let staked: u64 = if deact_epoch != u64::MAX && clock.epoch == deact_epoch {
                u64::from_le_bytes(stake.delegation.stake)
            } else if deact_epoch != u64::MAX && clock.epoch > deact_epoch {
                // After deactivation epoch, consult history to compute remaining effective
                stake.delegation.stake(
                    clock.epoch.to_le_bytes(),
                    stake_history,
                    crate::helpers::PERPETUAL_NEW_WARMUP_COOLDOWN_RATE_EPOCH,
                )
            } else {
                // Not deactivating
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
            // For Uninitialized, require the source account to be a signer
            if !source_stake_account_info.is_signer() {
                return Err(ProgramError::MissingRequiredSignature);
            }
            (Lockup::default(), 0u64, false)
        }
        _ => return Err(ProgramError::InvalidAccountData),
    };

    // Lockup must be expired or bypassed by a custodian signer
    #[cfg(feature = "cu-trace")] msg!("Withdraw: check lockup");
    // Determine if a custodian signer is present among accounts
    let custodian = accounts
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
