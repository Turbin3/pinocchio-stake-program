use pinocchio::{
    account_info::AccountInfo,
    program_error::ProgramError,
    pubkey::Pubkey,
    sysvars::clock::Clock,
    ProgramResult,
};

use crate::{
    error::to_program_error,
    helpers::{collect_signers, next_account_info},
    helpers::utils::{
        get_stake_state, get_vote_credits, new_stake_with_credits, redelegate_stake_with_credits, set_stake_state,
        validate_delegated_amount, ValidatedDelegatedInfo,
    },
    helpers::constant::MAXIMUM_SIGNERS,
    state::{StakeAuthorize, StakeFlags, StakeHistorySysvar, StakeStateV2},
};

/// Redelegate/Delegate helper (works for initial delegation and redelegation)
pub fn redelegate(accounts: &[AccountInfo]) -> ProgramResult {
    // Collect signers from the full account list
    let mut signers_buf = [Pubkey::default(); MAXIMUM_SIGNERS];
    let n = collect_signers(accounts, &mut signers_buf)?;
    let signers = &signers_buf[..n];

    // Expected accounts: 4 or 5 (native shape) -> [stake, vote, clock, stake_history, (optional stake_config)]
    let account_info_iter = &mut accounts.iter();
    let stake_account_info = next_account_info(account_info_iter)?;
    let vote_account_info  = next_account_info(account_info_iter)?;
    let clock_info         = next_account_info(account_info_iter)?;
    let stake_history_ai   = next_account_info(account_info_iter)?; // present but not read directly
    let _maybe_stake_config_ai = account_info_iter.next(); // optional and not read directly

    // Ownership/identity checks for native parity
    if *stake_account_info.owner() != crate::ID || !stake_account_info.is_writable() {
        return Err(ProgramError::InvalidAccountOwner);
    }
    if *vote_account_info.owner() != crate::state::vote_state::vote_program_id() {
        return Err(ProgramError::IncorrectProgramId);
    }
    // clock will be validated by Clock::from_account_info
    if stake_history_ai.key() != &crate::state::stake_history::ID {
        return Err(ProgramError::InvalidInstructionData);
    }
    // Optional: enforce stake_config identity behind a feature flag (not required for logic)
    // #[cfg(feature = "enforce-stake-config")]
    // if _stake_config_ai.key() != &crate::state::stake_config::ID {
    //     return Err(ProgramError::InvalidInstructionData);
    // }

    let clock = &Clock::from_account_info(clock_info)?;
    let stake_history = StakeHistorySysvar(clock.epoch);

    let vote_credits = get_vote_credits(vote_account_info)?;

    match get_stake_state(stake_account_info)? {
        StakeStateV2::Initialized(meta) => {
            // staker must sign
            meta.authorized
                .check(signers, StakeAuthorize::Staker)
                .map_err(to_program_error)?;

            // how much can be delegated (lamports - rent)
            let ValidatedDelegatedInfo { stake_amount } =
                validate_delegated_amount(stake_account_info, &meta)?;

            // Enforce minimum delegation at (re)delegate time (native parity)
            let min = crate::helpers::get_minimum_delegation();
            if stake_amount < min {
                return Err(to_program_error(crate::error::StakeError::InsufficientDelegation));
            }

            // create stake delegated to the vote account
            let stake = new_stake_with_credits(
                stake_amount,
                vote_account_info.key(),
                clock.epoch,
                vote_credits,
            );

            set_stake_state(
                stake_account_info,
                &StakeStateV2::Stake(meta, stake, StakeFlags::empty()),
            )?;
        }
        StakeStateV2::Stake(meta, mut stake, flags) => {
            // staker must sign
            meta.authorized
                .check(signers, StakeAuthorize::Staker)
                .map_err(to_program_error)?;

            let ValidatedDelegatedInfo { stake_amount } =
                validate_delegated_amount(stake_account_info, &meta)?;

            // Enforce minimum delegation on redelegation when inactive (native parity)
            let min = crate::helpers::get_minimum_delegation();
            if stake_amount < min {
                return Err(to_program_error(crate::error::StakeError::InsufficientDelegation));
            }

            // Mirror explicit TooSoon pre-check: if deactivating and target vote differs, reject
            let current_voter = stake.delegation.voter_pubkey;
            let deact_epoch = crate::helpers::bytes_to_u64(stake.delegation.deactivation_epoch);
            if deact_epoch != u64::MAX && current_voter != *vote_account_info.key() {
                return Err(to_program_error(crate::error::StakeError::TooSoonToRedelegate));
            }

            // Delegate helper enforces the active-stake rules & rescind-on-same-voter case.
            redelegate_stake_with_credits(
                &mut stake,
                stake_amount,
                vote_account_info.key(),
                vote_credits,
                clock.epoch,
                &stake_history,
            )?;

            set_stake_state(stake_account_info, &StakeStateV2::Stake(meta, stake, flags))?;
        }
        _ => return Err(ProgramError::InvalidAccountData),
    }

    Ok(())
}
