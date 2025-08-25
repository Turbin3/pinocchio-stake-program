use pinocchio::{
    account_info::AccountInfo, program_error::ProgramError, pubkey::Pubkey, sysvars::clock::Clock,
    ProgramResult,
};

use crate::{
    error::to_program_error,
    helpers::*,
    state::{StakeAuthorize, StakeFlags, StakeHistorySysvar, StakeStateV2},
};

pub fn redelegate(accounts: &[AccountInfo]) -> ProgramResult {
    // Check for enough accounts
    if accounts.len() < 5 {
        return Err(ProgramError::NotEnoughAccountKeys);
    }

    // Collect all signer pubkeys for authorization checks
    let mut signers_array = [Pubkey::default(); MAXIMUM_SIGNERS];
    let signers_count = collect_signers(accounts, &mut signers_array)?;
    let signers = &signers_array[..signers_count];

    // Get the required accounts
    let stake_account_info = &accounts[0];
    let vote_account_info = &accounts[1];
    let clock_info = &accounts[2];
    // We access accounts[3] and accounts[4] but don't use them directly
    // They're provided for compatibility with the Solana stake program interface

    // Make sure accounts are valid
    if !stake_account_info.is_writable() {
        return Err(ProgramError::InvalidAccountData);
    }

    // Get clock and stake history
    let clock = Clock::from_account_info(clock_info)?;
    let stake_history = StakeHistorySysvar(clock.slot);

    // Get vote state from the vote account
    let vote_state = get_vote_state(vote_account_info)?;

    // Get current state of the stake account
    let stake_state = StakeStateV2::deserialize(&stake_account_info.try_borrow_data()?)?;

    // Process based on current stake state
    match stake_state {
        StakeStateV2::Initialized(meta) => {
            // Verify authorization
            meta.authorized
                .check(&signers, StakeAuthorize::Staker)
                .map_err(to_program_error)?;

            // Validate delegation amount
            let ValidatedDelegatedInfo { stake_amount } =
                validate_delegated_amount(stake_account_info, &meta)?;

            // Create new stake with delegation to the vote account
            let stake = new_stake(
                stake_amount,
                vote_account_info.key(),
                &vote_state,
                clock.epoch,
            );

            // Update stake state with new delegation
            set_stake_state(
                stake_account_info,
                &StakeStateV2::Stake(meta, stake, StakeFlags::empty()),
            )?;

            // Successfully delegated stake
        }
        StakeStateV2::Stake(meta, mut stake, flags) => {
            // Verify authorization
            meta.authorized
                .check(&signers, StakeAuthorize::Staker)
                .map_err(to_program_error)?;

            // Validate redelegation amount
            let ValidatedDelegatedInfo { stake_amount } =
                validate_delegated_amount(stake_account_info, &meta)?;

            // If already delegated to the same vote account, this is a no-op
            if stake.delegation.voter_pubkey == *vote_account_info.key() {
                return Ok(());
            }

            // Redelegate to the new vote account
            redelegate_stake(
                &mut stake,
                stake_amount,
                vote_account_info.key(),
                &vote_state,
                clock.epoch,
                &stake_history,
            )?;

            // Update stake state with new delegation
            set_stake_state(stake_account_info, &StakeStateV2::Stake(meta, stake, flags))?;

            // Successfully redelegated stake
        }
        _ => return Err(ProgramError::InvalidAccountData),
    }

    Ok(())
}
