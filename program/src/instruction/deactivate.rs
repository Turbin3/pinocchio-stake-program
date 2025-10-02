use pinocchio::{
    account_info::AccountInfo,
    program_error::ProgramError,
    pubkey::Pubkey,
    sysvars::clock::Clock,
    ProgramResult,
};

use crate::{
    error::to_program_error,
    helpers::{collect_signers, get_stake_state, next_account_info, set_stake_state, MAXIMUM_SIGNERS},
    state::{stake_state_v2::StakeStateV2, StakeAuthorize},
};

pub fn process_deactivate(accounts: &[AccountInfo]) -> ProgramResult {
    // 1) Gather all transaction signers
    let mut signers_buf = [Pubkey::default(); MAXIMUM_SIGNERS];
    let signers_len = collect_signers(accounts, &mut signers_buf)?;
    let signers = &signers_buf[..signers_len];

    // 2) Accounts: stake, clock (extra accounts are ignored)
    let it = &mut accounts.iter();
    let stake_ai = next_account_info(it)?;
    let clock_ai = next_account_info(it)?;

    let clock = Clock::from_account_info(clock_ai)?;

    // 3) Load stake state (also checks program owner inside helper)
    let state = get_stake_state(stake_ai)?;

    // 4) Authorization + state transition
    match state {
        StakeStateV2::Stake(meta, mut stake, flags) => {
            // Require staker signature
            meta.authorized
                .check(signers, StakeAuthorize::Staker)
                .map_err(to_program_error)?;

            // delegate to stake logic — this enforces flags / “already deactivated” etc.
            stake
                .deactivate(clock.epoch.to_le_bytes())
                .map_err(to_program_error)?;
            pinocchio::msg!("deactivate: set_epoch");

            // 5) Write back
            set_stake_state(stake_ai, &StakeStateV2::Stake(meta, stake, flags))?;
        }
        _ => return Err(ProgramError::InvalidAccountData),
    }

    Ok(())
}
