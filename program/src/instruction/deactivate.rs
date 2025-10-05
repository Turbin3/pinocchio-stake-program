use pinocchio::{
    account_info::AccountInfo,
    program_error::ProgramError,
    pubkey::Pubkey,
    sysvars::{clock::Clock, Sysvar},
    ProgramResult,
};

use crate::{
    error::to_program_error,
    helpers::{collect_signers, get_stake_state, set_stake_state, MAXIMUM_SIGNERS},
    state::{stake_state_v2::StakeStateV2, StakeAuthorize},
};

pub fn process_deactivate(accounts: &[AccountInfo]) -> ProgramResult {
    if accounts.is_empty() { return Err(ProgramError::NotEnoughAccountKeys); }

    // Gather tx signers (repo-compatible behavior)
    let mut signers_buf = [Pubkey::default(); MAXIMUM_SIGNERS];
    let signers_len = collect_signers(accounts, &mut signers_buf)?;
    let signers = &signers_buf[..signers_len];

    let stake_ai = &accounts[0];

    // Native-like error split
    if *stake_ai.owner() != crate::ID { return Err(ProgramError::InvalidAccountOwner); }
    if !stake_ai.is_writable() { return Err(ProgramError::InvalidInstructionData); }

    let clock = Clock::get()?;

    // Load stake state and apply
    match get_stake_state(stake_ai)? {
        StakeStateV2::Stake(meta, mut stake, flags) => {
            // Require staker signature (from tx signers)
            meta.authorized
                .check(signers, StakeAuthorize::Staker)
                .map_err(to_program_error)?;

            stake.deactivate(clock.epoch.to_le_bytes()).map_err(to_program_error)?;
            set_stake_state(stake_ai, &StakeStateV2::Stake(meta, stake, flags))?;
            Ok(())
        }
        _ => Err(ProgramError::InvalidAccountData),
    }
}
