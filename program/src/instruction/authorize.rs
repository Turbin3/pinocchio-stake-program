use pinocchio::{
    account_info::AccountInfo, program_error::ProgramError, pubkey::Pubkey, sysvars::clock::Clock,
    ProgramResult,
};

use crate::{
    helpers::{collect_signers, get_stake_state, set_stake_state, MAXIMUM_SIGNERS},
    state::{stake_state_v2::StakeStateV2, StakeAuthorize},
};
use crate::helpers::authorize_update; 

/*fn parse_authorize_data(data: &[u8]) -> Result<AuthorizeData, ProgramError> {
    if data.len() != 33 { return Err(ProgramError::InvalidInstructionData); }
    let new_authorized =
        Pubkey::try_from(&data[0..32]).map_err(|_| ProgramError::InvalidInstructionData)?;
    let stake_authorize = match data[32] {
        0 => StakeAuthorize::Staker,
        1 => StakeAuthorize::Withdrawer,
        _ => return Err(ProgramError::InvalidInstructionData),
    };
    Ok(AuthorizeData { new_authorized, stake_authorize })
}*/

pub fn process_authorize(
    accounts: &[AccountInfo],
    new_authority: Pubkey,
    authority_type: StakeAuthorize,
) -> ProgramResult {
    if accounts.len() < 2 { return Err(ProgramError::NotEnoughAccountKeys); }

    // Find stake (owned by this program and writable) and clock sysvar anywhere in the list
    let mut stake_idx: Option<usize> = None;
    let mut clock_idx: Option<usize> = None;
    for (i, ai) in accounts.iter().enumerate() {
        if stake_idx.is_none() && *ai.owner() == crate::ID && ai.is_writable() {
            stake_idx = Some(i);
        }
        if clock_idx.is_none() && ai.key() == &pinocchio::sysvars::clock::CLOCK_ID {
            clock_idx = Some(i);
        }
        if stake_idx.is_some() && clock_idx.is_some() { break; }
    }
    let stake_ai = accounts.get(stake_idx.ok_or(ProgramError::InvalidAccountData)?)
        .ok_or(ProgramError::InvalidAccountData)?;
    let clock_ai = accounts.get(clock_idx.ok_or(ProgramError::InvalidInstructionData)?)
        .ok_or(ProgramError::InvalidInstructionData)?;
    if *stake_ai.owner() != crate::ID || !stake_ai.is_writable() { return Err(ProgramError::IncorrectProgramId); }
    let clock = unsafe { Clock::from_account_info_unchecked(clock_ai)? };

    // Load state to identify the expected lockup custodian; pass it if present and signer
    let state = get_stake_state(stake_ai)?;
    let custodian_pk = match &state {
        StakeStateV2::Initialized(meta) => meta.lockup.custodian,
        StakeStateV2::Stake(meta, _, _) => meta.lockup.custodian,
        _ => Pubkey::default(),
    };
    let maybe_lockup_authority: Option<&AccountInfo> = accounts
        .iter()
        .find(|ai| ai.key() == &custodian_pk && ai.is_signer());

    // Collect all tx signers
    let mut signers_buf = [Pubkey::default(); MAXIMUM_SIGNERS];
    let n = collect_signers(accounts, &mut signers_buf)?;
    let signers = &signers_buf[..n];

    // Update and store
    match state {
        StakeStateV2::Initialized(mut meta) => {
            authorize_update(
                &mut meta,
                new_authority,
                authority_type,
                signers,
                maybe_lockup_authority,
                &clock,
            )?;
            set_stake_state(stake_ai, &StakeStateV2::Initialized(meta))?;
        }
        StakeStateV2::Stake(mut meta, stake, flags) => {
            authorize_update(
                &mut meta,
                new_authority,
                authority_type,
                signers,
                maybe_lockup_authority,
                &clock,
            )?;
            set_stake_state(stake_ai, &StakeStateV2::Stake(meta, stake, flags))?;
        }
        _ => return Err(ProgramError::InvalidAccountData),
    }

    Ok(())
}
