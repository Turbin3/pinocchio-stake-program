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

    // Canonical order (SDK/native): [stake, authority, clock].
    // Load and validate stake first so Uninitialized returns InvalidAccountData
    let stake_ai = &accounts[0];
    if *stake_ai.owner() != crate::ID || !stake_ai.is_writable() {
        return Err(ProgramError::IncorrectProgramId);
    }

    // Quick path: if stake account is Uninitialized (discriminant == 0), return InvalidAccountData
    let data = unsafe { stake_ai.borrow_data_unchecked() };
    if !data.is_empty() && data[0] == 0 {
        return Err(ProgramError::InvalidAccountData);
    }
    // Load state for Initialized/Stake
    let state = get_stake_state(stake_ai)?;

    // Require clock in the remaining accounts only if state is not Uninitialized
    let clock = match state {
        StakeStateV2::Uninitialized => { return Err(ProgramError::InvalidAccountData); }
        _ => {
            // Find clock anywhere among remaining accounts to be tolerant to SDK ordering
            let clock_ai = accounts
                .iter()
                .find(|ai| ai.key() == &pinocchio::sysvars::clock::CLOCK_ID)
                .ok_or(ProgramError::InvalidInstructionData)?;
            unsafe { Clock::from_account_info_unchecked(clock_ai)? }
        }
    };

    // Load state to identify the expected lockup custodian; pass it if present and signer
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
