use pinocchio::{
    account_info::AccountInfo, program_error::ProgramError, pubkey::Pubkey, sysvars::{clock::Clock, Sysvar},
    ProgramResult,
};

use crate::{
    helpers::{get_stake_state, set_stake_state},
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
    // Simple positional order (native-compatible): [stake, clock, current_authority, (optional custodian), ...]
    if accounts.len() < 3 { return Err(ProgramError::NotEnoughAccountKeys); }
    let [stake_ai, clock_ai, current_auth_ai, rest @ ..] = accounts else { return Err(ProgramError::NotEnoughAccountKeys) };

    if *stake_ai.owner() != crate::ID {
        return Err(ProgramError::InvalidAccountOwner);
    }
    if !stake_ai.is_writable() {
        return Err(ProgramError::InvalidInstructionData);
    }
    if clock_ai.key() != &pinocchio::sysvars::clock::CLOCK_ID {
        return Err(ProgramError::InvalidInstructionData);
    }
    if !current_auth_ai.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }

    // Read clock via syscall for Pinocchio safety while retaining wire slot for clock
    let clock = Clock::get()?;
    let state = get_stake_state(stake_ai)?;

    // Determine custodian for this account and locate a matching signer if present
    let custodian_pk = match &state {
        StakeStateV2::Initialized(meta) => meta.lockup.custodian,
        StakeStateV2::Stake(meta, _, _) => meta.lockup.custodian,
        _ => return Err(ProgramError::InvalidAccountData),
    };
    let maybe_lockup_authority: Option<&AccountInfo> = rest
        .iter()
        .find(|ai| ai.is_signer() && ai.key() == &custodian_pk);

    // Restricted signers slice: current authority and optional custodian
    let mut signers = [Pubkey::default(); 2];
    let mut n = 0usize;
    signers[n] = *current_auth_ai.key(); n += 1;
    if let Some(ai) = maybe_lockup_authority { signers[n] = *ai.key(); n += 1; }
    let signers = &signers[..n];

    match state {
        StakeStateV2::Initialized(mut meta) => {
            authorize_update(&mut meta, new_authority, authority_type, signers, maybe_lockup_authority, &clock)?;
            set_stake_state(stake_ai, &StakeStateV2::Initialized(meta))?;
        }
        StakeStateV2::Stake(mut meta, stake, flags) => {
            authorize_update(&mut meta, new_authority, authority_type, signers, maybe_lockup_authority, &clock)?;
            set_stake_state(stake_ai, &StakeStateV2::Stake(meta, stake, flags))?;
        }
        _ => return Err(ProgramError::InvalidAccountData),
    }

    Ok(())
}
