use pinocchio::{
    account_info::AccountInfo,
    program_error::ProgramError,
    pubkey::Pubkey,
    sysvars::clock::Clock,
    ProgramResult,
};

use crate::{
    helpers::{collect_signers, get_stake_state, set_stake_state, MAXIMUM_SIGNERS},
    helpers::authorize_update,
    state::{
        accounts::AuthorizeWithSeedData,
        stake_state_v2::StakeStateV2,
    },
};



pub fn process_authorized_with_seeds(
    accounts: &[AccountInfo],
    args: AuthorizeWithSeedData, // already has: new_authorized, stake_authorize, authority_seed, authority_owner
) -> ProgramResult { 
    let role = args.stake_authorize;
    // Required accounts: stake, base, clock (optional custodian)
    if accounts.len() < 3 {
        return Err(ProgramError::NotEnoughAccountKeys);
    }

    // stake, base, clock, [maybe custodian, ...]
    let [stake_ai, _base_ai, clock_ai, rest @ ..] = accounts else {
        return Err(ProgramError::InvalidAccountData);
    };

    // Basic safety checks
    if *stake_ai.owner() != crate::ID || !stake_ai.is_writable() {
        return Err(ProgramError::IncorrectProgramId);
    }
    if clock_ai.key() != &pinocchio::sysvars::clock::CLOCK_ID {
        return Err(ProgramError::InvalidArgument);
    }

    // Load clock (safe)
    let clock = Clock::from_account_info(clock_ai)?;

    // Optional lockup custodian account (pass-through to policy)
    let maybe_lockup_authority: Option<&AccountInfo> = rest.first();

   
    // Build the signer set (include all tx signers). Base signer is sufficient
    // to satisfy policy for non-checked variant (old authority may change it).
    let mut signers_buf = [Pubkey::default(); MAXIMUM_SIGNERS];
    let n = collect_signers(accounts, &mut signers_buf)?;
    // No extra augmentation needed

    // Final signer slice we pass to the policy
    let signers = &signers_buf[..n];

    // Load state, apply policy update, write back
    match get_stake_state(stake_ai)? {
        StakeStateV2::Initialized(mut meta) => {
            authorize_update(
                &mut meta,
                args.new_authorized,
                role,
                signers,
                maybe_lockup_authority,
                &clock,
            )?;
            set_stake_state(stake_ai, &StakeStateV2::Initialized(meta))?;
        }
        StakeStateV2::Stake(mut meta, stake, flags) => {
            authorize_update(
                &mut meta,
                args.new_authorized,
                role,
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
