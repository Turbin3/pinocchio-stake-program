use pinocchio::{
    account_info::AccountInfo,
    program_error::ProgramError,
    pubkey::Pubkey,
    sysvars::{clock::Clock, Sysvar},
    ProgramResult,
};

use crate::{
    helpers::{get_stake_state, set_stake_state},
    helpers::authorize_update,
    state::{
        accounts::AuthorizeWithSeedData,
        stake_state_v2::StakeStateV2,
        StakeAuthorize,
    },
};



/// Recreates `Pubkey::create_with_seed(base, seed, owner)` in Pinocchio:
/// derived = sha256(base || seed || owner)
fn derive_with_seed_compat(base: &Pubkey, seed: &[u8], owner: &Pubkey) -> Result<Pubkey, ProgramError> {
    if seed.len() > 32 { return Err(ProgramError::InvalidInstructionData); }
    let mut buf = [0u8; 32 + 32 + 32];
    let mut off = 0usize;
    buf[off..off+32].copy_from_slice(&base[..]); off += 32;
    if !seed.is_empty() { buf[off..off+seed.len()].copy_from_slice(seed); }
    off += seed.len();
    buf[off..off+32].copy_from_slice(&owner[..]); off += 32;
    let out = crate::crypto::sha256::hash(&buf[..off]);
    Ok(out)
}

pub fn process_authorized_with_seeds(
    accounts: &[AccountInfo],
    args: AuthorizeWithSeedData, // already has: new_authorized, stake_authorize, authority_seed, authority_owner
) -> ProgramResult { 
    let role = args.stake_authorize;
    // Required accounts: [stake, base, clock, (optional custodian), ...]
    if accounts.len() < 3 { return Err(ProgramError::NotEnoughAccountKeys); }
    let [stake_ai, base_ai, clock_ai, rest @ ..] = accounts else { return Err(ProgramError::NotEnoughAccountKeys) };

    // Basic safety checks
    if *stake_ai.owner() != crate::ID {
        return Err(ProgramError::InvalidAccountOwner);
    }
    if !stake_ai.is_writable() {
        return Err(ProgramError::InvalidInstructionData);
    }
    if clock_ai.key() != &pinocchio::sysvars::clock::CLOCK_ID {
        return Err(ProgramError::InvalidInstructionData);
    }
    if !base_ai.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }
    

    // Load clock via sysvar
    let clock = Clock::get()?;

    // Load state to determine required current authority and expected custodian
    let state = get_stake_state(stake_ai)?;

    // Derive authority from (base, seed, owner)
    // Reject seeds longer than 32 (native behavior)
    let seed_len = args.authority_seed.len();
    if seed_len > 32 { return Err(ProgramError::InvalidInstructionData); }
    let mut seed_buf = [0u8; 32];
    if seed_len > 0 { seed_buf[..seed_len].copy_from_slice(&args.authority_seed[..seed_len]); }
    let mut derived = derive_with_seed_compat(base_ai.key(), &seed_buf[..seed_len], &args.authority_owner)?;

    // Derived must match current role; for Staker, allow withdrawer to rotate staker (parity)
    let (staker_pk, withdrawer_pk) = match &state {
        StakeStateV2::Initialized(meta) | StakeStateV2::Stake(meta, _, _) => (meta.authorized.staker, meta.authorized.withdrawer),
        _ => return Err(ProgramError::InvalidAccountData),
    };
    let mut derived_is_allowed_old = match role {
        StakeAuthorize::Staker => derived == staker_pk || derived == withdrawer_pk,
        StakeAuthorize::Withdrawer => derived == withdrawer_pk,
    };
    if !derived_is_allowed_old {
        return Err(ProgramError::MissingRequiredSignature);
    }

    // Optional lockup custodian (scan trailing accounts for a matching signer)
    let expected_custodian = match &state {
        StakeStateV2::Initialized(meta) | StakeStateV2::Stake(meta, _, _) => meta.lockup.custodian,
        _ => Pubkey::default(),
    };
    let maybe_lockup_authority: Option<&AccountInfo> = rest
        .iter()
        .find(|ai| ai.is_signer() && ai.key() == &expected_custodian);
    

    // Restricted signer set: derived (+ optional custodian)
    let mut signers = [Pubkey::default(); 2];
    let mut n = 0usize;
    signers[n] = derived; n += 1;
    if let Some(ai) = maybe_lockup_authority { signers[n] = *ai.key(); n += 1; }
    let signers = &signers[..n];

    // Apply policy update and write back
    
    match state {
        StakeStateV2::Initialized(mut meta) => {
            authorize_update(
                &mut meta,
                args.new_authorized,
                role.clone(),
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
