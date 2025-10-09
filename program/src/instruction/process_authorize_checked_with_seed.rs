#![allow(clippy::result_large_err)]

use pinocchio::{
    account_info::AccountInfo,
    program_error::ProgramError,
    pubkey::Pubkey,
    sysvars::{clock::Clock, Sysvar},
    ProgramResult,
};
extern crate alloc;

use crate::{
    helpers::{authorize_update, get_stake_state, set_stake_state},
    state::{
        accounts::AuthorizeCheckedWithSeedData,
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

/// Authorize (checked, with seed)
/// Accounts (strict positions):
///   0. [writable] Stake account (owned by stake program)
///   1. [signer]   Base (seed base)
///   2. []         Clock sysvar
///   3. [signer]   New authority
///   4. [signer]   Optional custodian (required if lockup in force)
pub fn process_authorize_checked_with_seed(
    accounts: &[AccountInfo],
    args: AuthorizeCheckedWithSeedData,
) -> ProgramResult {
    if accounts.len() < 4 { return Err(ProgramError::NotEnoughAccountKeys); }

    // Enforce strict positions (native wire): [stake, base, clock, new_authority, (custodian?)]
    let [stake_ai, base_ai, clock_ai, new_ai, rest @ ..] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };

    if *stake_ai.owner() != crate::ID { return Err(ProgramError::InvalidAccountOwner); }
    if !stake_ai.is_writable() { return Err(ProgramError::InvalidInstructionData); }
    if !base_ai.is_signer() { return Err(ProgramError::MissingRequiredSignature); }
    if clock_ai.key() != &pinocchio::sysvars::clock::CLOCK_ID { return Err(ProgramError::InvalidInstructionData); }
    if !new_ai.is_signer() { return Err(ProgramError::MissingRequiredSignature); }

    // Read clock via sysvar for Pinocchio safety
    let clock = Clock::get()?;

    // Load state and determine the expected current authority by role
    let state = get_stake_state(stake_ai)?;
    let (staker_pk, withdrawer_pk, custodian_pk) = match &state {
        StakeStateV2::Initialized(meta) | StakeStateV2::Stake(meta, _, _) => (
            meta.authorized.staker,
            meta.authorized.withdrawer,
            meta.lockup.custodian,
        ),
        _ => return Err(ProgramError::InvalidAccountData),
    };

    let role = args.stake_authorize;
    let old_allowed: &[Pubkey] = match role {
        StakeAuthorize::Staker => &[staker_pk, withdrawer_pk],
        StakeAuthorize::Withdrawer => &[withdrawer_pk],
    };

    // Reject seeds longer than 32 (native behavior), then derive old authority from (base, seed, owner)
    let seed_len = args.authority_seed.len();
    if seed_len > 32 { return Err(ProgramError::InvalidInstructionData); }
    let mut seed_buf = [0u8; 32];
    if seed_len > 0 { seed_buf[..seed_len].copy_from_slice(&args.authority_seed[..seed_len]); }
    let derived_old = derive_with_seed_compat(base_ai.key(), &seed_buf[..seed_len], &args.authority_owner)?;
    if !old_allowed.iter().any(|k| *k == derived_old) {
        return Err(ProgramError::MissingRequiredSignature);
    }

    // Custodian handling
    let in_force = match &state {
        StakeStateV2::Initialized(meta) | StakeStateV2::Stake(meta, _, _) => meta.lockup.is_in_force(&clock, None),
        _ => false,
    };
    let maybe_custodian = rest.iter().find(|ai| ai.is_signer() && ai.key() == &custodian_pk);
    if matches!(role, StakeAuthorize::Withdrawer) && in_force && maybe_custodian.is_none() {
        return Err(ProgramError::MissingRequiredSignature);
    }

    let new_authorized = *new_ai.key();

    // Restricted signer set: derived old (+ optional custodian)
    let mut signers = [Pubkey::default(); 2];
    let mut n = 0usize;
    signers[n] = derived_old; n += 1;
    if let Some(c) = maybe_custodian { signers[n] = *c.key(); n += 1; }
    let signers = &signers[..n];

    match state {
        StakeStateV2::Initialized(mut meta) => {
            authorize_update(
                &mut meta,
                new_authorized,
                role.clone(),
                signers,
                maybe_custodian,
                &clock,
            )?;
            set_stake_state(stake_ai, &StakeStateV2::Initialized(meta))
        }
        StakeStateV2::Stake(mut meta, stake, flags) => {
            authorize_update(
                &mut meta,
                new_authorized,
                role,
                signers,
                maybe_custodian,
                &clock,
            )?;
            set_stake_state(stake_ai, &StakeStateV2::Stake(meta, stake, flags))
        }
        _ => Err(ProgramError::InvalidAccountData),
    }
}
