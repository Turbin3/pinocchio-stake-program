#![allow(clippy::result_large_err)]

use pinocchio::{
    account_info::AccountInfo,
    program_error::ProgramError,
    pubkey::Pubkey,
    sysvars::{clock::Clock, Sysvar},
    ProgramResult,
};

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
fn derive_with_seed_compat(
    base: &Pubkey,
    seed: &[u8],
    owner: &Pubkey,
) -> Result<Pubkey, ProgramError> {
    // Enforce max seed length 32 bytes (native parity)
    if seed.len() > 32 {
        return Err(ProgramError::InvalidInstructionData);
    }

    let mut buf = [0u8; 32 + 32 + 32]; // base(32) + seed(<=32) + owner(32)
    let mut off = 0usize;

    // base
    buf[off..off + 32].copy_from_slice(&base[..]);
    off += 32;

    // seed (as provided; <= 32 bytes)
    buf[off..off + seed.len()].copy_from_slice(seed);
    off += seed.len();

    // owner
    buf[off..off + 32].copy_from_slice(&owner[..]);
    off += 32;

    // sha256(buf[..off]) -> 32 bytes
    let mut out = [0u8; 32];
    const SUCCESS: u64 = 0;
    let rc =
        unsafe { pinocchio::syscalls::sol_sha256(buf.as_ptr(), off as u64, out.as_mut_ptr()) };
    if rc != SUCCESS {
        return Err(ProgramError::InvalidInstructionData);
    }

    Ok(out)
}

/// Authorize (checked, with seed)
/// Accounts (order tolerant):
///   0. [writable] Stake account (owned by stake program)
///   [somewhere]   Clock sysvar
///   [somewhere]   Base signer (seed base)
///   [somewhere]   New authority signer (must sign)
///   [... optional signer] Custodian (required if lockup in force)
pub fn process_authorize_checked_with_seed(
    accounts: &[AccountInfo],
    args: AuthorizeCheckedWithSeedData,
) -> ProgramResult {
    if accounts.len() < 4 {
        return Err(ProgramError::NotEnoughAccountKeys);
    }

    let stake_ai = &accounts[0];

    // Native-like error split
    if *stake_ai.owner() != crate::ID {
        return Err(ProgramError::InvalidAccountOwner);
    }
    if !stake_ai.is_writable() {
        return Err(ProgramError::InvalidInstructionData);
    }

    let rest = &accounts[1..];

    // Find clock among the rest
    let clock_pos = rest
        .iter()
        .position(|ai| ai.key() == &pinocchio::sysvars::clock::CLOCK_ID)
        .ok_or(ProgramError::InvalidInstructionData)?;
    let _clock_ai = &rest[clock_pos];
    let clock = Clock::get()?; // validated by id above

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

    // Identify a *base signer* such that
    //   derive_with_seed_compat(base, seed, owner) == required old authority (by role).
    // (Allow withdrawer to rotate staker; withdrawer-only for withdrawer rotation.)
    let old_allowed: &[Pubkey] = match role {
        StakeAuthorize::Staker => &[staker_pk, withdrawer_pk],
        StakeAuthorize::Withdrawer => &[withdrawer_pk],
    };

    let mut base_ai_opt: Option<&AccountInfo> = None;
    let mut derived_old = Pubkey::default();

    for (i, ai) in rest.iter().enumerate() {
        if i == clock_pos {
            continue;
        }
        if !ai.is_signer() {
            continue;
        }
        let d = derive_with_seed_compat(ai.key(), args.authority_seed, &args.authority_owner)?;
        if old_allowed.iter().any(|k| *k == d) {
            base_ai_opt = Some(ai);
            derived_old = d;
            break;
        }
    }

    let base_ai = base_ai_opt.ok_or(ProgramError::MissingRequiredSignature)?;

    // Optional custodian among trailing accounts (must sign if lockup in force)
    let maybe_custodian = rest
        .iter()
        .find(|ai| ai.is_signer() && ai.key() == &custodian_pk);

    // The checked-with-seed variant also requires the *new* authority to sign.
    // Pick a signer that is not the base signer and not the custodian.
    let new_ai = rest
        .iter()
        .enumerate()
        .filter(|(i, ai)| *i != clock_pos && ai.is_signer())
        .map(|(_, ai)| ai)
        .find(|ai| ai.key() != base_ai.key() && Some(*ai.key()) != maybe_custodian.map(|c| *c.key()))
        .ok_or(ProgramError::MissingRequiredSignature)?;
    let new_authorized = *new_ai.key();

    // For policy helper, we present the *derived* old authority and (optionally) the custodian
    let mut signers = [Pubkey::default(); 2];
    let mut n = 0usize;
    signers[n] = derived_old;
    n += 1;
    if let Some(c) = maybe_custodian {
        signers[n] = *c.key();
        n += 1;
    }
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
