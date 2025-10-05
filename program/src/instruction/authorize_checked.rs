use pinocchio::{
    account_info::AccountInfo,
    program_error::ProgramError,
    pubkey::Pubkey,
    sysvars::{clock::Clock, Sysvar},
    ProgramResult,
};

use crate::{
    helpers::{authorize_update, get_stake_state, set_stake_state},
    state::{stake_state_v2::StakeStateV2, StakeAuthorize},
};

/// Authorize (checked)
/// Accounts (native-compatible, tolerant order):
///   0. [writable] Stake account (owned by stake program)
///   [somewhere]   Clock sysvar
///   [somewhere]   Old authority signer for `authority_type`
///   [somewhere]   New authority signer (to set)
///   [... optional signer] Custodian (required if lockup in force)
pub fn process_authorize_checked(
    accounts: &[AccountInfo],
    authority_type: StakeAuthorize,
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

    // Locate clock in remaining accounts (order tolerant)
    let rest = &accounts[1..];
    let clock_pos = rest
        .iter()
        .position(|ai| ai.key() == &pinocchio::sysvars::clock::CLOCK_ID)
        .ok_or(ProgramError::InvalidInstructionData)?;
    let _clock_ai = &rest[clock_pos]; // presence validated by id
    let clock = Clock::get()?;

    // Load state and resolve current authorities and custodian
    let state = get_stake_state(stake_ai)?;
    let (staker_pk, withdrawer_pk, custodian_pk) = match &state {
        StakeStateV2::Initialized(meta) => (
            meta.authorized.staker,
            meta.authorized.withdrawer,
            meta.lockup.custodian,
        ),
        StakeStateV2::Stake(meta, _, _) => (
            meta.authorized.staker,
            meta.authorized.withdrawer,
            meta.lockup.custodian,
        ),
        _ => return Err(ProgramError::InvalidAccountData),
    };

    // Identify old-authority signer and new-authority signer (order tolerant)
    let mut old_ai_opt: Option<&AccountInfo> = None;
    let mut new_ai_opt: Option<&AccountInfo> = None;

    for (i, ai) in rest.iter().enumerate() {
        if i == clock_pos {
            continue;
        }
        if !ai.is_signer() {
            continue;
        }

        // Old authority allowed set per native rules:
        // - Staker role: old may be staker OR withdrawer
        // - Withdrawer role: old must be withdrawer
        let k = ai.key();
        let is_valid_old = match authority_type {
            StakeAuthorize::Staker => k == &staker_pk || k == &withdrawer_pk,
            StakeAuthorize::Withdrawer => k == &withdrawer_pk,
        };

        if is_valid_old && old_ai_opt.is_none() {
            old_ai_opt = Some(ai);
            continue;
        }

        // New authority must be a signer and may not be the (optional) custodian
        if new_ai_opt.is_none() && ai.key() != &custodian_pk {
            new_ai_opt = Some(ai);
            continue;
        }

        if old_ai_opt.is_some() && new_ai_opt.is_some() {
            break;
        }
    }

    let old_ai = old_ai_opt.ok_or(ProgramError::MissingRequiredSignature)?;
    let new_ai = new_ai_opt.ok_or(ProgramError::MissingRequiredSignature)?;
    let new_authorized = *new_ai.key();
    if old_ai.is_signer() {
        pinocchio::msg!("authc:old_is_signer=1");
    } else {
        pinocchio::msg!("authc:old_is_signer=0");
        return Err(ProgramError::MissingRequiredSignature);
    }
    if !new_ai.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }

    // Optional custodian among trailing accounts (must sign if required by lockup)
    let maybe_custodian = accounts[1..]
        .iter()
        .find(|ai| ai.is_signer() && ai.key() == &custodian_pk);

    // Restrict authorities to [old, (custodian?)]
    let mut signers = [Pubkey::default(); 2];
    let mut n = 0usize;
    signers[n] = *old_ai.key();
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
                authority_type,
                signers,
                maybe_custodian,
                &clock,
            )?;
            set_stake_state(stake_ai, &StakeStateV2::Initialized(meta))?;
        }
        StakeStateV2::Stake(mut meta, stake, flags) => {
            authorize_update(
                &mut meta,
                new_authorized,
                authority_type,
                signers,
                maybe_custodian,
                &clock,
            )?;
            set_stake_state(stake_ai, &StakeStateV2::Stake(meta, stake, flags))?;
        }
        _ => return Err(ProgramError::InvalidAccountData),
    }

    Ok(())
}
