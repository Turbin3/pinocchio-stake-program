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
    if accounts.len() < 4 { return Err(ProgramError::NotEnoughAccountKeys); }

    let stake_ai = &accounts[0];
    if *stake_ai.owner() != crate::ID { return Err(ProgramError::InvalidAccountOwner); }
    if !stake_ai.is_writable() { return Err(ProgramError::InvalidInstructionData); }

    let rest = &accounts[1..];
    // Require that a Clock sysvar meta is present (native wire expectation),
    // while still reading via sysvar for Pinocchio safety.
    let has_clock_meta = rest.iter().any(|ai| ai.key() == &pinocchio::sysvars::clock::CLOCK_ID);
    if !has_clock_meta {
        return Err(ProgramError::InvalidInstructionData);
    }
    let clock = Clock::get()?;

    // Load state
    let state = get_stake_state(stake_ai)?;
    let (staker_pk, withdrawer_pk, custodian_pk) = match &state {
        StakeStateV2::Initialized(meta) | StakeStateV2::Stake(meta, _, _) => (
            meta.authorized.staker,
            meta.authorized.withdrawer,
            meta.lockup.custodian,
        ),
        _ => return Err(ProgramError::InvalidAccountData),
    };

    // Identify old authority by key + signer
    let old_is_allowed = |k: &Pubkey| match authority_type {
        StakeAuthorize::Staker => *k == staker_pk || *k == withdrawer_pk,
        StakeAuthorize::Withdrawer => *k == withdrawer_pk,
    };
    match authority_type {
        StakeAuthorize::Staker => pinocchio::msg!("ac:role=staker"),
        StakeAuthorize::Withdrawer => pinocchio::msg!("ac:role=withdrawer"),
    }
    let old_ai = match rest.iter().find(|ai| ai.is_signer() && old_is_allowed(ai.key())) {
        Some(ai) => { pinocchio::msg!("ac:old=1"); ai }
        None => { pinocchio::msg!("ac:old=0"); return Err(ProgramError::MissingRequiredSignature); }
    };

    // If lockup in force, custodian must sign; otherwise optional
    let in_force = match &state {
        StakeStateV2::Initialized(meta) | StakeStateV2::Stake(meta, _, _) => meta.lockup.is_in_force(&clock, None),
        _ => false,
    };
    let maybe_custodian = rest
        .iter()
        .find(|ai| ai.is_signer() && ai.key() == &custodian_pk);
    // Native: custodian only required when changing withdrawer and lockup is in force
    if matches!(authority_type, StakeAuthorize::Withdrawer) && in_force && maybe_custodian.is_none() {
        pinocchio::msg!("ac:need_cust");
        return Err(ProgramError::MissingRequiredSignature);
    }

    // Determine new_authorized from metas by position/content and require it be a signer (native)
    let mut new_ai_opt: Option<&AccountInfo> = None;
    for ai in rest.iter() {
        let k = ai.key();
        if k == &pinocchio::sysvars::clock::CLOCK_ID || k == stake_ai.key() || maybe_custodian.map_or(false, |c| k == c.key()) || k == old_ai.key() {
            continue;
        }
        new_ai_opt = Some(ai);
        break;
    }
    let new_ai = new_ai_opt.ok_or(ProgramError::InvalidInstructionData)?;
    if !new_ai.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }
    let new_authorized = *new_ai.key();

    // Restrict authorities to [old, (custodian?)]
    let mut signers = [Pubkey::default(); 2];
    let mut n = 0usize;
    signers[n] = *old_ai.key();
    n += 1;
    if let Some(c) = maybe_custodian { signers[n] = *c.key(); n += 1; }
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
