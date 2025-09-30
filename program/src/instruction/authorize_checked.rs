use pinocchio::{
    account_info::AccountInfo,
    program_error::ProgramError,
    pubkey::Pubkey,
    sysvars::clock::Clock,
    ProgramResult,
};

use crate::{
    helpers::{collect_signers, get_stake_state, set_stake_state, authorize_update, MAXIMUM_SIGNERS},
    state::{stake_state_v2::StakeStateV2, StakeAuthorize},
};

/// Authorize (checked) instruction
/// Accounts (4 + optional custodian):
///   0. [writable] Stake account (must be owned by stake program)
///   1. [sysvar]   Clock
///   2. []         Old stake/withdraw authority (presence only; no strict signer requirement here)
///   3. [signer]   New stake/withdraw authority
///   4. [optional signer] Custodian (needed only if lockup is in force)
pub fn process_authorize_checked(
    accounts: &[AccountInfo],
    authority_type: StakeAuthorize,
) -> ProgramResult {
    if accounts.len() < 3 { return Err(ProgramError::NotEnoughAccountKeys); }

    // Identify stake and clock in any order
    let mut stake_idx: Option<usize> = None;
    let mut clock_idx: Option<usize> = None;
    for (i, ai) in accounts.iter().enumerate() {
        if stake_idx.is_none() && *ai.owner() == crate::ID && ai.is_writable() { stake_idx = Some(i); }
        if clock_idx.is_none() && ai.key() == &pinocchio::sysvars::clock::CLOCK_ID { clock_idx = Some(i); }
        if stake_idx.is_some() && clock_idx.is_some() { break; }
    }
    let stake_ai = accounts.get(stake_idx.ok_or(ProgramError::InvalidAccountData)?)
        .ok_or(ProgramError::InvalidAccountData)?;
    let clock_ai = accounts.get(clock_idx.ok_or(ProgramError::InvalidInstructionData)?)
        .ok_or(ProgramError::InvalidInstructionData)?;
    if *stake_ai.owner() != crate::ID || !stake_ai.is_writable() { return Err(ProgramError::IncorrectProgramId); }
    let clock = unsafe { Clock::from_account_info_unchecked(clock_ai)? };

    // Load current state to determine required old authority and expected custodian
    let state = get_stake_state(stake_ai)?;
    let (required_old, custodian_pk) = match &state {
        StakeStateV2::Initialized(meta) => (match authority_type { StakeAuthorize::Staker => meta.authorized.staker, StakeAuthorize::Withdrawer => meta.authorized.withdrawer }, meta.lockup.custodian),
        StakeStateV2::Stake(meta, _, _) => (match authority_type { StakeAuthorize::Staker => meta.authorized.staker, StakeAuthorize::Withdrawer => meta.authorized.withdrawer }, meta.lockup.custodian),
        _ => return Err(ProgramError::InvalidAccountData),
    };

    // Find old authority account and ensure it signed
    let old_auth_ai = accounts
        .iter()
        .find(|ai| ai.key() == &required_old)
        .ok_or(ProgramError::MissingRequiredSignature)?;
    if !old_auth_ai.is_signer() { return Err(ProgramError::MissingRequiredSignature); }

    // Find new authority account: must be a signer and not the old authority, not stake, not clock
    let new_auth_ai = accounts
        .iter()
        .find(|ai| ai.is_signer()
            && ai.key() != &required_old
            && ai.key() != stake_ai.key()
            && ai.key() != &pinocchio::sysvars::clock::CLOCK_ID)
        .ok_or(ProgramError::MissingRequiredSignature)?;
    let new_authorized = *new_auth_ai.key();

    // Optional custodian (policy enforces signature only when lockup in force)
    let maybe_lockup_authority: Option<&AccountInfo> = accounts
        .iter()
        .find(|ai| ai.key() == &custodian_pk && ai.is_signer());

    // Collect transaction signers
    let mut signers_buf = [Pubkey::default(); MAXIMUM_SIGNERS];
    let n = collect_signers(accounts, &mut signers_buf)?;
    let signers = &signers_buf[..n];

    // Load -> authorize -> store
    match state {
        StakeStateV2::Initialized(mut meta) => {
            authorize_update(
                &mut meta,
                new_authorized,
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
                new_authorized,
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
