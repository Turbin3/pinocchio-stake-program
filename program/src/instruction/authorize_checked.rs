use pinocchio::{
    account_info::AccountInfo,
    program_error::ProgramError,
    pubkey::Pubkey,
    sysvars::{clock::Clock, Sysvar},
    ProgramResult,
};

use crate::{
    helpers::{collect_signers, get_stake_state, set_stake_state, authorize_update, MAXIMUM_SIGNERS},
    state::{stake_state_v2::StakeStateV2, StakeAuthorize},
};

/// Authorize (checked) instruction
/// Accounts (3 + optional custodian + optional extras):
///   0. [writable] Stake account (owned by stake program)
///   1. [signer]   Old stake/withdraw authority
///   2. [signer]   New stake/withdraw authority
///   3. [optional signer] Custodian (if lockup in force)
///   (Clock is obtained via sysvar syscall; no explicit clock account required.)
pub fn process_authorize_checked(
    accounts: &[AccountInfo],
    authority_type: StakeAuthorize,
) -> ProgramResult {
    if accounts.len() < 3 { return Err(ProgramError::NotEnoughAccountKeys); }

    // Stake must be first; other accounts may be in varying order per SDK.
    let stake_ai = &accounts[0];
    if *stake_ai.owner() != crate::ID || !stake_ai.is_writable() {
        return Err(ProgramError::IncorrectProgramId);
    }
    // Load current state to determine required old authority and expected custodian
    let state = get_stake_state(stake_ai)?;
    let (required_old, custodian_pk) = match &state {
        StakeStateV2::Initialized(meta) => (match authority_type { StakeAuthorize::Staker => meta.authorized.staker, StakeAuthorize::Withdrawer => meta.authorized.withdrawer }, meta.lockup.custodian),
        StakeStateV2::Stake(meta, _, _) => (match authority_type { StakeAuthorize::Staker => meta.authorized.staker, StakeAuthorize::Withdrawer => meta.authorized.withdrawer }, meta.lockup.custodian),
        _ => return Err(ProgramError::InvalidAccountData),
    };

    // Identify signers among the remaining accounts
    let rest = &accounts[1..];
    let old_auth_ai = rest
        .iter()
        .find(|ai| ai.is_signer() && ai.key() == &required_old)
        .ok_or(ProgramError::MissingRequiredSignature)?;
    let new_auth_ai = rest
        .iter()
        .find(|ai| ai.is_signer()
            && ai.key() != &required_old
            && ai.key() != stake_ai.key()
            && ai.key() != &pinocchio::sysvars::clock::CLOCK_ID)
        .ok_or(ProgramError::MissingRequiredSignature)?;
    // Fetch clock via sysvar call
    let clock = Clock::get()?;

    // Load current state to determine required old authority and expected custodian
    // Old authority must match state; new must differ from old and stake
    if old_auth_ai.key() != &required_old { return Err(ProgramError::InvalidInstructionData); }
    if new_auth_ai.key() == old_auth_ai.key() || new_auth_ai.key() == stake_ai.key() { return Err(ProgramError::InvalidInstructionData); }
    let new_authorized = *new_auth_ai.key();

    // Optional custodian (policy enforces signature only when lockup in force)
    let maybe_lockup_authority: Option<&AccountInfo> = rest
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
