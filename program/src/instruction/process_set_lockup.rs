use pinocchio::{
    account_info::AccountInfo,
    program_error::ProgramError,
    pubkey::Pubkey,
    sysvars::{clock::Clock, Sysvar},
    ProgramResult,
};

use crate::{
    helpers::{collect_signers, next_account_info},
    helpers::utils::{get_stake_state, set_stake_state},
    helpers::constant::MAXIMUM_SIGNERS,
    state::{accounts::SetLockupData, stake_state_v2::StakeStateV2, state::Meta},
};

#[inline]
fn parse_set_lockup_bytes(data: &[u8]) -> Result<SetLockupData, ProgramError> {
    if data.is_empty() { return Err(ProgramError::InvalidInstructionData); }
    let flags = data[0];
    // Only allow bits 0x01 (ts), 0x02 (epoch), 0x04 (custodian)
    if flags & !0x07 != 0 { return Err(ProgramError::InvalidInstructionData); }
    let mut off = 1usize;

    let unix_timestamp = if (flags & 0x01) != 0 {
        if off + 8 > data.len() { return Err(ProgramError::InvalidInstructionData); }
        let mut buf = [0u8; 8];
        buf.copy_from_slice(&data[off..off + 8]);
        off += 8;
        Some(i64::from_le_bytes(buf))
    } else { None };

    let epoch = if (flags & 0x02) != 0 {
        if off + 8 > data.len() { return Err(ProgramError::InvalidInstructionData); }
        let mut buf = [0u8; 8];
        buf.copy_from_slice(&data[off..off + 8]);
        off += 8;
        Some(u64::from_le_bytes(buf))
    } else { None };

    let custodian = if (flags & 0x04) != 0 {
        if off + 32 > data.len() { return Err(ProgramError::InvalidInstructionData); }
        let mut pk = [0u8; 32];
        pk.copy_from_slice(&data[off..off + 32]);
        off += 32;
        Some(pk)
    } else { None };

    // Reject trailing bytes to ensure unambiguous encoding
    if off != data.len() { return Err(ProgramError::InvalidInstructionData); }

    Ok(SetLockupData { unix_timestamp, epoch, custodian })
}

pub fn process_set_lockup(accounts: &[AccountInfo], instruction_data: &[u8]) -> ProgramResult {
    // Iterate accounts: first is stake; additional accounts may be supplied
    let account_info_iter = &mut accounts.iter();
    let stake_account_info = next_account_info(account_info_iter)?;
    // Additional accounts are considered for signer collection

    // Parse payload into optional fields (wire-safe flags+payloads)
    let args = parse_set_lockup_bytes(instruction_data)?;

    // Read the clock sysvar directly (no clock account is required)
    let clock = Clock::get()?;

    // Collect all signers from all provided accounts
    let mut signer_buf = [Pubkey::default(); MAXIMUM_SIGNERS];
    let n = collect_signers(accounts, &mut signer_buf)?;
    let signers = &signer_buf[..n];

    // Owner and size checks are performed by get_stake_state(); writable is enforced by set_stake_state
    match get_stake_state(stake_account_info)? {
        StakeStateV2::Initialized(mut meta) => {
            apply_lockup_update(&mut meta, &args, &clock, signers)?;
            set_stake_state(stake_account_info, &StakeStateV2::Initialized(meta))
        }
        StakeStateV2::Stake(mut meta, stake, stake_flags) => {
            apply_lockup_update(&mut meta, &args, &clock, signers)?;
            set_stake_state(
                stake_account_info,
                &StakeStateV2::Stake(meta, stake, stake_flags),
            )
        }
        _ => Err(ProgramError::InvalidAccountData),
    }
}

// Bincode-decoded variant: accept parsed LockupArgs directly (native parity)
pub fn process_set_lockup_parsed(
    accounts: &[AccountInfo],
    lockup: crate::state::accounts::SetLockupData, // we will translate to Meta updates
) -> ProgramResult {
    // Iterate accounts: first is stake
    let account_info_iter = &mut accounts.iter();
    let stake_account_info = next_account_info(account_info_iter)?;

    // Read the clock sysvar directly (no clock account required)
    let clock = Clock::get()?;

    // Collect signers
    let mut signer_buf = [Pubkey::default(); MAXIMUM_SIGNERS];
    let n = collect_signers(accounts, &mut signer_buf)?;
    let signers = &signer_buf[..n];

    match get_stake_state(stake_account_info)? {
        StakeStateV2::Initialized(mut meta) => {
            apply_lockup_update(&mut meta, &lockup, &clock, signers)?;
            set_stake_state(stake_account_info, &StakeStateV2::Initialized(meta))
        }
        StakeStateV2::Stake(mut meta, stake, stake_flags) => {
            apply_lockup_update(&mut meta, &lockup, &clock, signers)?;
            set_stake_state(
                stake_account_info,
                &StakeStateV2::Stake(meta, stake, stake_flags),
            )
        }
        _ => Err(ProgramError::InvalidAccountData),
    }
}

/// Lockup gating in `Meta::set_lockup`:
/// - If lockup is in force → current custodian must have signed
/// - Else → current withdraw authority must have signed
/// Then apply any provided fields as-is.
pub fn apply_lockup_update(
    meta: &mut Meta,
    args: &SetLockupData,
    clock: &Clock,
    signers: &[Pubkey],
) -> ProgramResult {
    let signed = |pk: &Pubkey| signers.iter().any(|s| s == pk);

    // Lockup in force? (pass None to disallow custodian bypass)
    let in_force = meta.lockup.is_in_force(clock, None);

    if in_force {
        if !signed(&meta.lockup.custodian) {
            return Err(ProgramError::MissingRequiredSignature);
        }
    } else if !signed(&meta.authorized.withdrawer) {
        return Err(ProgramError::MissingRequiredSignature);
    }

    // Apply optional fields (no monotonicity check)
    if let Some(ts) = args.unix_timestamp {
        meta.lockup.unix_timestamp = ts;
    }
    if let Some(ep) = args.epoch {
        meta.lockup.epoch = ep;
    }
    if let Some(cust) = args.custodian {
        meta.lockup.custodian = cust;
    }

    Ok(())
}
