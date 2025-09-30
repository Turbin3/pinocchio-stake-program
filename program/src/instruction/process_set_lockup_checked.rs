#![allow(clippy::result_large_err)]

use pinocchio::{
    account_info::AccountInfo,
    program_error::ProgramError,
    pubkey::Pubkey,
    sysvars::{clock::Clock, Sysvar},
    ProgramResult,
};

use crate::{
    helpers::{collect_signers, get_stake_state, set_stake_state, MAXIMUM_SIGNERS},
    state::{stake_state_v2::StakeStateV2, state::Meta},
};


pub struct LockupCheckedData {
    pub unix_timestamp: Option<i64>,
    pub epoch: Option<u64>,
}

impl LockupCheckedData {
    #[allow(unused_assignments)]
    fn parse(data: &[u8]) -> Result<Self, ProgramError> {
        if data.is_empty() {
            return Err(ProgramError::InvalidInstructionData);
        }
        let flags = data[0];
        let mut off = 1usize;

        let unix_timestamp = if (flags & 0x01) != 0 {
            if off + 8 > data.len() {
                return Err(ProgramError::InvalidInstructionData);
            }
            let mut buf = [0u8; 8];
            buf.copy_from_slice(&data[off..off + 8]);
            off += 8;
            Some(i64::from_le_bytes(buf))
        } else {
            None
        };

        let epoch = if (flags & 0x02) != 0 {
            if off + 8 > data.len() {
                return Err(ProgramError::InvalidInstructionData);
            }
            let mut buf = [0u8; 8];
            buf.copy_from_slice(&data[off..off + 8]);
            off += 8;
            Some(u64::from_le_bytes(buf))
        } else {
            None
        };

        Ok(Self { unix_timestamp, epoch })
    }
}


pub fn process_set_lockup_checked(
    accounts: &[AccountInfo],
    instruction_data: &[u8],
) -> ProgramResult {
    if accounts.is_empty() {
        return Err(ProgramError::NotEnoughAccountKeys);
    }

    // stake, [old_auth?], [new_lockup_auth?], ...
    let stake_ai = &accounts[0];

    // Parse the payload
    let checked = LockupCheckedData::parse(instruction_data)?;

    // Collect all signers
    let mut signer_buf = [Pubkey::default(); MAXIMUM_SIGNERS];
    let n = collect_signers(accounts, &mut signer_buf)?;
    let signers = &signer_buf[..n];

    // Optional new custodian comes from account #2 and must be a signer if present
    let custodian_update: Option<Pubkey> = match accounts.get(2) {
        Some(ai) if ai.is_signer() => Some(*ai.key()),
        Some(_ai) => return Err(ProgramError::MissingRequiredSignature),
        None => None, // no custodian change
    };

    // Use Clock::get() (no clock account is required)
    let clock = Clock::get()?;

    // Owner check happens in get_stake_state()
    match get_stake_state(stake_ai)? {
        StakeStateV2::Initialized(mut meta) => {
            apply_set_lockup_policy(
                &mut meta,
                checked.unix_timestamp,
                checked.epoch,
                custodian_update,
                signers,
                &clock,
            )?;
            set_stake_state(stake_ai, &StakeStateV2::Initialized(meta))?;
        }
        StakeStateV2::Stake(mut meta, stake, flags) => {
            apply_set_lockup_policy(
                &mut meta,
                checked.unix_timestamp,
                checked.epoch,
                custodian_update,
                signers,
                &clock,
            )?;
            set_stake_state(stake_ai, &StakeStateV2::Stake(meta, stake, flags))?;
        }
        _ => return Err(ProgramError::InvalidAccountData),
    }

    Ok(())
}


fn apply_set_lockup_policy(
    meta: &mut Meta,
    unix_ts: Option<i64>,
    epoch: Option<u64>,
    custodian_update: Option<Pubkey>,
    signers: &[Pubkey],
    clock: &Clock,
) -> Result<(), ProgramError> {
    let is_signed = |who: &Pubkey| signers.iter().any(|s| s == who);

    // Gate by current lockup status
    if meta.lockup.is_in_force(clock, None) {
        // Lockup currently in force => custodian must sign
        if !is_signed(&meta.lockup.custodian) {
            return Err(ProgramError::MissingRequiredSignature);
        }
    } else {
        // Lockup not in force => withdrawer must sign
        if !is_signed(&meta.authorized.withdrawer) {
            return Err(ProgramError::MissingRequiredSignature);
        }
    }

    // Apply updates
    if let Some(ts) = unix_ts {
        meta.lockup.unix_timestamp = ts;
    }
    if let Some(ep) = epoch {
        meta.lockup.epoch = ep;
    }
    if let Some(new_custodian) = custodian_update {
        meta.lockup.custodian = new_custodian;
    }

    Ok(())
}
