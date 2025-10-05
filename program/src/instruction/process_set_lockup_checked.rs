#![allow(clippy::result_large_err)]

use pinocchio::{
    account_info::AccountInfo,
    program_error::ProgramError,
    pubkey::Pubkey,
    sysvars::{clock::Clock, Sysvar},
    ProgramResult,
};

use crate::{
    helpers::{get_stake_state, set_stake_state},
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
        if flags & !0x03 != 0 {
            return Err(ProgramError::InvalidInstructionData);
        }
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

        if off != data.len() {
            return Err(ProgramError::InvalidInstructionData);
        }

        Ok(Self { unix_timestamp, epoch })
    }
}

pub fn process_set_lockup_checked(
    accounts: &[AccountInfo],
    instruction_data: &[u8],
) -> ProgramResult {
    pinocchio::msg!("slc:enter");
    if accounts.is_empty() {
        return Err(ProgramError::NotEnoughAccountKeys);
    }
    let stake_ai = &accounts[0];

    if *stake_ai.owner() != crate::ID {
        return Err(ProgramError::InvalidAccountOwner);
    }
    if !stake_ai.is_writable() {
        pinocchio::msg!("slc:not_writable");
        return Err(ProgramError::InvalidInstructionData);
    }

    let checked = LockupCheckedData::parse(instruction_data)?;
    pinocchio::msg!("slc:parsed");
    let rest = &accounts[1..];

    let clock = Clock::get()?;

    let state = get_stake_state(stake_ai)?;
    let (withdrawer_pk, custodian_pk, in_force) = match &state {
        StakeStateV2::Initialized(meta) | StakeStateV2::Stake(meta, _, _) => (
            meta.authorized.withdrawer,
            meta.lockup.custodian,
            meta.lockup.is_in_force(&clock, None),
        ),
        _ => return Err(ProgramError::InvalidAccountData),
    };

    let required_pk = if in_force { custodian_pk } else { withdrawer_pk };
    let authority_ai = rest
        .iter()
        .find(|ai| ai.is_signer() && ai.key() == &required_pk)
        .ok_or(ProgramError::MissingRequiredSignature)?;

    let maybe_new_custodian: Option<Pubkey> = if accounts.len() >= 3 {
        let ai = &accounts[2];
        if !ai.is_signer() {
            return Err(ProgramError::MissingRequiredSignature);
        }
        Some(*ai.key())
    } else {
        None
    };

    match state {
        StakeStateV2::Initialized(mut meta) => {
            apply_set_lockup_policy_checked(
                &mut meta,
                checked.unix_timestamp,
                checked.epoch,
                maybe_new_custodian.as_ref(),
                authority_ai,
                &clock,
            )?;
            set_stake_state(stake_ai, &StakeStateV2::Initialized(meta))?;
        }
        StakeStateV2::Stake(mut meta, stake, flags) => {
            apply_set_lockup_policy_checked(
                &mut meta,
                checked.unix_timestamp,
                checked.epoch,
                maybe_new_custodian.as_ref(),
                authority_ai,
                &clock,
            )?;
            set_stake_state(stake_ai, &StakeStateV2::Stake(meta, stake, flags))?;
        }
        _ => return Err(ProgramError::InvalidAccountData),
    }

    Ok(())
}

fn apply_set_lockup_policy_checked(
    meta: &mut Meta,
    unix_ts: Option<i64>,
    epoch: Option<u64>,
    new_custodian: Option<&Pubkey>,
    signer_ai: &AccountInfo,
    clock: &Clock,
) -> Result<(), ProgramError> {
    let in_force = meta.lockup.is_in_force(clock, None);
    let required = if in_force {
        meta.lockup.custodian
    } else {
        meta.authorized.withdrawer
    };

    if !signer_ai.is_signer() || *signer_ai.key() != required {
        return Err(ProgramError::MissingRequiredSignature);
    }

    if let Some(ts) = unix_ts {
        meta.lockup.unix_timestamp = ts;
    }
    if let Some(ep) = epoch {
        meta.lockup.epoch = ep;
    }
    if !in_force {
        if let Some(cust) = new_custodian {
            meta.lockup.custodian = *cust;
        }
    }
    Ok(())
}
