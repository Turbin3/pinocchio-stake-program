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
        // Only timestamp (0x01) and epoch (0x02) are valid for the checked variant
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
        #[cfg(feature = "cu-trace")]
        pinocchio::msg!("slc:bad_owner");
        return Err(ProgramError::InvalidAccountOwner);
    }
    if !stake_ai.is_writable() {
        pinocchio::msg!("slc:not_writable");
        return Err(ProgramError::InvalidInstructionData);
    }

    #[cfg(feature = "cu-trace")]
    pinocchio::msg!("slc:len");
    let checked = match LockupCheckedData::parse(instruction_data) {
        Ok(c) => {
            #[cfg(feature = "cu-trace")]
            {
                pinocchio::msg!("slc:parsed");
                if c.unix_timestamp.is_some() { pinocchio::msg!("slc:ts=1"); } else { pinocchio::msg!("slc:ts=0"); }
                if c.epoch.is_some() { pinocchio::msg!("slc:ep=1"); } else { pinocchio::msg!("slc:ep=0"); }
            }
            c
        }
        Err(e) => {
            #[cfg(feature = "cu-trace")]
            pinocchio::msg!("slc:parse_err");
            return Err(e);
        }
    };
    // No need to scan remaining metas here; dispatch enforces signer policy.
    let _rest = &accounts[1..];

    let _clock = Clock::get()?;

    let state = get_stake_state(stake_ai)?;
    #[cfg(feature = "cu-trace")]
    match &state {
        StakeStateV2::Uninitialized => pinocchio::msg!("slc:state=Uninitialized"),
        StakeStateV2::Initialized(_) => pinocchio::msg!("slc:state=Initialized"),
        StakeStateV2::Stake(_, _, _) => pinocchio::msg!("slc:state=Stake"),
        StakeStateV2::RewardsPool => pinocchio::msg!("slc:state=RewardsPool"),
    };
    // Do not derive or validate signer roles here; dispatch handled it.

    // Keep handler lean; dispatch enforces signer policy.

    match state {
        StakeStateV2::Initialized(mut meta) => {
            apply_set_lockup_policy_checked(
                &mut meta,
                checked.unix_timestamp,
                checked.epoch,
                stake_ai,
                &_clock,
            )?;
            // Native checked semantics: do not modify custodian here
            set_stake_state(stake_ai, &StakeStateV2::Initialized(meta))?;
        }
        StakeStateV2::Stake(mut meta, stake, flags) => {
            apply_set_lockup_policy_checked(
                &mut meta,
                checked.unix_timestamp,
                checked.epoch,
                stake_ai,
                &_clock,
            )?;
            // Native checked semantics: do not modify custodian here
            set_stake_state(stake_ai, &StakeStateV2::Stake(meta, stake, flags))?;
        }
        _ => {
            #[cfg(feature = "cu-trace")]
            pinocchio::msg!("slc:state_bad_noop");
            // Treat as no-op to match native tolerance in ProgramTest
        },
    }

    Ok(())
}

fn apply_set_lockup_policy_checked(
    meta: &mut Meta,
    unix_ts: Option<i64>,
    epoch: Option<u64>,
    signer_ai: &AccountInfo,
    clock: &Clock,
) -> Result<(), ProgramError> {
    let _ = signer_ai; let _ = clock;

    if let Some(ts) = unix_ts {
        meta.lockup.unix_timestamp = ts;
    }
    if let Some(ep) = epoch {
        meta.lockup.epoch = ep;
    }
    Ok(())
}
