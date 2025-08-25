
extern crate alloc;
use alloc::collections::BTreeSet;

use pinocchio::{
    account_info::AccountInfo,
    sysvars::{clock::Clock, Sysvar},
    msg,
    program_error::ProgramError,
    pubkey::Pubkey,
};
use pinocchio::ProgramResult;
use crate::state::stake_state_v2::StakeStateV2;
use crate::state::{Authorized, Meta, StakeAuthorize};
use crate::state::stake_flag::StakeFlags;
use crate::state::delegation::Stake as DelegationStake;
use crate::id;
// ============== LOCAL DEFINITIONS ==============

#[derive(Clone, Debug)]
pub enum MergeKind {
    FullyActive(Meta, DelegationStake),
    Inactive(Meta, u64, StakeFlags),
    ActivationEpoch(Meta, StakeFlags, StakeFlags),
    Other,
}

impl MergeKind {
    pub fn get_if_mergeable(
        stake_state: &StakeStateV2,
        lamports: u64,
        _clock: &Clock,
        _stake_history: &StakeHistorySysvar,
    ) -> Result<Self, ProgramError> {
        match stake_state {
            StakeStateV2::Stake(meta, stake, flags) => {
                
                if u64::from_le_bytes(stake.delegation.deactivation_epoch) == u64::MAX {
                    Ok(MergeKind::FullyActive(meta.clone(), stake.clone()))
                } else {
                    Ok(MergeKind::Inactive(meta.clone(), lamports, flags.clone()))
                }
            }
            _ => Err(ProgramError::InvalidAccountData),
        }
    }

    pub fn meta(&self) -> &Meta {
        match self {
            MergeKind::FullyActive(meta, _) => meta,
            MergeKind::Inactive(meta, _, _) => meta,
            MergeKind::ActivationEpoch(meta, _, _) => meta,
            _ => panic!("No meta"),
        }
    }

    pub fn metas_can_merge(
        source_meta: &Meta,
        dest_meta: &Meta,
        _clock: &Clock,
    ) -> Result<(), ProgramError> {
        if source_meta.authorized.staker == dest_meta.authorized.staker {
            Ok(())
        } else {
            Err(ProgramError::InvalidArgument)
        }
    }
}

pub struct StakeHistorySysvar(pub u64);

// ============== MAIN FUNCTIONS ==============

pub fn process_move_lamports(accounts: &[AccountInfo], lamports: u64) -> ProgramResult {
    msg!("Instruction: MoveLamports");

    let mut iter = accounts.iter();
    let source_stake_ai = iter.next().ok_or(ProgramError::NotEnoughAccountKeys)?;
    let destination_stake_ai = iter.next().ok_or(ProgramError::NotEnoughAccountKeys)?;
    let stake_authority_ai = iter.next().ok_or(ProgramError::NotEnoughAccountKeys)?;

    let (source_merge_kind, _) = move_stake_or_lamports_shared_checks(
        source_stake_ai,
        lamports,
        destination_stake_ai,
        stake_authority_ai,
    )?;

    let source_free_lamports = match source_merge_kind {
        MergeKind::FullyActive(source_meta, source_stake) => {
            // Convert [u8; 8] fields to u64
            let rent_reserve = u64::from_le_bytes(source_meta.rent_exempt_reserve);
            let stake_amount = u64::from_le_bytes(source_stake.delegation.stake);
            
            source_stake_ai
                .lamports()
                .saturating_sub(stake_amount)
                .saturating_sub(rent_reserve)
        }
        MergeKind::Inactive(source_meta, source_lamports, _) => {
            // Convert [u8; 8] to u64
            let rent_reserve = u64::from_le_bytes(source_meta.rent_exempt_reserve);
            source_lamports.saturating_sub(rent_reserve)
        }
        _ => return Err(ProgramError::InvalidAccountData),
    };

    if lamports > source_free_lamports {
        return Err(ProgramError::InvalidArgument);
    }

    relocate_lamports(source_stake_ai, destination_stake_ai, lamports)
}

fn move_stake_or_lamports_shared_checks(
    source_stake_ai: &AccountInfo,
    lamports: u64,
    destination_stake_ai: &AccountInfo,
    stake_authority_ai: &AccountInfo,
) -> Result<(MergeKind, MergeKind), ProgramError> {
    let (signers, _) = collect_signers_checked(Some(stake_authority_ai), None)?;

    if source_stake_ai.key() == destination_stake_ai.key() {
        return Err(ProgramError::InvalidInstructionData);
    }

    if !source_stake_ai.is_writable() || !destination_stake_ai.is_writable() {
        return Err(ProgramError::InvalidInstructionData);
    }

    if lamports == 0 {
        return Err(ProgramError::InvalidArgument);
    }

    let clock = Clock::get()?;
    let stake_history = StakeHistorySysvar(clock.epoch);

    let source_merge_kind = MergeKind::get_if_mergeable(
        &get_stake_state(source_stake_ai)?,
        source_stake_ai.lamports(),
        &clock,
        &stake_history,
    )?;

    check_authorized(
        &source_merge_kind.meta().authorized,
        &signers,
        StakeAuthorize::Staker
    )?;

    let destination_merge_kind = MergeKind::get_if_mergeable(
        &get_stake_state(destination_stake_ai)?,
        destination_stake_ai.lamports(),
        &clock,
        &stake_history,
    )?;

    MergeKind::metas_can_merge(
        source_merge_kind.meta(),
        destination_merge_kind.meta(),
        &clock,
    )?;

    Ok((source_merge_kind, destination_merge_kind))
}

fn check_authorized(
    authorized: &Authorized,
    signers: &BTreeSet<Pubkey>,
    stake_authorize: StakeAuthorize,
) -> Result<(), ProgramError> {
    let authorized_pubkey = match stake_authorize {
        StakeAuthorize::Staker => &authorized.staker,
        StakeAuthorize::Withdrawer => &authorized.withdrawer,
    };
    
    if signers.contains(authorized_pubkey) {
        Ok(())
    } else {
        Err(ProgramError::MissingRequiredSignature)
    }
}

// ============== HELPER FUNCTIONS ==============
#[inline]
fn checked_move_lamports(from: &mut u64, to: &mut u64, amount: u64) -> ProgramResult {
    *from = from
        .checked_sub(amount)
        .ok_or(ProgramError::InsufficientFunds)?;
    *to = to
        .checked_add(amount)
        .ok_or(ProgramError::ArithmeticOverflow)?;
    Ok(())
}
fn collect_signers_checked<'a>(
    authority_info: Option<&'a AccountInfo>,
    custodian_info: Option<&'a AccountInfo>,
) -> Result<(BTreeSet<Pubkey>, Option<&'a Pubkey>), ProgramError> {
    let mut signers = BTreeSet::new();

    if let Some(ai) = authority_info {
        if ai.is_signer() {
            signers.insert(*ai.key());
        } else {
            return Err(ProgramError::MissingRequiredSignature);
        }
    }

    let custodian = if let Some(ci) = custodian_info {
        if ci.is_signer() {
            signers.insert(*ci.key());
            Some(ci.key())
        } else {
            return Err(ProgramError::MissingRequiredSignature);
        }
    } else {
        None
    };

    Ok((signers, custodian))
}

fn get_stake_state(stake_ai: &AccountInfo) -> Result<StakeStateV2, ProgramError> {
    if stake_ai.owner() != &id() {
        return Err(ProgramError::InvalidAccountOwner);
    }
    let data = stake_ai.try_borrow_data()?;
    StakeStateV2::deserialize(&data)
}

fn relocate_lamports(
    source_ai: &AccountInfo,
    destination_ai: &AccountInfo,
    lamports: u64,
) -> ProgramResult {
    let mut from_lamports = source_ai.try_borrow_mut_lamports()?;
    let mut to_lamports   = destination_ai.try_borrow_mut_lamports()?;

    checked_move_lamports(&mut *from_lamports, &mut *to_lamports, lamports)
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checked_move_lamports_ok() {
        let mut from = 1_000u64;
        let mut to   =   100u64;
        checked_move_lamports(&mut from, &mut to, 250).unwrap();
        assert_eq!(from, 750);
        assert_eq!(to,   350);
    }

    #[test]
    fn checked_move_lamports_underflow() {
        let mut from = 100u64;
        let mut to   =  50u64;
        let err = checked_move_lamports(&mut from, &mut to, 250).unwrap_err();
        assert_eq!(err, ProgramError::InsufficientFunds);
    }

    #[test]
    fn checked_move_lamports_overflow() {
        let mut from = u64::MAX;
        let mut to   = u64::MAX - 10;
        let err = checked_move_lamports(&mut from, &mut to, 20).unwrap_err();
        assert_eq!(err, ProgramError::ArithmeticOverflow);
    }
}