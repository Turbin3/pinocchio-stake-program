
extern crate alloc;

use pinocchio::{account_info::AccountInfo, program_error::ProgramError, ProgramResult};
use crate::helpers::relocate_lamports;
use crate::helpers::merge::move_stake_or_lamports_shared_checks;
use crate::state::merge_kind::MergeKind;

/// Move withdrawable lamports from one stake account to another.
///
/// Accounts (exactly 3):
/// 0. `[writable]` Source stake account (owned by this program)
/// 1. `[writable]` Destination stake account (owned by this program)
/// 2. `[signer]`   Staker authority (must be the *staker* of the source)
pub fn process_move_lamports(accounts: &[AccountInfo], lamports: u64) -> ProgramResult {
    // Canonical SDK order: [source_stake, destination_stake, staker]; enforce exactly 3
    if accounts.len() != 3 {
        return Err(ProgramError::InvalidInstructionData);
    }
    let [source_stake_ai, destination_stake_ai, staker_authority_ai] = accounts else {
        return Err(ProgramError::InvalidInstructionData);
    };
    // Resolve the expected staker key from source meta and ensure the 3rd account is that signer
    let src_state = crate::helpers::get_stake_state(source_stake_ai)?;
    let expected_staker = match src_state {
        crate::state::stake_state_v2::StakeStateV2::Initialized(meta)
        | crate::state::stake_state_v2::StakeStateV2::Stake(meta, _, _) => meta.authorized.staker,
        _ => return Err(ProgramError::InvalidAccountData),
    };
    if !staker_authority_ai.is_signer() || staker_authority_ai.key() != &expected_staker {
        return Err(ProgramError::MissingRequiredSignature);
    }

    // Always perform checks via shared helper; reject transient shapes.

    // Shared checks (signer present, accounts distinct and writable, nonzero amount,
    // classification via MergeKind, and metadata compatibility)
    let (source_kind, dest_kind) = move_stake_or_lamports_shared_checks(
        source_stake_ai,
        lamports,
        destination_stake_ai,
        staker_authority_ai,
        true,  // enforce meta compatibility (authorities, lockups)
        false, // do not require mergeable classification
    )?;
    // shared checks complete

    // Authorities/lockups compatibility were already enforced by shared checks.

    // (post-check logging removed; pre-check above handles transient)

    // Additional authority check (redundant with helper and above): staker must match
    if source_kind.meta().authorized.staker != *staker_authority_ai.key() {
        return Err(ProgramError::MissingRequiredSignature);
    }

    // Compute withdrawable lamports from source using the earlier classification
    // - FullyActive: total - rent - max(delegated, min_delegation)
    // - Inactive (Initialized or post-deactivation): total - rent
    // - ActivationEpoch: reject (transient)
    let source_free_lamports = {
        let total = source_stake_ai.lamports();
        match &source_kind {
            MergeKind::Inactive(meta, _stake_lamports, _flags) => {
                let rent_reserve = u64::from_le_bytes(meta.rent_exempt_reserve);
                pinocchio::msg!("ml:inact");
                total.saturating_sub(rent_reserve)
            }
            MergeKind::FullyActive(meta, stake) => {
                let rent_reserve = u64::from_le_bytes(meta.rent_exempt_reserve);
                let delegated = crate::helpers::bytes_to_u64(stake.delegation.stake);
                if delegated == 0 { pinocchio::msg!("ml:deleg0"); } else { pinocchio::msg!("ml:delegN"); }
                pinocchio::msg!("ml:fa");
                // Native parity: free = total - rent - delegated
                total.saturating_sub(rent_reserve).saturating_sub(delegated)
            }
            MergeKind::ActivationEpoch(_, _, _) => {
                pinocchio::msg!("ml:transient_act");
                return Err(crate::error::to_program_error(crate::error::StakeError::MergeMismatch));
            }
        }
    };
    // Emit comparison markers for tests
    pinocchio::msg!("ml:amt");
    let _ = lamports;
    pinocchio::msg!("ml:free");
    // computed free

    // Amount must be within the available budget
    if lamports > source_free_lamports {
        pinocchio::msg!("ml:overshoot");
        return Err(ProgramError::InvalidArgument);
    }
    pinocchio::msg!("ml:within");

    // Move lamports (declared direction only)
    pinocchio::msg!("ml:relocate");
    relocate_lamports(source_stake_ai, destination_stake_ai, lamports)?;
    // relocated

    // Post-condition: both accounts must remain at/above their rent reserves
    let src_meta = source_kind.meta();
    let dst_meta = dest_kind.meta();
    if source_stake_ai.lamports() < u64::from_le_bytes(src_meta.rent_exempt_reserve)
        || destination_stake_ai.lamports() < u64::from_le_bytes(dst_meta.rent_exempt_reserve)
    {
        return Err(ProgramError::InvalidArgument);
    }

    Ok(())
}
