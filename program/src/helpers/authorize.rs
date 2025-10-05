use pinocchio::{account_info::AccountInfo, program_error::ProgramError, pubkey::Pubkey, sysvars::clock::Clock};

use crate::state::{StakeAuthorize};
use crate::state::state::Meta;

pub fn authorize_update(
    meta: &mut Meta,
    new_authorized: Pubkey,
    which: StakeAuthorize,
    signers: &[Pubkey],                     // all tx signer pubkeys
    maybe_lockup_authority: Option<&AccountInfo>,
    clock: &Clock,
) -> Result<(), ProgramError> {
    let signed = |k: &Pubkey| signers.iter().any(|s| s == k);

    match which {
        StakeAuthorize::Staker => {
            // Either staker OR withdrawer may change the staker
            if !(signed(&meta.authorized.staker) || signed(&meta.authorized.withdrawer)) {
                pinocchio::msg!("auth_upd:staker:not_signed");
                return Err(ProgramError::MissingRequiredSignature);
            }
            meta.authorized.staker = new_authorized;
        }
        StakeAuthorize::Withdrawer => {
            // Only withdrawer may change the withdrawer
            if !signed(&meta.authorized.withdrawer) {
                pinocchio::msg!("auth_upd:withdrawer:not_signed");
                return Err(ProgramError::MissingRequiredSignature);
            }

            // Lockup enforcement: require custodian signer if lockup still in force
            let epoch_in_force = meta.lockup.epoch> clock.epoch;
            let ts_in_force    = meta.lockup.unix_timestamp > clock.unix_timestamp;
            if epoch_in_force || ts_in_force {
                let custodian_ok = maybe_lockup_authority
                    .map(|a| a.is_signer() && a.key() == &meta.lockup.custodian)
                    .unwrap_or(false);
                if !custodian_ok {
                    pinocchio::msg!("auth_upd:withdrawer:lockup_no_custodian");
                    return Err(ProgramError::MissingRequiredSignature);
                }
            }

            meta.authorized.withdrawer = new_authorized;
        }
    }

    Ok(())
}
