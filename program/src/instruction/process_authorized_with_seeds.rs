use pinocchio::{account_info::AccountInfo, program_error::ProgramError, ProgramResult};

use crate::state::accounts::{AuthorizeWithSeedData, Authorized, StakeAuthorize};

pub fn process_authorized_with_seeds(
    accounts: &[AccountInfo],
    instruction_data: &[u8],
) -> ProgramResult {
    if accounts.len() < 2 {
        return Err(ProgramError::NotEnoughAccountKeys);
    };

    let [stake_account, authority_account, _remaining @ ..] = accounts else {
        return Err(ProgramError::InvalidAccountData);
    };

    let authorized_data = AuthorizeWithSeedData::parse(instruction_data)?;

    if !stake_account.is_writable() {
        return Err(ProgramError::InvalidAccountData);
    };

    if stake_account.owner() != &crate::ID {
        return Err(ProgramError::IncorrectProgramId);
    };

    if !authority_account.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    };

    let mut authorized = Authorized::get_account_info_mut(stake_account)?;

    match authorized_data.stake_authorize {
        StakeAuthorize::Staker => {
            // Check if the authority account is the current staker
            if !authorized.is_staker(authority_account.key()) {
                return Err(ProgramError::InvalidAccountData);
            }
            // Update the staker authority to the new one
            authorized.staker = authorized_data.new_authorized;
        }
        StakeAuthorize::Withdrawer => {
            // Check if the authority account is the current withdrawer
            if !authorized.is_withdrawer(authority_account.key()) {
                return Err(ProgramError::InvalidAccountData);
            }
            // Update the withdrawer authority to the new one
            authorized.withdrawer = authorized_data.new_authorized;
        }
    }

    Ok(())
}
