use pinocchio::program_error::ProgramError;

pub mod initialize;
pub mod split;

pub use initialize::*;
pub use split::*;

pub mod process_set_lockup;
pub use process_set_lockup::*;



pub mod process_authorized_with_seeds;
pub use process_authorized_with_seeds::*;


pub mod process_delegate;
pub use process_delegate::*;



pub mod process_move_stake;
pub use process_move_stake::*;

pub mod process_redelegate;
pub use process_redelegate::*;

pub mod deactivate_delinquent;
pub use deactivate_delinquent::*;
pub mod move_lamports;
pub use move_lamports::*;

#[repr(u8)]
pub enum StakeInstruction {
    Initialize,
    Authorize,
    DelegateStake,
    Split,
    Withdraw,
    Deactivate,
    SetLockup,
    Merge,
    AuthorizeWithSeed,
    InitializeChecked,
    AuthorizeChecked,
    AuthorizeCheckedWithSeed,
    SetLockupChecked,
    GetMinimumDelegation,
    DeactivateDelinquent,
    #[deprecated(since = "2.1.0", note = "Redelegate will not be enabled")]
    Redelegate,
    MoveStake,
    MoveLamports,
}

impl TryFrom<&u8> for StakeInstruction {
    type Error = ProgramError;

    fn try_from(value: &u8) -> Result<Self, Self::Error> {
        match *value {
            0 => Ok(StakeInstruction::Initialize),
            1 => Ok(StakeInstruction::Authorize),
            2 => Ok(StakeInstruction::DelegateStake),
            3 => Ok(StakeInstruction::Split),
            4 => Ok(StakeInstruction::Withdraw),
            5 => Ok(StakeInstruction::Deactivate),
            6 => Ok(StakeInstruction::SetLockup),
            7 => Ok(StakeInstruction::Merge),
            8 => Ok(StakeInstruction::AuthorizeWithSeed),
            9 => Ok(StakeInstruction::InitializeChecked),
            10 => Ok(StakeInstruction::AuthorizeChecked),
            11 => Ok(StakeInstruction::AuthorizeCheckedWithSeed),
            12 => Ok(StakeInstruction::SetLockupChecked),
            13 => Ok(StakeInstruction::GetMinimumDelegation),
            14 => Ok(StakeInstruction::DeactivateDelinquent),
            #[allow(deprecated)]
            15 => Ok(StakeInstruction::Redelegate),
            16 => Ok(StakeInstruction::MoveStake),
            17 => Ok(StakeInstruction::MoveLamports),
            _ => Err(ProgramError::InvalidInstructionData),
        }
    }
}
