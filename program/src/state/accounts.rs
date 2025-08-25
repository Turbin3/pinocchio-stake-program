use crate::{error::StakeError, state::Lockup};

use core::mem::size_of;
use pinocchio::{account_info::AccountInfo, program_error::ProgramError, pubkey::Pubkey};

use crate::helpers::*;

// Constants for fixed-size arrays
pub const MAX_AUTHORITY_SEED_LEN: usize = 32;

#[repr(C)]
#[derive(Default, Debug, PartialEq, Eq, Clone, Copy)]
pub struct Authorized {
    /// Authority to manage the stake account (delegate, deactivate, split, merge)
    pub staker: Pubkey,

    /// Authority to withdraw funds from the stake account
    pub withdrawer: Pubkey,
}

impl Authorized {
    pub const fn size() -> usize {
        core::mem::size_of::<Authorized>() // Removed the +8
    }

    pub fn new(staker: Pubkey, withdrawer: Pubkey) -> Self {
        Self { staker, withdrawer }
    }

    pub fn is_staker(&self, pubkey: &Pubkey) -> bool {
        self.staker == *pubkey
    }

    pub fn is_withdrawer(&self, pubkey: &Pubkey) -> bool {
        self.withdrawer == *pubkey
    }

    pub fn get_account_info(accounts: &AccountInfo) -> Result<&Self, ProgramError> {
        if accounts.data_len() < Self::size() {
            return Err(ProgramError::InvalidAccountData);
        }

        Ok(unsafe { &*(accounts.borrow_data_unchecked().as_ptr() as *const Self) })
    }

    pub fn get_account_info_mut(accounts: &AccountInfo) -> Result<&mut Self, ProgramError> {
        if accounts.data_len() < Self::size() {
            return Err(ProgramError::InvalidAccountData);
        }

        Ok(unsafe { &mut *(accounts.borrow_mut_data_unchecked().as_ptr() as *mut Self) })
    }

    // verify required signature is present
    pub fn check(
        &self,
        signers: &[Pubkey],
        stake_authorize: StakeAuthorize,
    ) -> Result<(), StakeError> {
        let required = match stake_authorize {
            StakeAuthorize::Staker => self.staker,
            StakeAuthorize::Withdrawer => self.withdrawer,
        };

        if signers.contains(&required) {
            Ok(())
        } else {
            Err(StakeError::InvalidAuthorization)
        }
    }
}

// #[repr(C)]
// #[derive(Default, Debug, PartialEq, Eq, Clone, Copy)]
// pub struct Lockup {
//     /// Unix timestamp at which this stake will allow withdrawal, unless the transaction is signed by the custodian
//     pub unix_timestamp: UnixTimestamp,
//     /// Epoch height at which this stake will allow withdrawal, unless the transaction is signed by the custodian
//     pub epoch: Epoch,
//     // Custodian signature on a transaction exempts the operation from lockup constraints
//     pub custodian: Pubkey,
// }

// impl Lockup {
//     pub const fn size() -> usize {
//         core::mem::size_of::<Lockup>()
//     }

//     /// Create a new lockup
//     pub fn new(unix_timestamp: i64, epoch: Epoch, custodian: Pubkey) -> Self {
//         Self {
//             unix_timestamp,
//             epoch,
//             custodian,
//         }
//     }

//     /// Check if the lockup is active for the given timestamp and epoch
//     pub fn is_active(&self, current_timestamp: i64, current_epoch: u64) -> bool {
//         current_timestamp < self.unix_timestamp || current_epoch < bytes_to_u64(self.epoch)
//     }

//     pub fn get_account_info(account: &AccountInfo) -> Result<&Self, ProgramError> {
//         if account.data_len() < Self::size() {
//             return Err(ProgramError::InvalidAccountData);
//         };

//         if account.owner() != &crate::ID {
//             return Err(ProgramError::IncorrectProgramId);
//         };

//         return Ok(unsafe { &*(account.borrow_data_unchecked().as_ptr() as *const Self) });
//     }

//     pub fn get_account_info_mut(account: &AccountInfo) -> Result<&mut Self, ProgramError> {
//         if account.data_len() < Self::size() {
//             return Err(ProgramError::InvalidAccountData);
//         };

//         if !account.is_writable() {
//             return Err(ProgramError::InvalidAccountData);
//         };

//         if account.owner() != &crate::ID {
//             return Err(ProgramError::IncorrectProgramId);
//         };

//         return Ok(unsafe { &mut *(account.borrow_mut_data_unchecked().as_ptr() as *mut Self) });
//     }
// }

#[derive(Debug, Clone, PartialEq)]
#[repr(C)]
pub struct Stake {
    /// Delegation information
    pub delegation: Delegation,
    /// Credits observed during the epoch
    pub credits_observed: u64,
}

#[derive(Debug, Clone, PartialEq)]
#[repr(C)]
pub struct Delegation {
    /// To whom the stake is delegated
    pub voter_pubkey: Pubkey,
    /// Amount of stake delegated, in lamports
    pub stake: u64,
    /// Epoch at which this delegation was activated
    pub activation_epoch: u64,
    /// Epoch at which this delegation was deactivated, or u64::MAX if never deactivated
    pub deactivation_epoch: u64,
    /// How much stake we can activate per-epoch as a fraction of currently effective stake
    pub warmup_cooldown_rate: f64,
}

impl Delegation {
    pub fn size() -> usize {
        size_of::<Delegation>()
    }

    /// Check if the delegation is active
    pub fn is_active(&self) -> bool {
        self.deactivation_epoch == u64::MAX
    }

    /// Check if the delegation is fully activated
    pub fn is_fully_activated(&self, current_epoch: u64) -> bool {
        current_epoch >= self.activation_epoch
    }
}

/// Configuration parameters for the stake program
#[derive(Debug, Clone, PartialEq)]
#[repr(C)]
pub struct Config {
    /// How much stake we can activate/deactivate per-epoch as a fraction of currently effective stake
    pub warmup_cooldown_rate: f64,
    /// Percentage of stake lost when slashing a stake account
    pub slash_penalty: u8,
}

impl Config {
    pub const fn size() -> usize {
        core::mem::size_of::<Config>()
    }
}

/// Initialize stake account instruction data
#[repr(C)]
pub struct InitializeData {
    pub authorized: Authorized,
    pub lockup: Lockup,
}

impl InitializeData {
    pub const fn size() -> usize {
        Authorized::size() + Lockup::size()
    }
}

// Delegate stake instruction data
#[derive(Debug, Clone, PartialEq)]
#[repr(C)]
pub struct DelegateStakeData {
    pub vote_pubkey: Pubkey,
}

impl DelegateStakeData {
    pub const fn size() -> usize {
        core::mem::size_of::<DelegateStakeData>()
    }
}

// Split stake instruction data
#[derive(Debug, Clone, PartialEq)]
#[repr(C)]
pub struct SplitData {
    pub lamports: u64,
}

impl SplitData {
    pub const fn size() -> usize {
        core::mem::size_of::<SplitData>()
    }
}

// Withdraw instruction data
#[derive(Debug, Clone, PartialEq)]
#[repr(C)]
pub struct WithdrawData {
    pub lamports: u64,
}

impl WithdrawData {
    pub const fn size() -> usize {
        core::mem::size_of::<WithdrawData>()
    }
}

// Authorize instruction data
#[derive(Debug, Clone, PartialEq)]
#[repr(C)]
pub struct AuthorizeData {
    pub new_authorized: Pubkey,
    pub stake_authorize: StakeAuthorize,
}

impl AuthorizeData {
    pub const fn size() -> usize {
        core::mem::size_of::<AuthorizeData>()
    }
}

/// Types of stake authorization
#[derive(Debug, Clone, PartialEq)]
#[repr(u8)]
pub enum StakeAuthorize {
    Staker = 0,
    Withdrawer = 1,
}

/// Authorize with seed instruction data
#[repr(C)]
pub struct AuthorizeWithSeedData<'a> {
    pub new_authorized: Pubkey,
    pub stake_authorize: StakeAuthorize,
    pub authority_seed: &'a [u8],
    pub authority_owner: Pubkey,
}

impl<'a> AuthorizeWithSeedData<'a> {
    pub const fn size() -> usize {
        core::mem::size_of::<AuthorizeWithSeedData>()
    }
    pub fn parse(data: &'a [u8]) -> Result<Self, ProgramError> {
        // Expected format:
        // [0..32] - new_authorized pubkey
        // [32] - stake_authorize (0 or 1)
        // [33] - seed length
        // [34..34+seed_len] - authority_seed
        // [34+seed_len..66+seed_len] - authority_owner pubkey

        if data.len() < 34 + 32 {
            return Err(ProgramError::InvalidInstructionData);
        }

        // Fix: use [0..32] not [0..33]
        let new_authorized =
            Pubkey::try_from(&data[0..32]).map_err(|_| ProgramError::InvalidInstructionData)?;

        let stake_authorize = match data[32] {
            0 => StakeAuthorize::Staker,
            1 => StakeAuthorize::Withdrawer,
            _ => return Err(ProgramError::InvalidInstructionData),
        };

        let seed_len = data[33] as usize;

        if seed_len > 32 {
            return Err(ProgramError::InvalidInstructionData);
        }

        if data.len() < 34 + seed_len + 32 {
            return Err(ProgramError::InvalidInstructionData);
        }

        let authority_seed = &data[34..34 + seed_len];
        let authority_owner = Pubkey::try_from(&data[34 + seed_len..34 + seed_len + 32])
            .map_err(|_| ProgramError::InvalidInstructionData)?;

        Ok(Self {
            new_authorized,
            stake_authorize,
            authority_seed,
            authority_owner,
        })
    }
}

#[derive(Clone)]
pub struct SetLockupData {
    pub unix_timestamp: Option<i64>,
    pub epoch: Option<u64>,
    pub custodian: Option<Pubkey>,
}

impl SetLockupData {
    pub const LEN: usize = 1 + 8 + 1 + 8 + 1 + 32; // flags + timestamp + flag + epoch + flag + pubkey

    pub fn instruction_data(data: &[u8]) -> &mut Self {
        unsafe { &mut *(data.as_ptr() as *mut Self) }
    }
}
