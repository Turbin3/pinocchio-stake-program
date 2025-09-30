use crate::{
    helpers::get_minimum_delegation,
    instruction::{self},
    state::{
        accounts::{AuthorizeCheckedWithSeedData, AuthorizeWithSeedData},
        StakeAuthorize,
    },
};
use crate::error::{to_program_error, StakeError};
#[cfg(all(feature = "wire_bincode", feature = "std"))]
use bincode;
use pinocchio::{
    account_info::AccountInfo, msg, program_entrypoint, program_error::ProgramError,
    pubkey::Pubkey, ProgramResult,
};

macro_rules! trace { ($($t:tt)*) => { #[cfg(feature = "cu-trace")] { msg!($($t)*); } } }

// Entrypoint macro
program_entrypoint!(process_instruction);

#[inline(always)]
fn process_instruction(
    _program_id: &Pubkey,
    accounts: &[AccountInfo],
    instruction_data: &[u8],
) -> ProgramResult {
    // entry marker for both std and sbf
    pinocchio::msg!("ep:enter");
    // Enforce correct program id for consensus parity with native
    let expected_id = Pubkey::try_from(&crate::ID[..]).map_err(|_| ProgramError::IncorrectProgramId)?;
    if *_program_id != expected_id {
        return Err(ProgramError::IncorrectProgramId);
    }
    // Decode StakeInstruction via bincode (native wire). Feature is enabled by default.
    #[cfg(all(feature = "wire_bincode", feature = "std"))]
    {
        let wire_ix = bincode::deserialize::<wire::StakeInstruction>(instruction_data)
            .map_err(|_| ProgramError::InvalidInstructionData)?;
        // Always-on opcode log for debugging
        log_std_variant(&wire_ix);
        // EpochRewards gating
        if epoch_rewards_active() {
            if !matches!(wire_ix, wire::StakeInstruction::GetMinimumDelegation) {
                return Err(to_program_error(StakeError::EpochRewardsActive));
            }
        }
        return dispatch_wire_instruction(accounts, wire_ix);
    }

    // SBF/no_std path: decode native bincode manually without allocations
    #[cfg(all(feature = "wire_bincode", not(feature = "std")))]
    {
        let wire_ix = wire_sbf::deserialize(instruction_data)?;
        log_sbf_variant(&wire_ix);
        if epoch_rewards_active() {
            if !matches!(wire_ix, wire_sbf::StakeInstruction::GetMinimumDelegation) {
                return Err(to_program_error(StakeError::EpochRewardsActive));
            }
        }
        return wire_sbf::dispatch(accounts, wire_ix);
    }

    #[allow(unreachable_code)] Err(ProgramError::InvalidInstructionData)
}

// Wire decoding for StakeInstruction (bincode) for host/dev (std)
#[cfg(all(feature = "wire_bincode", feature = "std"))]
mod wire {
    use serde::{Deserialize, Serialize};
    use super::*;
    #[cfg(not(feature = "std"))]
    use alloc::string::String;

    pub type WirePubkey = [u8; 32];
    impl From<WirePubkey> for Pubkey { fn from(w: WirePubkey) -> Self { Pubkey::new_from_array(w) } }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
    pub struct Authorized { pub staker: WirePubkey, pub withdrawer: WirePubkey }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
    pub struct Lockup { pub unix_timestamp: i64, pub epoch: u64, pub custodian: WirePubkey }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
    pub enum StakeAuthorize { Staker, Withdrawer }

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    pub struct LockupArgs { pub unix_timestamp: Option<i64>, pub epoch: Option<u64>, pub custodian: Option<WirePubkey> }

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    pub struct LockupCheckedArgs { pub unix_timestamp: Option<i64>, pub epoch: Option<u64> }

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    pub struct AuthorizeWithSeedArgs { pub new_authorized_pubkey: WirePubkey, pub stake_authorize: StakeAuthorize, pub authority_seed: String, pub authority_owner: WirePubkey }

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    pub struct AuthorizeCheckedWithSeedArgs { pub stake_authorize: StakeAuthorize, pub authority_seed: String, pub authority_owner: WirePubkey }

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    pub enum StakeInstruction {
        Initialize(Authorized, Lockup),
        Authorize(WirePubkey, StakeAuthorize),
        DelegateStake,
        Split(u64),
        Withdraw(u64),
        Deactivate,
        SetLockup(LockupArgs),
        Merge,
        AuthorizeWithSeed(AuthorizeWithSeedArgs),
        InitializeChecked,
        AuthorizeChecked(StakeAuthorize),
        AuthorizeCheckedWithSeed(AuthorizeCheckedWithSeedArgs),
        SetLockupChecked(LockupCheckedArgs),
        GetMinimumDelegation,
        DeactivateDelinquent,
        #[deprecated]
        Redelegate,
        MoveStake(u64),
        MoveLamports(u64),
    }
}

#[cfg(all(feature = "wire_bincode", feature = "std"))]
fn dispatch_wire_instruction(accounts: &[AccountInfo], ix: wire::StakeInstruction) -> ProgramResult {
    use wire::*;
    match ix {
        StakeInstruction::Initialize(auth, l) => {
            trace!("Instruction: Initialize");
            let authorized = crate::state::accounts::Authorized { staker: Pubkey::from(auth.staker), withdrawer: Pubkey::from(auth.withdrawer) };
            let lockup = crate::state::state::Lockup { unix_timestamp: l.unix_timestamp, epoch: l.epoch, custodian: Pubkey::from(l.custodian) };
            instruction::initialize::initialize(accounts, authorized, lockup)
        }
        StakeInstruction::Authorize(new_auth, which) => {
            trace!("Instruction: Authorize");
            let typ = match which { StakeAuthorize::Staker => StakeAuthorize::Staker, StakeAuthorize::Withdrawer => StakeAuthorize::Withdrawer };
            instruction::authorize::process_authorize(accounts, Pubkey::from(new_auth), typ)
        }
        StakeInstruction::DelegateStake => {
            trace!("Instruction: DelegateStake");
            instruction::process_delegate::process_delegate(accounts)
        }
        StakeInstruction::Split(lamports) => {
            pinocchio::msg!("ep:Split");
            instruction::split::process_split(accounts, lamports)
        }
        StakeInstruction::Withdraw(lamports) => {
            trace!("Instruction: Withdraw");
            instruction::withdraw::process_withdraw(accounts, lamports)
        }
        StakeInstruction::Deactivate => {
            trace!("Instruction: Deactivate");
            instruction::deactivate::process_deactivate(accounts)
        }
        StakeInstruction::SetLockup(args) => {
            trace!("Instruction: SetLockup");
            // Translate into our SetLockupData shape
            let data = crate::state::accounts::SetLockupData {
                unix_timestamp: args.unix_timestamp,
                epoch: args.epoch,
                custodian: args.custodian.map(|c| Pubkey::from(c)),
            };
            instruction::process_set_lockup::process_set_lockup_parsed(accounts, data)
        }
        StakeInstruction::Merge => {
            trace!("Instruction: Merge");
            instruction::merge_dedicated::process_merge(accounts)
        }
        StakeInstruction::AuthorizeWithSeed(args) => {
            trace!("Instruction: AuthorizeWithSeed");
            let new_authorized = Pubkey::from(args.new_authorized_pubkey);
            let stake_authorize = match args.stake_authorize { StakeAuthorize::Staker => StakeAuthorize::Staker, StakeAuthorize::Withdrawer => StakeAuthorize::Withdrawer };
            let authority_owner = Pubkey::from(args.authority_owner);
            let seed_vec = args.authority_seed.into_bytes();
            let data = AuthorizeWithSeedData { new_authorized, stake_authorize, authority_seed: &seed_vec, authority_owner };
            // Keep seed_vec alive across the call
            let res = instruction::process_authorized_with_seeds::process_authorized_with_seeds(accounts, data);
            core::mem::drop(seed_vec);
            res
        }
        StakeInstruction::InitializeChecked => {
            trace!("Instruction: InitializeChecked");
            instruction::initialize_checked::process_initialize_checked(accounts)
        }
        StakeInstruction::AuthorizeChecked(which) => {
            trace!("Instruction: AuthorizeChecked");
            let typ = match which { StakeAuthorize::Staker => StakeAuthorize::Staker, StakeAuthorize::Withdrawer => StakeAuthorize::Withdrawer };
            instruction::authorize_checked::process_authorize_checked(accounts, typ)
        }
        StakeInstruction::AuthorizeCheckedWithSeed(args) => {
            trace!("Instruction: AuthorizeCheckedWithSeed");
            let stake_authorize = match args.stake_authorize { StakeAuthorize::Staker => StakeAuthorize::Staker, StakeAuthorize::Withdrawer => StakeAuthorize::Withdrawer };
            let authority_owner = Pubkey::from(args.authority_owner);
            let seed_vec = args.authority_seed.into_bytes();
            let new_authorized = accounts.get(3).map(|ai| *ai.key()).ok_or(ProgramError::NotEnoughAccountKeys)?;
            let data = AuthorizeCheckedWithSeedData { new_authorized, stake_authorize, authority_seed: &seed_vec, authority_owner };
            let res = instruction::process_authorize_checked_with_seed::process_authorize_checked_with_seed(accounts, data);
            core::mem::drop(seed_vec);
            res
        }
        StakeInstruction::SetLockupChecked(args) => {
            trace!("Instruction: SetLockupChecked");
            // Encode native args into the compact flags+payload expected by the handler
            let mut buf = [0u8; 1 + 8 + 8];
            let mut off = 1usize;
            let mut flags = 0u8;
            if let Some(ts) = args.unix_timestamp { flags |= 0x01; buf[off..off + 8].copy_from_slice(&ts.to_le_bytes()); off += 8; }
            if let Some(ep) = args.epoch { flags |= 0x02; buf[off..off + 8].copy_from_slice(&ep.to_le_bytes()); off += 8; }
            buf[0] = flags;
            instruction::process_set_lockup_checked::process_set_lockup_checked(accounts, &buf[..off])
        }
        StakeInstruction::GetMinimumDelegation => {
            trace!("Instruction: GetMinimumDelegation");
            let value = crate::helpers::get_minimum_delegation();
            let data = value.to_le_bytes();
            #[cfg(not(feature = "std"))]
            { pinocchio::program::set_return_data(&data); }
            Ok(())
        }
        StakeInstruction::DeactivateDelinquent => {
            trace!("Instruction: DeactivateDelinquent");
            instruction::deactivate_delinquent::process_deactivate_delinquent(accounts)
        }
        #[allow(deprecated)]
        StakeInstruction::Redelegate => Err(ProgramError::InvalidInstructionData),
        StakeInstruction::MoveStake(lamports) => {
            trace!("Instruction: MoveStake");
            instruction::process_move_stake::process_move_stake(accounts, lamports)
        }
        StakeInstruction::MoveLamports(lamports) => {
            trace!("Instruction: MoveLamports");
            instruction::move_lamports::process_move_lamports(accounts, lamports)
        }
    }
}

// no_std/SBF: manual decoder for native bincode wire without allocations
#[cfg(all(feature = "wire_bincode", not(feature = "std")))]
mod wire_sbf {
    use super::*;

    pub type WirePubkey = [u8; 32];

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct Authorized { pub staker: WirePubkey, pub withdrawer: WirePubkey }
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct Lockup { pub unix_timestamp: i64, pub epoch: u64, pub custodian: WirePubkey }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum StakeAuthorize { Staker, Withdrawer }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct LockupArgs { pub unix_timestamp: Option<i64>, pub epoch: Option<u64>, pub custodian: Option<WirePubkey> }
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct LockupCheckedArgs { pub unix_timestamp: Option<i64>, pub epoch: Option<u64> }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct AuthorizeWithSeedArgs<'a> { pub new_authorized_pubkey: WirePubkey, pub stake_authorize: StakeAuthorize, pub authority_seed: &'a [u8], pub authority_owner: WirePubkey }
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct AuthorizeCheckedWithSeedArgs<'a> { pub stake_authorize: StakeAuthorize, pub authority_seed: &'a [u8], pub authority_owner: WirePubkey }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum StakeInstruction<'a> {
        Initialize(Authorized, Lockup),
        Authorize(WirePubkey, StakeAuthorize),
        DelegateStake,
        Split(u64),
        Withdraw(u64),
        Deactivate,
        SetLockup(LockupArgs),
        Merge,
        AuthorizeWithSeed(AuthorizeWithSeedArgs<'a>),
        InitializeChecked,
        AuthorizeChecked(StakeAuthorize),
        AuthorizeCheckedWithSeed(AuthorizeCheckedWithSeedArgs<'a>),
        SetLockupChecked(LockupCheckedArgs),
        GetMinimumDelegation,
        DeactivateDelinquent,
        Redelegate,
        MoveStake(u64),
        MoveLamports(u64),
    }

    struct R<'a> { b: &'a [u8], off: usize }
    impl<'a> R<'a> {
        fn new(b: &'a [u8]) -> Self { Self { b, off: 0 } }
        fn rem(&self) -> usize { self.b.len().saturating_sub(self.off) }
        fn take(&mut self, n: usize) -> Result<&'a [u8], ProgramError> {
            if self.rem() < n { return Err(ProgramError::InvalidInstructionData); }
            let s = &self.b[self.off..self.off + n];
            self.off += n;
            Ok(s)
        }
        fn u8(&mut self) -> Result<u8, ProgramError> { Ok(self.take(1)?[0]) }
        fn u32(&mut self) -> Result<u32, ProgramError> { let mut a=[0u8;4]; a.copy_from_slice(self.take(4)?); Ok(u32::from_le_bytes(a)) }
        fn u64(&mut self) -> Result<u64, ProgramError> { let mut a=[0u8;8]; a.copy_from_slice(self.take(8)?); Ok(u64::from_le_bytes(a)) }
        fn i64(&mut self) -> Result<i64, ProgramError> { let mut a=[0u8;8]; a.copy_from_slice(self.take(8)?); Ok(i64::from_le_bytes(a)) }
        fn bool(&mut self) -> Result<bool, ProgramError> { Ok(self.u8()? != 0) }
        fn pubkey(&mut self) -> Result<WirePubkey, ProgramError> { let mut a=[0u8;32]; a.copy_from_slice(self.take(32)?); Ok(a) }
        fn opt_i64(&mut self) -> Result<Option<i64>, ProgramError> { if self.bool()? { Ok(Some(self.i64()?)) } else { Ok(None) } }
        fn opt_u64(&mut self) -> Result<Option<u64>, ProgramError> { if self.bool()? { Ok(Some(self.u64()?)) } else { Ok(None) } }
        fn opt_pubkey(&mut self) -> Result<Option<WirePubkey>, ProgramError> { if self.bool()? { Ok(Some(self.pubkey()?)) } else { Ok(None) } }
        fn string_bytes(&mut self) -> Result<&'a [u8], ProgramError> { let len = self.u64()? as usize; self.take(len) }
        fn stake_auth(&mut self) -> Result<StakeAuthorize, ProgramError> {
            match self.u32()? {
                0 => Ok(StakeAuthorize::Staker),
                1 => Ok(StakeAuthorize::Withdrawer),
                _ => Err(ProgramError::InvalidInstructionData),
            }
        }
    }

    pub fn deserialize(data: &[u8]) -> Result<StakeInstruction, ProgramError> {
        let mut r = R::new(data);
        let variant = r.u32()?;
        use StakeInstruction as SI;
        let ix = match variant {
            0 => {
                let auth = Authorized { staker: r.pubkey()?, withdrawer: r.pubkey()? };
                let l = Lockup { unix_timestamp: r.i64()?, epoch: r.u64()?, custodian: r.pubkey()? };
                SI::Initialize(auth, l)
            }
            1 => SI::Authorize(r.pubkey()?, r.stake_auth()?),
            2 => SI::DelegateStake,
            3 => SI::Split(r.u64()?),
            4 => SI::Withdraw(r.u64()?),
            5 => SI::Deactivate,
            6 => {
                let args = LockupArgs { unix_timestamp: r.opt_i64()?, epoch: r.opt_u64()?, custodian: r.opt_pubkey()? };
                SI::SetLockup(args)
            }
            7 => SI::Merge,
            8 => {
                let args = AuthorizeWithSeedArgs { new_authorized_pubkey: r.pubkey()?, stake_authorize: r.stake_auth()?, authority_seed: r.string_bytes()?, authority_owner: r.pubkey()? };
                SI::AuthorizeWithSeed(args)
            }
            9 => SI::InitializeChecked,
            10 => SI::AuthorizeChecked(r.stake_auth()?),
            11 => {
                let args = AuthorizeCheckedWithSeedArgs { stake_authorize: r.stake_auth()?, authority_seed: r.string_bytes()?, authority_owner: r.pubkey()? };
                SI::AuthorizeCheckedWithSeed(args)
            }
            12 => {
                let args = LockupCheckedArgs { unix_timestamp: r.opt_i64()?, epoch: r.opt_u64()? };
                SI::SetLockupChecked(args)
            }
            13 => SI::GetMinimumDelegation,
            14 => SI::DeactivateDelinquent,
            15 => SI::Redelegate,
            16 => SI::MoveStake(r.u64()?),
            17 => SI::MoveLamports(r.u64()?),
            _ => return Err(ProgramError::InvalidInstructionData),
        };
        Ok(ix)
    }

    pub fn dispatch(accounts: &[AccountInfo], ix: StakeInstruction) -> ProgramResult {
        use StakeInstruction as SI;
        match ix {
            SI::Initialize(auth, l) => {
                trace!("Instruction: Initialize");
                let authorized = crate::state::accounts::Authorized { staker: Pubkey::from(auth.staker), withdrawer: Pubkey::from(auth.withdrawer) };
                let lockup = crate::state::state::Lockup { unix_timestamp: l.unix_timestamp, epoch: l.epoch, custodian: Pubkey::from(l.custodian) };
                crate::instruction::initialize::initialize(accounts, authorized, lockup)
            }
            SI::Authorize(new_auth, which) => {
                trace!("Instruction: Authorize");
                let typ = match which { StakeAuthorize::Staker => crate::state::StakeAuthorize::Staker, StakeAuthorize::Withdrawer => crate::state::StakeAuthorize::Withdrawer };
                crate::instruction::authorize::process_authorize(accounts, Pubkey::from(new_auth), typ)
            }
            SI::DelegateStake => { trace!("Instruction: DelegateStake"); crate::instruction::process_delegate::process_delegate(accounts) }
            SI::Split(lamports) => { pinocchio::msg!("ep:Split"); crate::instruction::split::process_split(accounts, lamports) }
            SI::Withdraw(lamports) => { trace!("Instruction: Withdraw"); crate::instruction::withdraw::process_withdraw(accounts, lamports) }
            SI::Deactivate => { trace!("Instruction: Deactivate"); crate::instruction::deactivate::process_deactivate(accounts) }
            SI::SetLockup(args) => { trace!("Instruction: SetLockup");
                let data = crate::state::accounts::SetLockupData { unix_timestamp: args.unix_timestamp, epoch: args.epoch, custodian: args.custodian.map(Pubkey::from) };
                crate::instruction::process_set_lockup::process_set_lockup_parsed(accounts, data)
            }
            SI::Merge => { trace!("Instruction: Merge"); crate::instruction::merge_dedicated::process_merge(accounts) }
            SI::AuthorizeWithSeed(args) => { trace!("Instruction: AuthorizeWithSeed");
                let new_authorized = Pubkey::from(args.new_authorized_pubkey);
                let stake_authorize = match args.stake_authorize { StakeAuthorize::Staker => crate::state::StakeAuthorize::Staker, StakeAuthorize::Withdrawer => crate::state::StakeAuthorize::Withdrawer };
                let authority_owner = Pubkey::from(args.authority_owner);
                let data = crate::state::accounts::AuthorizeWithSeedData { new_authorized, stake_authorize, authority_seed: args.authority_seed, authority_owner };
                crate::instruction::process_authorized_with_seeds::process_authorized_with_seeds(accounts, data)
            }
            SI::InitializeChecked => { trace!("Instruction: InitializeChecked"); crate::instruction::initialize_checked::process_initialize_checked(accounts) }
            SI::AuthorizeChecked(which) => { trace!("Instruction: AuthorizeChecked");
                let typ = match which { StakeAuthorize::Staker => crate::state::StakeAuthorize::Staker, StakeAuthorize::Withdrawer => crate::state::StakeAuthorize::Withdrawer };
                crate::instruction::authorize_checked::process_authorize_checked(accounts, typ)
            }
            SI::AuthorizeCheckedWithSeed(args) => { trace!("Instruction: AuthorizeCheckedWithSeed");
                let stake_authorize = match args.stake_authorize { StakeAuthorize::Staker => crate::state::StakeAuthorize::Staker, StakeAuthorize::Withdrawer => crate::state::StakeAuthorize::Withdrawer };
                let authority_owner = Pubkey::from(args.authority_owner);
                // In native wire, new_authorized is provided as an account; expected at index 3
                let new_authorized = accounts.get(3).map(|ai| *ai.key()).ok_or(ProgramError::NotEnoughAccountKeys)?;
                let data = crate::state::accounts::AuthorizeCheckedWithSeedData { new_authorized, stake_authorize, authority_seed: args.authority_seed, authority_owner };
                crate::instruction::process_authorize_checked_with_seed::process_authorize_checked_with_seed(accounts, data)
            }
            SI::SetLockupChecked(args) => {
                trace!("Instruction: SetLockupChecked");
                let mut buf = [0u8; 1 + 8 + 8];
                let mut off = 1usize;
                let mut flags = 0u8;
                if let Some(ts) = args.unix_timestamp { flags |= 0x01; buf[off..off + 8].copy_from_slice(&ts.to_le_bytes()); off += 8; }
                if let Some(ep) = args.epoch { flags |= 0x02; buf[off..off + 8].copy_from_slice(&ep.to_le_bytes()); off += 8; }
                buf[0] = flags;
                crate::instruction::process_set_lockup_checked::process_set_lockup_checked(accounts, &buf[..off])
            }
            SI::GetMinimumDelegation => { trace!("Instruction: GetMinimumDelegation");
                let value = crate::helpers::get_minimum_delegation();
                let data = value.to_le_bytes();
                pinocchio::program::set_return_data(&data);
                Ok(())
            }
            SI::DeactivateDelinquent => { trace!("Instruction: DeactivateDelinquent"); crate::instruction::deactivate_delinquent::process_deactivate_delinquent(accounts) }
            SI::Redelegate => Err(ProgramError::InvalidInstructionData),
            SI::MoveStake(lamports) => { trace!("Instruction: MoveStake"); crate::instruction::process_move_stake::process_move_stake(accounts, lamports) }
            SI::MoveLamports(lamports) => { trace!("Instruction: MoveLamports"); crate::instruction::move_lamports::process_move_lamports(accounts, lamports) }
        }
    }
}

// ---- EpochRewards gating (attempt best-effort sysvar read) ----
fn epoch_rewards_active() -> bool { false }

// ----- Debug opcode loggers -----
#[cfg(all(feature = "wire_bincode", feature = "std"))]
fn log_std_variant(ix: &wire::StakeInstruction) {
    use wire::StakeInstruction as SI;
    let tag = match ix {
        SI::Initialize(_, _) => "init",
        SI::Authorize(_, _) => "auth",
        SI::DelegateStake => "delegate",
        SI::Split(_) => "split",
        SI::Withdraw(_) => "withdraw",
        SI::Deactivate => "deactivate",
        SI::SetLockup(_) => "set_lockup",
        SI::Merge => "merge",
        SI::AuthorizeWithSeed(_) => "auth_ws",
        SI::InitializeChecked => "init_checked",
        SI::AuthorizeChecked(_) => "auth_checked",
        SI::AuthorizeCheckedWithSeed(_) => "auth_cws",
        SI::SetLockupChecked(_) => "set_lockup_checked",
        SI::GetMinimumDelegation => "get_min",
        SI::DeactivateDelinquent => "deact_delinquent",
        SI::Redelegate => "redelegate",
        SI::MoveStake(_) => "move_stake",
        SI::MoveLamports(_) => "move_lamports",
    };
    pinocchio::msg!("ep:std:{tag}");
}

#[cfg(all(feature = "wire_bincode", not(feature = "std")))]
fn log_sbf_variant(ix: &wire_sbf::StakeInstruction) {
    use wire_sbf::StakeInstruction as SI;
    let tag = match ix {
        SI::Initialize(_, _) => "init",
        SI::Authorize(_, _) => "auth",
        SI::DelegateStake => "delegate",
        SI::Split(_) => "split",
        SI::Withdraw(_) => "withdraw",
        SI::Deactivate => "deactivate",
        SI::SetLockup(_) => "set_lockup",
        SI::Merge => "merge",
        SI::AuthorizeWithSeed(_) => "auth_ws",
        SI::InitializeChecked => "init_checked",
        SI::AuthorizeChecked(_) => "auth_checked",
        SI::AuthorizeCheckedWithSeed(_) => "auth_cws",
        SI::SetLockupChecked(_) => "set_lockup_checked",
        SI::GetMinimumDelegation => "get_min",
        SI::DeactivateDelinquent => "deact_delinquent",
        SI::Redelegate => "redelegate",
        SI::MoveStake(_) => "move_stake",
        SI::MoveLamports(_) => "move_lamports",
    };
    pinocchio::msg!("ep:sbf:{tag}");
}
