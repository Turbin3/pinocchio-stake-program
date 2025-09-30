use solana_program_test::BanksClient;
use solana_sdk::{
    instruction::{AccountMeta, Instruction},
    pubkey::Pubkey,
    stake::{
        instruction as sdk_ixn,
        program::id as stake_program_id,
        state::{Authorized, Lockup, Meta, Stake, StakeAuthorize},
    },
};

pub mod ixn {
    use super::*;


    pub fn get_minimum_delegation() -> Instruction {
        sdk_ixn::get_minimum_delegation()
    }

    pub fn initialize(stake: &Pubkey, authorized: &Authorized, lockup: &Lockup) -> Instruction {
        sdk_ixn::initialize(stake, authorized, lockup)
    }

    pub fn initialize_checked(stake: &Pubkey, authorized: &Authorized) -> Instruction {
        sdk_ixn::initialize_checked(stake, authorized)
    }

    pub fn authorize(
        stake: &Pubkey,
        authority: &Pubkey,
        new_authorized: &Pubkey,
        role: StakeAuthorize,
        custodian: Option<&Pubkey>,
    ) -> Instruction {
        let mut ix = sdk_ixn::authorize(stake, authority, new_authorized, role, custodian);
        ix
    }

    pub fn authorize_checked(
        stake: &Pubkey,
        authority: &Pubkey,
        new_authorized: &Pubkey,
        role: StakeAuthorize,
        custodian: Option<&Pubkey>,
    ) -> Instruction {
        let mut ix = sdk_ixn::authorize_checked(stake, authority, new_authorized, role, custodian);
        ix
    }

    pub fn authorize_checked_with_seed(
        stake: &Pubkey,
        base: &Pubkey,
        seed: String,
        owner: &Pubkey,
        new_authorized: &Pubkey,
        role: StakeAuthorize,
        custodian: Option<&Pubkey>,
    ) -> Instruction {
        let mut ix = sdk_ixn::authorize_checked_with_seed(
            stake,
            base,
            seed.clone(),
            owner,
            new_authorized,
            role,
            custodian,
        );
        ix
    }

    // Non-checked with-seed variant: base signs; new_authorized does not need to sign
    pub fn authorize_with_seed(
        stake: &Pubkey,
        base: &Pubkey,
        seed: String,
        owner: &Pubkey,
        new_authorized: &Pubkey,
        role: StakeAuthorize,
        _custodian: Option<&Pubkey>,
    ) -> Instruction {
        sdk_ixn::authorize_with_seed(stake, base, seed, owner, new_authorized, role, _custodian)
    }

    pub fn set_lockup_checked(stake: &Pubkey, args: &solana_sdk::stake::instruction::LockupArgs, signer: &Pubkey) -> Instruction {
        let mut ix = sdk_ixn::set_lockup_checked(stake, args, signer);
        ix
    }

    pub fn delegate_stake(stake: &Pubkey, staker: &Pubkey, vote: &Pubkey) -> Instruction {
        // Use native metas and wire
        sdk_ixn::delegate_stake(stake, staker, vote)
    }

    pub fn split(stake: &Pubkey, authority: &Pubkey, lamports: u64, split_dest: &Pubkey) -> Vec<Instruction> {
        // Use native metas and wire
        sdk_ixn::split(stake, authority, lamports, split_dest)
    }

    pub fn withdraw(
        stake: &Pubkey,
        withdrawer: &Pubkey,
        recipient: &Pubkey,
        lamports: u64,
        custodian: Option<&Pubkey>,
    ) -> Instruction {
        // Use native metas and wire
        sdk_ixn::withdraw(stake, withdrawer, recipient, lamports, custodian)
    }

    pub fn deactivate_stake(stake: &Pubkey, staker: &Pubkey) -> Instruction {
        sdk_ixn::deactivate_stake(stake, staker)
    }

    // Convenience alias matching native name
    pub fn deactivate(stake: &Pubkey, staker: &Pubkey) -> Instruction {
        deactivate_stake(stake, staker)
    }

    pub fn merge(dest: &Pubkey, src: &Pubkey, authority: &Pubkey) -> Vec<Instruction> {
        // Use native metas and wire
        sdk_ixn::merge(dest, src, authority)
    }

    pub fn move_stake(source: &Pubkey, dest: &Pubkey, staker: &Pubkey, lamports: u64) -> Instruction {
        sdk_ixn::move_stake(source, dest, staker, lamports)
    }

    pub fn move_lamports(source: &Pubkey, dest: &Pubkey, staker: &Pubkey, lamports: u64) -> Instruction {
        sdk_ixn::move_lamports(source, dest, staker, lamports)
    }

    // DeactivateDelinquent: [stake, delinquent_vote, reference_vote]
    pub fn deactivate_delinquent(stake: &Pubkey, delinquent_vote: &Pubkey, reference_vote: &Pubkey) -> Instruction {
        // Build native-ABI instruction data via bincode (SDK may not expose this helper)
        Instruction {
            program_id: stake_program_id(),
            accounts: vec![
                AccountMeta::new(*stake, false),
                AccountMeta::new_readonly(*delinquent_vote, false),
                AccountMeta::new_readonly(*reference_vote, false),
            ],
            data: bincode::serialize(&solana_sdk::stake::instruction::StakeInstruction::DeactivateDelinquent)
                .expect("serialize DeactivateDelinquent"),
        }
    }
}

// Re-export ixn::* so tests can `use crate::common::pin_adapter as ixn;`
pub use ixn::*;

// ---------- State helpers ----------
pub async fn get_stake_account(
    banks_client: &mut BanksClient,
    pubkey: &Pubkey,
) -> (Meta, Option<Stake>, u64) {
    use pinocchio_stake::state as pstate;
    let stake_account = banks_client.get_account(*pubkey).await.unwrap().unwrap();
    let lamports = stake_account.lamports;
    let st = pstate::stake_state_v2::StakeStateV2::deserialize(&stake_account.data).unwrap();
    match st {
        pstate::stake_state_v2::StakeStateV2::Initialized(meta) => {
            let meta_sdk = Meta {
                authorized: Authorized {
                    staker: Pubkey::new_from_array(meta.authorized.staker),
                    withdrawer: Pubkey::new_from_array(meta.authorized.withdrawer),
                },
                rent_exempt_reserve: u64::from_le_bytes(meta.rent_exempt_reserve),
                lockup: Lockup {
                    unix_timestamp: meta.lockup.unix_timestamp,
                    epoch: meta.lockup.epoch,
                    custodian: Pubkey::new_from_array(meta.lockup.custodian),
                },
            };
            (meta_sdk, None, lamports)
        }
        pstate::stake_state_v2::StakeStateV2::Stake(meta, stake, _flags) => {
            let meta_sdk = Meta {
                authorized: Authorized {
                    staker: Pubkey::new_from_array(meta.authorized.staker),
                    withdrawer: Pubkey::new_from_array(meta.authorized.withdrawer),
                },
                rent_exempt_reserve: u64::from_le_bytes(meta.rent_exempt_reserve),
                lockup: Lockup {
                    unix_timestamp: meta.lockup.unix_timestamp,
                    epoch: meta.lockup.epoch,
                    custodian: Pubkey::new_from_array(meta.lockup.custodian),
                },
            };
            let del = &stake.delegation;
            let delegation_sdk = solana_sdk::stake::state::Delegation {
                voter_pubkey: Pubkey::new_from_array(del.voter_pubkey),
                stake: u64::from_le_bytes(del.stake),
                activation_epoch: u64::from_le_bytes(del.activation_epoch),
                deactivation_epoch: u64::from_le_bytes(del.deactivation_epoch),
                warmup_cooldown_rate: f64::from_bits(u64::from_le_bytes(del.warmup_cooldown_rate)),
            };
            let stake_sdk = Stake {
                delegation: delegation_sdk,
                credits_observed: u64::from_le_bytes(stake.credits_observed),
            };
            (meta_sdk, Some(stake_sdk), lamports)
        }
        pstate::stake_state_v2::StakeStateV2::Uninitialized => panic!("panic: uninitialized"),
        _ => unimplemented!(),
    }
}

pub async fn get_stake_account_rent(banks_client: &mut BanksClient) -> u64 {
    let rent = banks_client.get_rent().await.unwrap();
    rent.minimum_balance(pinocchio_stake::state::stake_state_v2::StakeStateV2::size_of())
}

pub fn encode_program_stake_state(st: &pinocchio_stake::state::stake_state_v2::StakeStateV2) -> Vec<u8> {
    let mut buf = vec![0u8; pinocchio_stake::state::stake_state_v2::StakeStateV2::size_of()];
    pinocchio_stake::state::stake_state_v2::StakeStateV2::serialize(st, &mut buf)
        .expect("serialize stake state");
    buf
}

// ---------- Error helpers ----------
pub mod err {
    use solana_sdk::{program_error::ProgramError, stake::instruction::StakeError};

    pub fn matches_stake_error(e: &ProgramError, expected: StakeError) -> bool {
        match (e, expected.clone()) {
            (ProgramError::Custom(0x11), StakeError::AlreadyDeactivated) => true,
            (ProgramError::Custom(0x12), StakeError::InsufficientDelegation) => true,
            (ProgramError::Custom(0x13), StakeError::VoteAddressMismatch) => true,
            (ProgramError::Custom(0x14), StakeError::MergeMismatch) => true,
            (ProgramError::Custom(0x15), StakeError::LockupInForce) => true,
            (ProgramError::Custom(0x18), StakeError::TooSoonToRedelegate) => true,
            _ => *e == expected.into(),
        }
    }
}
