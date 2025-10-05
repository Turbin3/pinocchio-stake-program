#![cfg(feature = "e2e")]
//! Native vs Pinocchio snapshot parity (end-to-end, minimal flow)
//! These tests run ProgramTest twice (native and pin) and compare stake state
//! after identical flows.

use crate::common::*;
use solana_program_test::ProgramTest;

mod common;

#[derive(Debug, Clone, PartialEq, Eq)]
struct MetaSnap {
    staker: [u8;32],
    withdrawer: [u8;32],
    unix_timestamp: i64,
    epoch: u64,
    custodian: [u8;32],
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DelegSnap {
    voter: [u8;32],
    stake: u64,
    activation_epoch: u64,
    deactivation_epoch: u64,
    credits_observed: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct StakeSnap { lamports: u64, meta: MetaSnap, deleg: Option<DelegSnap> }

async fn read_native_snap(banks: &mut BanksClient, addr: Pubkey) -> StakeSnap {
    use solana_stake_interface::state as istate;
    let acc = banks.get_account(addr).await.unwrap().unwrap();
    let st: istate::StakeStateV2 = bincode::deserialize(&acc.data).unwrap();
    let meta = match st.meta().expect("not uninitialized") {
        m => m,
    };
    let deleg = st.stake_ref().map(|s| DelegSnap {
        voter: s.delegation.voter_pubkey.to_bytes(),
        stake: s.delegation.stake,
        activation_epoch: s.delegation.activation_epoch,
        deactivation_epoch: s.delegation.deactivation_epoch,
        credits_observed: s.credits_observed,
    });
    let snap = StakeSnap {
        lamports: acc.lamports,
        meta: MetaSnap {
            staker: meta.authorized.staker.to_bytes(),
            withdrawer: meta.authorized.withdrawer.to_bytes(),
            unix_timestamp: meta.lockup.unix_timestamp,
            epoch: meta.lockup.epoch,
            custodian: meta.lockup.custodian.to_bytes(),
        },
        deleg,
    };
    snap
}

async fn read_pin_snap(banks: &mut BanksClient, addr: Pubkey) -> StakeSnap {
    let acc = banks.get_account(addr).await.unwrap().unwrap();
    let st = pinocchio_stake::state::stake_state_v2::StakeStateV2::deserialize(&acc.data).unwrap();
    match st {
        pinocchio_stake::state::stake_state_v2::StakeStateV2::Initialized(meta) => StakeSnap {
            lamports: acc.lamports,
            meta: MetaSnap {
                staker: meta.authorized.staker,
                withdrawer: meta.authorized.withdrawer,
                unix_timestamp: meta.lockup.unix_timestamp,
                epoch: meta.lockup.epoch,
                custodian: meta.lockup.custodian,
            },
            deleg: None,
        },
        pinocchio_stake::state::stake_state_v2::StakeStateV2::Stake(meta, stake, _flags) => StakeSnap {
            lamports: acc.lamports,
            meta: MetaSnap {
                staker: meta.authorized.staker,
                withdrawer: meta.authorized.withdrawer,
                unix_timestamp: meta.lockup.unix_timestamp,
                epoch: meta.lockup.epoch,
                custodian: meta.lockup.custodian,
            },
            deleg: Some(DelegSnap {
                voter: stake.delegation.voter_pubkey,
                stake: u64::from_le_bytes(stake.delegation.stake),
                activation_epoch: u64::from_le_bytes(stake.delegation.activation_epoch),
                deactivation_epoch: u64::from_le_bytes(stake.delegation.deactivation_epoch),
                credits_observed: u64::from_le_bytes(stake.credits_observed),
            }),
        },
        _ => panic!("unexpected state"),
    }
}

async fn run_flow(pt: ProgramTest, staker: &Keypair, withdrawer: &Keypair) -> StakeSnap {
    use crate::common::pin_adapter as ixn;
    let mut ctx = pt.start_with_context().await;
    // Create stake account owned by active program id
    let program_id = Pubkey::new_from_array(pinocchio_stake::ID);
    let stake_acc = Keypair::new();
    let rent = ctx.banks_client.get_rent().await.unwrap();
    let space = pinocchio_stake::state::stake_state_v2::StakeStateV2::ACCOUNT_SIZE as u64;
    let reserve = rent.minimum_balance(space as usize);
    let create = system_instruction::create_account(&ctx.payer.pubkey(), &stake_acc.pubkey(), reserve, space, &program_id);
    let tx = Transaction::new_signed_with_payer(&[create], Some(&ctx.payer.pubkey()), &[&ctx.payer, &stake_acc], ctx.last_blockhash);
    ctx.banks_client.process_transaction(tx).await.unwrap();

    // InitializeChecked
    let init_ix = ixn::initialize_checked(&stake_acc.pubkey(), &solana_sdk::stake::state::Authorized { staker: staker.pubkey(), withdrawer: withdrawer.pubkey() });
    let tx = Transaction::new_signed_with_payer(&[init_ix], Some(&ctx.payer.pubkey()), &[&ctx.payer, withdrawer], ctx.last_blockhash);
    ctx.banks_client.process_transaction(tx).await.unwrap();

    // SetLockupChecked: set epoch only (not in force)
    let args = solana_sdk::stake::instruction::LockupArgs { unix_timestamp: None, epoch: Some(3), custodian: None };
    let ix = ixn::set_lockup_checked(&stake_acc.pubkey(), &args, &withdrawer.pubkey());
    let tx = Transaction::new_signed_with_payer(&[ix], Some(&ctx.payer.pubkey()), &[&ctx.payer, withdrawer], ctx.last_blockhash);
    ctx.banks_client.process_transaction(tx).await.unwrap();

    read_snap(&mut ctx.banks_client, stake_acc.pubkey()).await
}

async fn read_snap(banks: &mut BanksClient, addr: Pubkey) -> StakeSnap {
    // The active program is either native or pin; try native first
    let acc = banks.get_account(addr).await.unwrap().unwrap();
    // Try native deserialize; if it fails, use pin serializer
    let is_native = bincode::deserialize::<solana_stake_interface::state::StakeStateV2>(&acc.data).is_ok();
    if is_native { read_native_snap(banks, addr).await } else { read_pin_snap(banks, addr).await }
}

#[tokio::test]
#[ignore]
async fn native_vs_pinocchio_min_flow_parity() {
    // Native bench (builtin stake or BPF override if provided via env/fixtures)
    let pt_native = common::program_test_native();
    let staker = Keypair::new();
    let withdrawer = Keypair::new();
    let snap_native = run_flow(pt_native, &staker, &withdrawer).await;

    // Pinocchio bench (override stake with our SBF)
    let pt_pin = common::program_test();
    let snap_pin = run_flow(pt_pin, &staker, &withdrawer).await;

    assert_eq!(snap_native.meta.staker, snap_pin.meta.staker);
    assert_eq!(snap_native.meta.withdrawer, snap_pin.meta.withdrawer);
    assert_eq!(snap_native.meta.epoch, snap_pin.meta.epoch);
    assert_eq!(snap_native.meta.unix_timestamp, snap_pin.meta.unix_timestamp);
    assert_eq!(snap_native.meta.custodian, snap_pin.meta.custodian);
    // Not delegated in this minimal flow
    assert_eq!(snap_native.deleg, snap_pin.deleg);
}
