#![cfg(feature = "e2e")]
//! Wire-parity smoke tests: compare Instruction bytes and metas built from two
//! independent sources to catch drift early. These do not execute the program;
//! they just assert byte-identical discriminants/payloads and meta ordering.

use solana_sdk::{instruction::Instruction as SdkInstruction, signature::{Keypair, Signer}};
use solana_sdk::pubkey::Pubkey;
use solana_stake_interface as iface;

#[derive(Debug, Clone, PartialEq, Eq)]
struct MetaShape { key: [u8;32], is_signer: bool, is_writable: bool }
#[derive(Debug, Clone, PartialEq, Eq)]
struct IxShape { program: [u8;32], data: Vec<u8>, metas: Vec<MetaShape> }

fn shape_from_sdk(ix: &SdkInstruction) -> IxShape {
    IxShape {
        program: ix.program_id.to_bytes(),
        data: ix.data.clone(),
        metas: ix.accounts.iter().map(|m| MetaShape { key: m.pubkey.to_bytes(), is_signer: m.is_signer, is_writable: m.is_writable }).collect(),
    }
}

#[tokio::test]
async fn parity_initialize_checked_bytes_and_metas() {
    // Inputs
    let stake = Keypair::new().pubkey();
    let staker = Keypair::new().pubkey();
    let withdrawer = Keypair::new().pubkey();

    // Native SDK builder
    let native = solana_sdk::stake::instruction::initialize_checked(
        &stake,
        &solana_sdk::stake::state::Authorized { staker, withdrawer },
    );

    // Interface builder (independent crate)
    // Build using interface crate types (different Pubkey type), convert from arrays
    let stake_if = solana_pubkey::Pubkey::new_from_array(stake.to_bytes());
    let staker_if = solana_pubkey::Pubkey::new_from_array(staker.to_bytes());
    let withdrawer_if = solana_pubkey::Pubkey::new_from_array(withdrawer.to_bytes());
    let other = solana_stake_interface::instruction::initialize_checked(
        &stake_if,
        &solana_stake_interface::state::Authorized { staker: staker_if, withdrawer: withdrawer_if },
    );
    let other_shape = IxShape {
        program: other.program_id.to_bytes(),
        data: other.data.clone(),
        metas: other.accounts.iter().map(|m| MetaShape { key: m.pubkey.to_bytes(), is_signer: m.is_signer, is_writable: m.is_writable }).collect(),
    };
    assert_eq!(shape_from_sdk(&native), other_shape);
}

#[tokio::test]
async fn parity_set_lockup_checked_bytes_and_metas() {
    // Inputs
    let stake = Keypair::new().pubkey();
    let role_signer = Keypair::new().pubkey();
    // Only unix_timestamp/epoch are encoded in the checked variant payload
    let args_sdk = solana_sdk::stake::instruction::LockupArgs { unix_timestamp: Some(1234), epoch: Some(56), custodian: None };

    // Native SDK builder (program id is native stake id)
    let native = solana_sdk::stake::instruction::set_lockup_checked(&stake, &args_sdk, &role_signer);

    // Interface builder (independent crate)
    let stake_if = solana_pubkey::Pubkey::new_from_array(stake.to_bytes());
    let role_if  = solana_pubkey::Pubkey::new_from_array(role_signer.to_bytes());
    let args_if = solana_stake_interface::instruction::LockupArgs { unix_timestamp: Some(1234), epoch: Some(56), custodian: None };
    let other = solana_stake_interface::instruction::set_lockup_checked(&stake_if, &args_if, &role_if);
    let other_shape = IxShape {
        program: other.program_id.to_bytes(),
        data: other.data.clone(),
        metas: other.accounts.iter().map(|m| MetaShape { key: m.pubkey.to_bytes(), is_signer: m.is_signer, is_writable: m.is_writable }).collect(),
    };
    assert_eq!(shape_from_sdk(&native), other_shape);
}

#[tokio::test]
async fn parity_authorize_bytes_and_metas() {
    let stake = Keypair::new().pubkey();
    let current = Keypair::new().pubkey();
    let new_auth = Keypair::new().pubkey();

    let native = solana_sdk::stake::instruction::authorize(
        &stake,
        &current,
        &new_auth,
        solana_sdk::stake::state::StakeAuthorize::Staker,
        None,
    );

    let stake_if = solana_pubkey::Pubkey::new_from_array(stake.to_bytes());
    let current_if = solana_pubkey::Pubkey::new_from_array(current.to_bytes());
    let new_if = solana_pubkey::Pubkey::new_from_array(new_auth.to_bytes());
    let other = iface::instruction::authorize(
        &stake_if,
        &current_if,
        &new_if,
        iface::state::StakeAuthorize::Staker,
        None,
    );

    let other_shape = IxShape {
        program: other.program_id.to_bytes(),
        data: other.data.clone(),
        metas: other.accounts.iter().map(|m| MetaShape { key: m.pubkey.to_bytes(), is_signer: m.is_signer, is_writable: m.is_writable }).collect(),
    };
    assert_eq!(shape_from_sdk(&native), other_shape);
}

#[tokio::test]
async fn parity_authorize_checked_bytes_and_metas() {
    let stake = Keypair::new().pubkey();
    let current = Keypair::new().pubkey();
    let new_auth = Keypair::new().pubkey();

    let native = solana_sdk::stake::instruction::authorize_checked(
        &stake,
        &current,
        &new_auth,
        solana_sdk::stake::state::StakeAuthorize::Withdrawer,
        None,
    );

    let stake_if = solana_pubkey::Pubkey::new_from_array(stake.to_bytes());
    let current_if = solana_pubkey::Pubkey::new_from_array(current.to_bytes());
    let new_if = solana_pubkey::Pubkey::new_from_array(new_auth.to_bytes());
    let other = iface::instruction::authorize_checked(
        &stake_if,
        &current_if,
        &new_if,
        iface::state::StakeAuthorize::Withdrawer,
        None,
    );

    let other_shape = IxShape { program: other.program_id.to_bytes(), data: other.data.clone(), metas: other.accounts.iter().map(|m| MetaShape { key: m.pubkey.to_bytes(), is_signer: m.is_signer, is_writable: m.is_writable }).collect() };
    assert_eq!(shape_from_sdk(&native), other_shape);
}

#[tokio::test]
async fn parity_authorize_with_seed_bytes_and_metas() {
    let stake = Keypair::new().pubkey();
    let base = Keypair::new().pubkey();
    let owner = Pubkey::new_unique();
    let new_auth = Keypair::new().pubkey();
    let seed = "abc".to_string();

    let native = solana_sdk::stake::instruction::authorize_with_seed(
        &stake,
        &base,
        seed.clone(),
        &owner,
        &new_auth,
        solana_sdk::stake::state::StakeAuthorize::Staker,
        None,
    );

    let stake_if = solana_pubkey::Pubkey::new_from_array(stake.to_bytes());
    let base_if = solana_pubkey::Pubkey::new_from_array(base.to_bytes());
    let owner_if = solana_pubkey::Pubkey::new_from_array(owner.to_bytes());
    let new_if = solana_pubkey::Pubkey::new_from_array(new_auth.to_bytes());
    let other = iface::instruction::authorize_with_seed(
        &stake_if,
        &base_if,
        seed.clone(),
        &owner_if,
        &new_if,
        iface::state::StakeAuthorize::Staker,
        None,
    );
    let other_shape = IxShape { program: other.program_id.to_bytes(), data: other.data.clone(), metas: other.accounts.iter().map(|m| MetaShape { key: m.pubkey.to_bytes(), is_signer: m.is_signer, is_writable: m.is_writable }).collect() };
    assert_eq!(shape_from_sdk(&native), other_shape);
}

#[tokio::test]
async fn parity_delegate_and_deactivate_bytes_and_metas() {
    let stake = Keypair::new().pubkey();
    let staker = Keypair::new().pubkey();
    let vote = Keypair::new().pubkey();

    let native_delegate = solana_sdk::stake::instruction::delegate_stake(&stake, &staker, &vote);
    let native_deactivate = solana_sdk::stake::instruction::deactivate_stake(&stake, &staker);

    let stake_if = solana_pubkey::Pubkey::new_from_array(stake.to_bytes());
    let staker_if = solana_pubkey::Pubkey::new_from_array(staker.to_bytes());
    let vote_if = solana_pubkey::Pubkey::new_from_array(vote.to_bytes());
    let other_delegate = iface::instruction::delegate_stake(&stake_if, &staker_if, &vote_if);
    let other_deactivate = iface::instruction::deactivate_stake(&stake_if, &staker_if);

    let del_other = IxShape { program: other_delegate.program_id.to_bytes(), data: other_delegate.data.clone(), metas: other_delegate.accounts.iter().map(|m| MetaShape { key: m.pubkey.to_bytes(), is_signer: m.is_signer, is_writable: m.is_writable }).collect() };
    let del_native = shape_from_sdk(&native_delegate);
    assert_eq!(del_native, del_other);

    let de_other = IxShape { program: other_deactivate.program_id.to_bytes(), data: other_deactivate.data.clone(), metas: other_deactivate.accounts.iter().map(|m| MetaShape { key: m.pubkey.to_bytes(), is_signer: m.is_signer, is_writable: m.is_writable }).collect() };
    let de_native = shape_from_sdk(&native_deactivate);
    assert_eq!(de_native, de_other);
}

#[tokio::test]
async fn parity_get_minimum_delegation_bytes_and_metas() {
    let native = solana_sdk::stake::instruction::get_minimum_delegation();
    let other = iface::instruction::get_minimum_delegation();

    let other_shape = IxShape { program: other.program_id.to_bytes(), data: other.data.clone(), metas: other.accounts.iter().map(|m| MetaShape { key: m.pubkey.to_bytes(), is_signer: m.is_signer, is_writable: m.is_writable }).collect() };
    assert_eq!(shape_from_sdk(&native), other_shape);
}

fn shapes_from_sdk_vec(v: &[SdkInstruction]) -> Vec<IxShape> {
    v.iter().map(shape_from_sdk).collect()
}

fn shapes_from_iface_vec(v: &[solana_instruction::Instruction]) -> Vec<IxShape> {
    v.iter().map(|ix| IxShape { program: ix.program_id.to_bytes(), data: ix.data.clone(), metas: ix.accounts.iter().map(|m| MetaShape { key: m.pubkey.to_bytes(), is_signer: m.is_signer, is_writable: m.is_writable }).collect() }).collect()
}

#[tokio::test]
async fn parity_split_bytes_and_metas() {
    let stake = Keypair::new().pubkey();
    let authority = Keypair::new().pubkey();
    let split_dest = Keypair::new().pubkey();
    let lamports: u64 = 12345;

    let native_vec = solana_sdk::stake::instruction::split(&stake, &authority, lamports, &split_dest);

    let stake_if = solana_pubkey::Pubkey::new_from_array(stake.to_bytes());
    let auth_if = solana_pubkey::Pubkey::new_from_array(authority.to_bytes());
    let dest_if = solana_pubkey::Pubkey::new_from_array(split_dest.to_bytes());
    let other_vec = iface::instruction::split(&stake_if, &auth_if, lamports, &dest_if);

    assert_eq!(shapes_from_sdk_vec(&native_vec), shapes_from_iface_vec(&other_vec));
}

#[tokio::test]
async fn parity_withdraw_bytes_and_metas() {
    let stake = Keypair::new().pubkey();
    let withdrawer = Keypair::new().pubkey();
    let recipient = Keypair::new().pubkey();
    let lamports: u64 = 777;

    let native = solana_sdk::stake::instruction::withdraw(
        &stake,
        &withdrawer,
        &recipient,
        lamports,
        None,
    );

    let stake_if = solana_pubkey::Pubkey::new_from_array(stake.to_bytes());
    let w_if = solana_pubkey::Pubkey::new_from_array(withdrawer.to_bytes());
    let r_if = solana_pubkey::Pubkey::new_from_array(recipient.to_bytes());
    let other = iface::instruction::withdraw(&stake_if, &w_if, &r_if, lamports, None);
    let other_shape = IxShape { program: other.program_id.to_bytes(), data: other.data.clone(), metas: other.accounts.iter().map(|m| MetaShape { key: m.pubkey.to_bytes(), is_signer: m.is_signer, is_writable: m.is_writable }).collect() };
    assert_eq!(shape_from_sdk(&native), other_shape);
}

#[tokio::test]
async fn parity_merge_bytes_and_metas() {
    let dest = Keypair::new().pubkey();
    let src = Keypair::new().pubkey();
    let authority = Keypair::new().pubkey();

    let native_vec = solana_sdk::stake::instruction::merge(&dest, &src, &authority);

    let dest_if = solana_pubkey::Pubkey::new_from_array(dest.to_bytes());
    let src_if = solana_pubkey::Pubkey::new_from_array(src.to_bytes());
    let auth_if = solana_pubkey::Pubkey::new_from_array(authority.to_bytes());
    let other_vec = iface::instruction::merge(&dest_if, &src_if, &auth_if);

    assert_eq!(shapes_from_sdk_vec(&native_vec), shapes_from_iface_vec(&other_vec));
}

#[tokio::test]
async fn parity_deactivate_delinquent_bytes_and_metas() {
    let stake = Keypair::new().pubkey();
    let delinquent = Keypair::new().pubkey();
    let reference = Keypair::new().pubkey();

    let native = solana_sdk::stake::instruction::deactivate_delinquent_stake(&stake, &delinquent, &reference);

    let stake_if = solana_pubkey::Pubkey::new_from_array(stake.to_bytes());
    let delinquent_if = solana_pubkey::Pubkey::new_from_array(delinquent.to_bytes());
    let reference_if = solana_pubkey::Pubkey::new_from_array(reference.to_bytes());
    let other = iface::instruction::deactivate_delinquent_stake(&stake_if, &delinquent_if, &reference_if);

    let other_shape = IxShape { program: other.program_id.to_bytes(), data: other.data.clone(), metas: other.accounts.iter().map(|m| MetaShape { key: m.pubkey.to_bytes(), is_signer: m.is_signer, is_writable: m.is_writable }).collect() };
    assert_eq!(shape_from_sdk(&native), other_shape);
}

#[tokio::test]
async fn parity_initialize_bytes_and_metas() {
    let stake = Keypair::new().pubkey();
    let staker = Keypair::new().pubkey();
    let withdrawer = Keypair::new().pubkey();
    let custodian = Keypair::new().pubkey();

    let native = solana_sdk::stake::instruction::initialize(
        &stake,
        &solana_sdk::stake::state::Authorized { staker, withdrawer },
        &solana_sdk::stake::state::Lockup { unix_timestamp: 11, epoch: 22, custodian },
    );

    let stake_if = solana_pubkey::Pubkey::new_from_array(stake.to_bytes());
    let staker_if = solana_pubkey::Pubkey::new_from_array(staker.to_bytes());
    let withdrawer_if = solana_pubkey::Pubkey::new_from_array(withdrawer.to_bytes());
    let custodian_if = solana_pubkey::Pubkey::new_from_array(custodian.to_bytes());
    let other = iface::instruction::initialize(
        &stake_if,
        &iface::state::Authorized { staker: staker_if, withdrawer: withdrawer_if },
        &iface::state::Lockup { unix_timestamp: 11, epoch: 22, custodian: custodian_if },
    );
    let other_shape = IxShape { program: other.program_id.to_bytes(), data: other.data.clone(), metas: other.accounts.iter().map(|m| MetaShape { key: m.pubkey.to_bytes(), is_signer: m.is_signer, is_writable: m.is_writable }).collect() };
    assert_eq!(shape_from_sdk(&native), other_shape);
}

#[tokio::test]
async fn parity_set_lockup_bytes_and_metas() {
    let stake = Keypair::new().pubkey();
    let custodian = Keypair::new().pubkey();
    let role_signer = Keypair::new().pubkey();

    let native = solana_sdk::stake::instruction::set_lockup(
        &stake,
        &solana_sdk::stake::instruction::LockupArgs { unix_timestamp: Some(5), epoch: Some(7), custodian: Some(custodian) },
        &role_signer,
    );

    let stake_if = solana_pubkey::Pubkey::new_from_array(stake.to_bytes());
    let cust_if = solana_pubkey::Pubkey::new_from_array(custodian.to_bytes());
    let role_if = solana_pubkey::Pubkey::new_from_array(role_signer.to_bytes());
    let other = iface::instruction::set_lockup(
        &stake_if,
        &iface::instruction::LockupArgs { unix_timestamp: Some(5), epoch: Some(7), custodian: Some(cust_if) },
        &role_if,
    );
    let other_shape = IxShape { program: other.program_id.to_bytes(), data: other.data.clone(), metas: other.accounts.iter().map(|m| MetaShape { key: m.pubkey.to_bytes(), is_signer: m.is_signer, is_writable: m.is_writable }).collect() };
    assert_eq!(shape_from_sdk(&native), other_shape);
}

#[tokio::test]
async fn parity_authorize_checked_with_seed_bytes_and_metas() {
    let stake = Keypair::new().pubkey();
    let base = Keypair::new().pubkey();
    let owner = Pubkey::new_unique();
    let new_auth = Keypair::new().pubkey();
    let seed = "abcd".to_string();

    let native = solana_sdk::stake::instruction::authorize_checked_with_seed(
        &stake,
        &base,
        seed.clone(),
        &owner,
        &new_auth,
        solana_sdk::stake::state::StakeAuthorize::Withdrawer,
        None,
    );

    let stake_if = solana_pubkey::Pubkey::new_from_array(stake.to_bytes());
    let base_if = solana_pubkey::Pubkey::new_from_array(base.to_bytes());
    let owner_if = solana_pubkey::Pubkey::new_from_array(owner.to_bytes());
    let new_if = solana_pubkey::Pubkey::new_from_array(new_auth.to_bytes());
    let other = iface::instruction::authorize_checked_with_seed(
        &stake_if,
        &base_if,
        seed.clone(),
        &owner_if,
        &new_if,
        iface::state::StakeAuthorize::Withdrawer,
        None,
    );
    let other_shape = IxShape { program: other.program_id.to_bytes(), data: other.data.clone(), metas: other.accounts.iter().map(|m| MetaShape { key: m.pubkey.to_bytes(), is_signer: m.is_signer, is_writable: m.is_writable }).collect() };
    assert_eq!(shape_from_sdk(&native), other_shape);
}

#[tokio::test]
async fn parity_move_stake_and_lamports_bytes_and_metas() {
    let src = Keypair::new().pubkey();
    let dst = Keypair::new().pubkey();
    let staker = Keypair::new().pubkey();
    let lamports: u64 = 42;

    // MoveStake
    let native_ms = solana_sdk::stake::instruction::move_stake(&src, &dst, &staker, lamports);
    let src_if = solana_pubkey::Pubkey::new_from_array(src.to_bytes());
    let dst_if = solana_pubkey::Pubkey::new_from_array(dst.to_bytes());
    let staker_if = solana_pubkey::Pubkey::new_from_array(staker.to_bytes());
    let other_ms = iface::instruction::move_stake(&src_if, &dst_if, &staker_if, lamports);
    let other_ms_shape = IxShape { program: other_ms.program_id.to_bytes(), data: other_ms.data.clone(), metas: other_ms.accounts.iter().map(|m| MetaShape { key: m.pubkey.to_bytes(), is_signer: m.is_signer, is_writable: m.is_writable }).collect() };
    assert_eq!(shape_from_sdk(&native_ms), other_ms_shape);

    // MoveLamports
    let native_ml = solana_sdk::stake::instruction::move_lamports(&src, &dst, &staker, lamports);
    let other_ml = iface::instruction::move_lamports(&src_if, &dst_if, &staker_if, lamports);
    let other_ml_shape = IxShape { program: other_ml.program_id.to_bytes(), data: other_ml.data.clone(), metas: other_ml.accounts.iter().map(|m| MetaShape { key: m.pubkey.to_bytes(), is_signer: m.is_signer, is_writable: m.is_writable }).collect() };
    assert_eq!(shape_from_sdk(&native_ml), other_ml_shape);
}
