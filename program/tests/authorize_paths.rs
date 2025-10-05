mod common;
use common::*;
use common::pin_adapter as ixn;
use solana_sdk::{
    instruction::{AccountMeta, Instruction},
    message::Message,
    pubkey::Pubkey,
    stake::state::{Authorized, StakeAuthorize},
    system_instruction,
};

async fn create_stake_account(ctx: &mut ProgramTestContext, lamports: u64, program_id: &Pubkey) -> Keypair {
    let stake = Keypair::new();
    let space = pinocchio_stake::state::stake_state_v2::StakeStateV2::ACCOUNT_SIZE as u64;
    let ix = system_instruction::create_account(&ctx.payer.pubkey(), &stake.pubkey(), lamports, space, program_id);
    let msg = Message::new(&[ix], Some(&ctx.payer.pubkey()));
    let mut tx = Transaction::new_unsigned(msg);
    tx.try_sign(&[&ctx.payer, &stake], ctx.last_blockhash).unwrap();
    ctx.banks_client.process_transaction(tx).await.unwrap();
    stake
}

#[tokio::test]
async fn authorize_checked_with_seed_base_not_signer_fails() {
    let mut pt = common::program_test();
    let mut ctx = pt.start_with_context().await;
    let program_id = Pubkey::new_from_array(pinocchio_stake::ID);

    // Prepare stake with staker = derived(base, seed, owner)
    let base = Keypair::new();
    let seed = "seed-acs-1";
    let owner = solana_sdk::system_program::id();
    let derived_staker = Pubkey::create_with_seed(&base.pubkey(), seed, &owner).unwrap();

    let rent = ctx.banks_client.get_rent().await.unwrap();
    let space = pinocchio_stake::state::stake_state_v2::StakeStateV2::ACCOUNT_SIZE as usize;
    let reserve = rent.minimum_balance(space);
    let stake = create_stake_account(&mut ctx, reserve, &program_id).await;

    // Initialize with staker = derived address
    let withdrawer = Keypair::new();
    let init_ix = ixn::initialize_checked(
        &stake.pubkey(),
        &Authorized { staker: derived_staker, withdrawer: withdrawer.pubkey() },
    );
    let msg = Message::new(&[init_ix], Some(&ctx.payer.pubkey()));
    let mut tx = Transaction::new_unsigned(msg);
    tx.try_sign(&[&ctx.payer, &withdrawer], ctx.last_blockhash).unwrap();
    ctx.banks_client.process_transaction(tx).await.unwrap();

    // Attempt checked-with-seed without base signer
    let new_staker = Keypair::new();
    let mut ix = ixn::authorize_checked_with_seed(
        &stake.pubkey(),
        &base.pubkey(),
        seed.to_string(),
        &owner,
        &new_staker.pubkey(),
        StakeAuthorize::Staker,
        None,
    );
    // Mark base meta as non-signer to simulate missing signature at runtime
    if let Some(pos) = ix.accounts.iter().position(|am| am.pubkey == base.pubkey()) {
        ix.accounts[pos].is_signer = false;
    }
    let msg = Message::new(&[ix], Some(&ctx.payer.pubkey()));
    let mut tx = Transaction::new_unsigned(msg);
    // Intentionally do NOT sign with base; only new staker signs (checked requires it)
    tx.try_sign(&[&ctx.payer, &new_staker], ctx.last_blockhash).unwrap();
    // Expect failure due to missing base signature
    assert!(ctx.banks_client.process_transaction(tx).await.is_err());
}

#[cfg(feature = "strict-authz")]
#[tokio::test]
async fn authorize_checked_with_seed_bad_derivation_fails() {
    let mut pt = common::program_test();
    let mut ctx = pt.start_with_context().await;
    let program_id = Pubkey::new_from_array(pinocchio_stake::ID);

    let base = Keypair::new();
    let seed = "seed-acs-2";
    let owner = solana_sdk::system_program::id();
    let good_derived = Pubkey::create_with_seed(&base.pubkey(), seed, &owner).unwrap();

    let rent = ctx.banks_client.get_rent().await.unwrap();
    let space = pinocchio_stake::state::stake_state_v2::StakeStateV2::ACCOUNT_SIZE as usize;
    let reserve = rent.minimum_balance(space);
    let stake = create_stake_account(&mut ctx, reserve, &program_id).await;

    let withdrawer = Keypair::new();
    let init_ix = ixn::initialize_checked(
        &stake.pubkey(),
        &Authorized { staker: good_derived, withdrawer: withdrawer.pubkey() },
    );
    let msg = Message::new(&[init_ix], Some(&ctx.payer.pubkey()));
    let mut tx = Transaction::new_unsigned(msg);
    tx.try_sign(&[&ctx.payer, &withdrawer], ctx.last_blockhash).unwrap();
    ctx.banks_client.process_transaction(tx).await.unwrap();

    // Use wrong seed -> derived != current staker
    let new_staker = Keypair::new();
    let wrong_seed = "wrong-seed";
    let mut ix = ixn::authorize_checked_with_seed(
        &stake.pubkey(),
        &base.pubkey(),
        wrong_seed.to_string(),
        &owner,
        &new_staker.pubkey(),
        StakeAuthorize::Staker,
        None,
    );
    let msg = Message::new(&[ix], Some(&ctx.payer.pubkey()));
    let mut tx = Transaction::new_unsigned(msg);
    tx.try_sign(&[&ctx.payer, &base, &new_staker], ctx.last_blockhash).unwrap();
    // Expect failure due to bad derivation
    assert!(ctx.banks_client.process_transaction(tx).await.is_err());
}

#[tokio::test]
async fn authorize_with_seed_base_not_signer_fails() {
    let mut pt = common::program_test();
    let mut ctx = pt.start_with_context().await;
    let program_id = Pubkey::new_from_array(pinocchio_stake::ID);

    let base = Keypair::new();
    let seed = "seed-aws-1";
    let owner = solana_sdk::system_program::id();
    let derived = Pubkey::create_with_seed(&base.pubkey(), seed, &owner).unwrap();

    let rent = ctx.banks_client.get_rent().await.unwrap();
    let space = pinocchio_stake::state::stake_state_v2::StakeStateV2::ACCOUNT_SIZE as usize;
    let reserve = rent.minimum_balance(space);
    let stake = create_stake_account(&mut ctx, reserve, &program_id).await;

    let withdrawer = Keypair::new();
    let init_ix = ixn::initialize_checked(
        &stake.pubkey(),
        &Authorized { staker: derived, withdrawer: withdrawer.pubkey() },
    );
    let msg = Message::new(&[init_ix], Some(&ctx.payer.pubkey()));
    let mut tx = Transaction::new_unsigned(msg);
    tx.try_sign(&[&ctx.payer, &withdrawer], ctx.last_blockhash).unwrap();
    ctx.banks_client.process_transaction(tx).await.unwrap();

    let new_staker = Keypair::new();
    let mut ix = ixn::authorize_with_seed(
        &stake.pubkey(),
        &base.pubkey(),
        seed.to_string(),
        &owner,
        &new_staker.pubkey(),
        StakeAuthorize::Staker,
        None,
    );
    if let Some(pos) = ix.accounts.iter().position(|am| am.pubkey == base.pubkey()) {
        ix.accounts[pos].is_signer = false;
    }
    let msg = Message::new(&[ix], Some(&ctx.payer.pubkey()));
    let mut tx = Transaction::new_unsigned(msg);
    // Do not sign with base
    tx.try_sign(&[&ctx.payer], ctx.last_blockhash).unwrap();
    // Expect failure when base did not sign
    assert!(ctx.banks_client.process_transaction(tx).await.is_err());
}

#[cfg(feature = "strict-authz")]
#[tokio::test]
async fn authorize_with_seed_withdrawer_lockup_requires_custodian() {
    let mut pt = common::program_test();
    let mut ctx = pt.start_with_context().await;
    let program_id = Pubkey::new_from_array(pinocchio_stake::ID);

    let base = Keypair::new();
    let seed = "seed-aws-2";
    let owner = solana_sdk::system_program::id();
    let derived_withdrawer = Pubkey::create_with_seed(&base.pubkey(), seed, &owner).unwrap();
    let custodian = Keypair::new();

    // Create stake with lockup in force (epoch = current_epoch + 10)
    let rent = ctx.banks_client.get_rent().await.unwrap();
    let space = pinocchio_stake::state::stake_state_v2::StakeStateV2::ACCOUNT_SIZE as usize;
    let reserve = rent.minimum_balance(space);
    let stake = create_stake_account(&mut ctx, reserve, &program_id).await;

    let clock = ctx.banks_client.get_sysvar::<solana_sdk::clock::Clock>().await.unwrap();
    let lockup = solana_sdk::stake::state::Lockup { unix_timestamp: 0, epoch: clock.epoch + 10, custodian: custodian.pubkey() };
    let init_ix = ixn::initialize(
        &stake.pubkey(),
        &Authorized { staker: Pubkey::new_unique(), withdrawer: derived_withdrawer },
        &lockup,
    );
    let msg = Message::new(&[init_ix], Some(&ctx.payer.pubkey()));
    let mut tx = Transaction::new_unsigned(msg);
    tx.try_sign(&[&ctx.payer], ctx.last_blockhash).unwrap();
    ctx.banks_client.process_transaction(tx).await.unwrap();

    // Attempt to change withdrawer without custodian signer -> fail
    let new_withdrawer = Keypair::new();
    let ix = ixn::authorize_with_seed(
        &stake.pubkey(),
        &base.pubkey(),
        seed.to_string(),
        &owner,
        &new_withdrawer.pubkey(),
        StakeAuthorize::Withdrawer,
        None,
    );
    let msg = Message::new(&[ix.clone()], Some(&ctx.payer.pubkey()));
    let mut tx = Transaction::new_unsigned(msg);
    tx.try_sign(&[&ctx.payer, &base], ctx.last_blockhash).unwrap();
    // Expect failure without custodian signer while lockup in force
    assert!(ctx.banks_client.process_transaction(tx).await.is_err());

    // Now include custodian as trailing signer account and sign -> succeed
    let mut ix2 = ix.clone();
    ix2.accounts.push(AccountMeta::new_readonly(custodian.pubkey(), true));
    let msg = Message::new(&[ix2], Some(&ctx.payer.pubkey()));
    let mut tx = Transaction::new_unsigned(msg);
    tx.try_sign(&[&ctx.payer, &base, &custodian], ctx.last_blockhash).unwrap();
    let res = ctx.banks_client.process_transaction(tx).await;
    assert!(res.is_ok(), "AuthorizeWithSeed withdrawer with custodian should succeed: {:?}", res);
}
