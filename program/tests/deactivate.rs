mod common;
use common::*;
use common::pin_adapter as ixn;
use solana_sdk::{
    message::Message,
    pubkey::Pubkey,
    system_instruction,
    stake::state::Authorized,
};
use std::str::FromStr;

fn vote_state_space() -> u64 {
    std::mem::size_of::<pinocchio_stake::state::vote_state::VoteState>() as u64
}

async fn create_dummy_vote_account(ctx: &mut ProgramTestContext, kp: &Keypair) {
    let rent = ctx.banks_client.get_rent().await.unwrap();
    let space = vote_state_space();
    let lamports = rent.minimum_balance(space as usize);
    // Use the real vote program ID as the owner to satisfy strict owner checks
    let vote_program_id = Pubkey::from_str("Vote111111111111111111111111111111111111111").unwrap();
    let ix = system_instruction::create_account(
        &ctx.payer.pubkey(),
        &kp.pubkey(),
        lamports,
        space,
        &vote_program_id,
    );
    let msg = Message::new(&[ix], Some(&ctx.payer.pubkey()));
    let mut tx = Transaction::new_unsigned(msg);
    tx.try_sign(&[&ctx.payer, kp], ctx.last_blockhash).unwrap();
    ctx.banks_client.process_transaction(tx).await.unwrap();
}

#[tokio::test]
async fn deactivate_success_after_delegate() {
    let mut pt = common::program_test();
    let mut ctx = pt.start_with_context().await;
    let program_id = Pubkey::new_from_array(pinocchio_stake::ID);

    // Stake authorities
    let staker = Keypair::new();
    let withdrawer = Keypair::new();

    // Create stake account
    let stake = Keypair::new();
    let rent = ctx.banks_client.get_rent().await.unwrap();
    let space = pinocchio_stake::state::stake_state_v2::StakeStateV2::ACCOUNT_SIZE as u64;
    let reserve = rent.minimum_balance(space as usize);
    let create_stake = system_instruction::create_account(
        &ctx.payer.pubkey(),
        &stake.pubkey(),
        reserve,
        space,
        &program_id,
    );
    let msg = Message::new(&[create_stake], Some(&ctx.payer.pubkey()));
    let mut tx = Transaction::new_unsigned(msg);
    tx.try_sign(&[&ctx.payer, &stake], ctx.last_blockhash).unwrap();
    ctx.banks_client.process_transaction(tx).await.unwrap();

    // InitializeChecked (withdrawer signs)
    let init_ix = ixn::initialize_checked(
        &stake.pubkey(),
        &Authorized { staker: staker.pubkey(), withdrawer: withdrawer.pubkey() },
    );
    let msg = Message::new(&[init_ix], Some(&ctx.payer.pubkey()));
    let mut tx = Transaction::new_unsigned(msg);
    tx.try_sign(&[&ctx.payer, &withdrawer], ctx.last_blockhash).unwrap();
    ctx.banks_client.process_transaction(tx).await.unwrap();

    // Create a dummy vote account with the in-crate VoteState layout
    let vote_acc = Keypair::new();
    create_dummy_vote_account(&mut ctx, &vote_acc).await;

    // Fund stake with at least the minimum delegation before delegating
    let min_del = common::get_minimum_delegation_lamports(&mut ctx).await;
    let fund_tx = Transaction::new_signed_with_payer(
        &[system_instruction::transfer(&ctx.payer.pubkey(), &stake.pubkey(), min_del)],
        Some(&ctx.payer.pubkey()),
        &[&ctx.payer],
        ctx.last_blockhash,
    );
    ctx.banks_client.process_transaction(fund_tx).await.unwrap();

    // DelegateStake to transition to Stake state
    let del_ix = ixn::delegate_stake(&stake.pubkey(), &staker.pubkey(), &vote_acc.pubkey());
    let msg = Message::new(&[del_ix], Some(&ctx.payer.pubkey()));
    let mut tx = Transaction::new_unsigned(msg);
    tx.try_sign(&[&ctx.payer, &staker], ctx.last_blockhash).unwrap();
    ctx.banks_client.process_transaction(tx).await.unwrap();

    // Deactivate: [stake, clock] + staker signer
    let deact_ix = ixn::deactivate_stake(&stake.pubkey(), &staker.pubkey());
    let msg = Message::new(&[deact_ix], Some(&ctx.payer.pubkey()));
    let mut tx = Transaction::new_unsigned(msg);
    tx.try_sign(&[&ctx.payer, &staker], ctx.last_blockhash).unwrap();
    let res = ctx.banks_client.process_transaction(tx).await;
    assert!(res.is_ok(), "Deactivate should succeed: {:?}", res);

    // Validate deactivation_epoch set to current epoch
    let clock = ctx.banks_client.get_sysvar::<solana_sdk::clock::Clock>().await.unwrap();
    let acct = ctx.banks_client.get_account(stake.pubkey()).await.unwrap().unwrap();
    let state = pinocchio_stake::state::stake_state_v2::StakeStateV2::deserialize(&acct.data).unwrap();
    match state {
        pinocchio_stake::state::stake_state_v2::StakeStateV2::Stake(_meta, stake_data, _flags) => {
            let deact = u64::from_le_bytes(stake_data.delegation.deactivation_epoch);
            assert_eq!(deact, clock.epoch, "deactivation epoch should match clock");
        }
        other => panic!("expected Stake state, got {:?}", other),
    }
}

#[tokio::test]
async fn deactivate_missing_staker_signature_fails() {
    let mut pt = common::program_test();
    let mut ctx = pt.start_with_context().await;
    let program_id = Pubkey::new_from_array(pinocchio_stake::ID);

    let staker = Keypair::new();
    let withdrawer = Keypair::new();
    let stake = Keypair::new();
    let rent = ctx.banks_client.get_rent().await.unwrap();
    let space = pinocchio_stake::state::stake_state_v2::StakeStateV2::ACCOUNT_SIZE as u64;
    let reserve = rent.minimum_balance(space as usize);
    let create_stake = system_instruction::create_account(
        &ctx.payer.pubkey(),
        &stake.pubkey(),
        reserve,
        space,
        &program_id,
    );
    let msg = Message::new(&[create_stake], Some(&ctx.payer.pubkey()));
    let mut tx = Transaction::new_unsigned(msg);
    tx.try_sign(&[&ctx.payer, &stake], ctx.last_blockhash).unwrap();
    ctx.banks_client.process_transaction(tx).await.unwrap();

    // InitializeChecked
    let init_ix = ixn::initialize_checked(
        &stake.pubkey(),
        &Authorized { staker: staker.pubkey(), withdrawer: withdrawer.pubkey() },
    );
    let msg = Message::new(&[init_ix], Some(&ctx.payer.pubkey()));
    let mut tx = Transaction::new_unsigned(msg);
    tx.try_sign(&[&ctx.payer, &withdrawer], ctx.last_blockhash).unwrap();
    ctx.banks_client.process_transaction(tx).await.unwrap();

    // Create dummy vote and fund stake above minimum, then delegate (with staker signature)
    let vote_acc = Keypair::new();
    create_dummy_vote_account(&mut ctx, &vote_acc).await;
    let min_del = common::get_minimum_delegation_lamports(&mut ctx).await;
    let fund_tx = Transaction::new_signed_with_payer(
        &[system_instruction::transfer(&ctx.payer.pubkey(), &stake.pubkey(), min_del)],
        Some(&ctx.payer.pubkey()),
        &[&ctx.payer],
        ctx.last_blockhash,
    );
    ctx.banks_client.process_transaction(fund_tx).await.unwrap();
    let del_ix = ixn::delegate_stake(&stake.pubkey(), &staker.pubkey(), &vote_acc.pubkey());
    let msg = Message::new(&[del_ix], Some(&ctx.payer.pubkey()));
    let mut tx = Transaction::new_unsigned(msg);
    tx.try_sign(&[&ctx.payer, &staker], ctx.last_blockhash).unwrap();
    ctx.banks_client.process_transaction(tx).await.unwrap();

    // Now attempt Deactivate WITHOUT staker signer present
    let mut deact_ix = ixn::deactivate_stake(&stake.pubkey(), &staker.pubkey());
    // Remove staker signer to simulate missing signature case
    deact_ix
        .accounts
        .retain(|am| am.pubkey != staker.pubkey());
    let msg = Message::new(&[deact_ix], Some(&ctx.payer.pubkey()));
    let mut tx = Transaction::new_unsigned(msg);
    tx.try_sign(&[&ctx.payer], ctx.last_blockhash).unwrap();
    let err = ctx.banks_client.process_transaction(tx).await.unwrap_err();

    match err {
        solana_program_test::BanksClientError::TransactionError(te) => {
            use solana_sdk::transaction::TransactionError;
            use solana_sdk::instruction::InstructionError;
            match te {
                TransactionError::InstructionError(_, InstructionError::MissingRequiredSignature) => {}
                TransactionError::InstructionError(_, InstructionError::Custom(_)) => {}
                other => panic!("unexpected transaction error: {:?}", other),
            }
        }
        other => panic!("unexpected banks client error: {:?}", other),
    }
}
