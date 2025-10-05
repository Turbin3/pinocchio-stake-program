mod common;
use common::*;
use common::pin_adapter as ixn;
use solana_sdk::stake::state::Authorized;
use solana_sdk::{
    instruction::{AccountMeta, Instruction},
    message::Message,
    pubkey::Pubkey,
    system_instruction,
};

#[tokio::test]
async fn move_lamports_from_inactive_source() {
    let mut pt = common::program_test();
    let mut ctx = pt.start_with_context().await;
    let program_id = Pubkey::new_from_array(pinocchio_stake::ID);

    // Authorities shared by both stake accounts
    let staker = Keypair::new();
    let withdrawer = Keypair::new();

    // Create two stake accounts with identical authorities, Initialized but not delegated (Inactive)
    let rent = ctx.banks_client.get_rent().await.unwrap();
    let space = pinocchio_stake::state::stake_state_v2::StakeStateV2::ACCOUNT_SIZE as u64;
    let reserve = rent.minimum_balance(space as usize);

    let source = Keypair::new();
    let dest = Keypair::new();

    for kp in [&source, &dest] {
        let create = system_instruction::create_account(
            &ctx.payer.pubkey(),
            &kp.pubkey(),
            reserve,
            space,
            &program_id,
        );
        let msg = Message::new(&[create], Some(&ctx.payer.pubkey()));
        let mut tx = Transaction::new_unsigned(msg);
        tx.try_sign(&[&ctx.payer, kp], ctx.last_blockhash).unwrap();
        ctx.banks_client.process_transaction(tx).await.unwrap();

        // InitializeChecked to set authorities (use adapter)
        let auth = Authorized { staker: staker.pubkey(), withdrawer: withdrawer.pubkey() };
        let init_ix = ixn::initialize_checked(&kp.pubkey(), &auth);
        let msg = Message::new(&[init_ix], Some(&ctx.payer.pubkey()));
        let mut tx = Transaction::new_unsigned(msg);
        tx.try_sign(&[&ctx.payer, &withdrawer], ctx.last_blockhash).unwrap();
        ctx.banks_client.process_transaction(tx).await.unwrap();
    }

    // Prefund source above reserve so there are free lamports to move
    let extra: u64 = reserve / 2 + 1_000_000; // ensure > 0 free
    let fund_tx = Transaction::new_signed_with_payer(
        &[system_instruction::transfer(
            &ctx.payer.pubkey(),
            &source.pubkey(),
            extra,
        )],
        Some(&ctx.payer.pubkey()),
        &[&ctx.payer],
        ctx.last_blockhash,
    );
    ctx.banks_client.process_transaction(fund_tx).await.unwrap();

    // Record balances before
    let src_before = ctx
        .banks_client
        .get_account(source.pubkey())
        .await
        .unwrap()
        .unwrap()
        .lamports;
    let dst_before = ctx
        .banks_client
        .get_account(dest.pubkey())
        .await
        .unwrap()
        .unwrap()
        .lamports;

    let amount = extra / 2; // should be <= free lamports

    // Build MoveLamports via adapter (re-encodes data and accounts)
    let ix = ixn::move_lamports(&source.pubkey(), &dest.pubkey(), &staker.pubkey(), amount);

    let msg = Message::new(&[ix], Some(&ctx.payer.pubkey()));
    let mut tx = Transaction::new_unsigned(msg);
    tx.try_sign(&[&ctx.payer, &staker], ctx.last_blockhash).unwrap();
    let res = ctx.banks_client.process_transaction(tx).await;
    assert!(res.is_ok(), "MoveLamports should succeed: {:?}", res);

    // Verify balances moved
    let src_after = ctx
        .banks_client
        .get_account(source.pubkey())
        .await
        .unwrap()
        .unwrap()
        .lamports;
    let dst_after = ctx
        .banks_client
        .get_account(dest.pubkey())
        .await
        .unwrap()
        .unwrap()
        .lamports;

    assert_eq!(src_before - amount, src_after);
    assert_eq!(dst_before + amount, dst_after);
}

#[tokio::test]
async fn move_lamports_fails_if_staker_not_third_account() {
    let mut pt = common::program_test();
    let mut ctx = pt.start_with_context().await;
    let program_id = Pubkey::new_from_array(pinocchio_stake::ID);

    // Shared authorities
    let staker = Keypair::new();
    let withdrawer = Keypair::new();

    // Create Initialized source/dest with same authorities
    let rent = ctx.banks_client.get_rent().await.unwrap();
    let space = pinocchio_stake::state::stake_state_v2::StakeStateV2::ACCOUNT_SIZE as u64;
    let reserve = rent.minimum_balance(space as usize);

    let source = Keypair::new();
    let dest = Keypair::new();

    for kp in [&source, &dest] {
        let create = system_instruction::create_account(
            &ctx.payer.pubkey(),
            &kp.pubkey(),
            reserve,
            space,
            &program_id,
        );
        let msg = Message::new(&[create], Some(&ctx.payer.pubkey()));
        let mut tx = Transaction::new_unsigned(msg);
        tx.try_sign(&[&ctx.payer, kp], ctx.last_blockhash).unwrap();
        ctx.banks_client.process_transaction(tx).await.unwrap();

        // InitializeChecked to set authorities (use adapter)
        let auth = Authorized { staker: staker.pubkey(), withdrawer: withdrawer.pubkey() };
        let init_ix = ixn::initialize_checked(&kp.pubkey(), &auth);
        let msg = Message::new(&[init_ix], Some(&ctx.payer.pubkey()));
        let mut tx = Transaction::new_unsigned(msg);
        tx.try_sign(&[&ctx.payer, &withdrawer], ctx.last_blockhash).unwrap();
        ctx.banks_client.process_transaction(tx).await.unwrap();
    }

    // Prefund source with withdrawable lamports
    let extra: u64 = reserve / 2 + 10_000;
    let fund_tx = Transaction::new_signed_with_payer(
        &[system_instruction::transfer(
            &ctx.payer.pubkey(),
            &source.pubkey(),
            extra,
        )],
        Some(&ctx.payer.pubkey()),
        &[&ctx.payer],
        ctx.last_blockhash,
    );
    ctx.banks_client.process_transaction(fund_tx).await.unwrap();

    // Build MoveLamports data via adapter, but override account metas to place
    // a non-staker signer at index 2, and the real staker at index 3
    let amount = extra / 3;
    let template_ix = ixn::move_lamports(&source.pubkey(), &dest.pubkey(), &staker.pubkey(), amount);
    let mut accounts = Vec::new();
    accounts.push(AccountMeta::new(source.pubkey(), false));
    accounts.push(AccountMeta::new(dest.pubkey(), false));
    // Wrong signer in third position (withdrawer), real staker placed fourth
    accounts.push(AccountMeta::new_readonly(withdrawer.pubkey(), true));
    accounts.push(AccountMeta::new_readonly(staker.pubkey(), true));

    let ix = Instruction { program_id, accounts, data: template_ix.data };
    let msg = Message::new(&[ix], Some(&ctx.payer.pubkey()));
    let mut tx = Transaction::new_unsigned(msg);
    // Sign by both withdrawer (wrong third) and staker (correct but not third)
    tx.try_sign(&[&ctx.payer, &withdrawer, &staker], ctx.last_blockhash).unwrap();
    let res = ctx.banks_client.process_transaction(tx).await;
    assert!(res.is_err(), "MoveLamports must fail if staker not third: {:?}", res);
}
