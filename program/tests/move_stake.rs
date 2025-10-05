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

async fn create_vote_like_account(ctx: &mut ProgramTestContext, kp: &Keypair) {
    let rent = ctx.banks_client.get_rent().await.unwrap();
    let space = std::mem::size_of::<pinocchio_stake::state::vote_state::VoteState>() as u64;
    let lamports = rent.minimum_balance(space as usize);
    // Set the owner to the real Vote program to satisfy strict owner check
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

async fn setup_active_stake(
    ctx: &mut ProgramTestContext,
    program_id: &Pubkey,
    staker: &Keypair,
    withdrawer: &Keypair,
    vote_pubkey: &Pubkey,
    extra: u64,
) -> Keypair {
    let rent = ctx.banks_client.get_rent().await.unwrap();
    let space = pinocchio_stake::state::stake_state_v2::StakeStateV2::ACCOUNT_SIZE as u64;
    let reserve = rent.minimum_balance(space as usize);
    let kp = Keypair::new();
    let create = system_instruction::create_account(&ctx.payer.pubkey(), &kp.pubkey(), reserve, space, program_id);
    let msg = Message::new(&[create], Some(&ctx.payer.pubkey()));
    let mut tx = Transaction::new_unsigned(msg);
    tx.try_sign(&[&ctx.payer, &kp], ctx.last_blockhash).unwrap();
    ctx.banks_client.process_transaction(tx).await.unwrap();

    let init_ix = ixn::initialize_checked(
        &kp.pubkey(),
        &Authorized { staker: staker.pubkey(), withdrawer: withdrawer.pubkey() },
    );
    let msg = Message::new(&[init_ix], Some(&ctx.payer.pubkey()));
    let mut tx = Transaction::new_unsigned(msg);
    tx.try_sign(&[&ctx.payer, withdrawer], ctx.last_blockhash).unwrap();
    ctx.banks_client.process_transaction(tx).await.unwrap();

    // Ensure we fund with at least the minimum delegation so delegate succeeds
    let minimum = crate::common::get_minimum_delegation_lamports(ctx).await;
    let extra = core::cmp::max(extra, minimum);
    if extra > 0 {
        let fund_tx = Transaction::new_signed_with_payer(
            &[system_instruction::transfer(&ctx.payer.pubkey(), &kp.pubkey(), extra)],
            Some(&ctx.payer.pubkey()),
            &[&ctx.payer],
            ctx.last_blockhash,
        );
        ctx.banks_client.process_transaction(fund_tx).await.unwrap();
    }

    let del_ix = ixn::delegate_stake(&kp.pubkey(), &staker.pubkey(), vote_pubkey);
    let msg = Message::new(&[del_ix], Some(&ctx.payer.pubkey()));
    let mut tx = Transaction::new_unsigned(msg);
    tx.try_sign(&[&ctx.payer, staker], ctx.last_blockhash).unwrap();
    ctx.banks_client.process_transaction(tx).await.unwrap();

    kp
}

#[tokio::test]
async fn move_stake_between_active_same_vote() {
    let mut pt = common::program_test();
    let mut ctx = pt.start_with_context().await;
    let program_id = Pubkey::new_from_array(pinocchio_stake::ID);

    let staker = Keypair::new();
    let withdrawer = Keypair::new();

    // Create a shared vote account
    let vote = Keypair::new();
    create_vote_like_account(&mut ctx, &vote).await;

    // Create active source and destination using the helper
    let source_extra = 3_000_000u64;
    let dest_extra = 1_000_000u64;
    let vote_pk = vote.pubkey();
    let source = setup_active_stake(&mut ctx, &program_id, &staker, &withdrawer, &vote_pk, source_extra).await;
    let dest = setup_active_stake(&mut ctx, &program_id, &staker, &withdrawer, &vote_pk, dest_extra).await;

    // Advance multiple epochs so both stakes fully activate per history
    let slots_per_epoch = ctx.genesis_config().epoch_schedule.slots_per_epoch;
    let mut root_slot = ctx.banks_client.get_root_slot().await.unwrap();
    for _ in 0..64 {
        root_slot += slots_per_epoch;
        ctx.warp_to_slot(root_slot).unwrap();
    }

    // Move a portion from source to dest
    let amount = 500_000u64;
    let src_before = ctx.banks_client.get_account(source.pubkey()).await.unwrap().unwrap();
    let dst_before = ctx.banks_client.get_account(dest.pubkey()).await.unwrap().unwrap();

    let ix = ixn::move_stake(&source.pubkey(), &dest.pubkey(), &staker.pubkey(), amount);
    let msg = Message::new(&[ix], Some(&ctx.payer.pubkey()));
    let mut tx = Transaction::new_unsigned(msg);
    tx.try_sign(&[&ctx.payer, &staker], ctx.last_blockhash).unwrap();
    let res = ctx.banks_client.process_transaction(tx).await;
    assert!(res.is_ok(), "MoveStake should succeed: {:?}", res);

    // Check lamports movement
    let src_after = ctx.banks_client.get_account(source.pubkey()).await.unwrap().unwrap();
    let dst_after = ctx.banks_client.get_account(dest.pubkey()).await.unwrap().unwrap();
    assert_eq!(src_before.lamports - amount, src_after.lamports);
    assert_eq!(dst_before.lamports + amount, dst_after.lamports);

    // Check stake amounts updated
    let src_state = pinocchio_stake::state::stake_state_v2::StakeStateV2::deserialize(&src_after.data).unwrap();
    let dst_state = pinocchio_stake::state::stake_state_v2::StakeStateV2::deserialize(&dst_after.data).unwrap();
    match (src_state, dst_state) {
        (
            pinocchio_stake::state::stake_state_v2::StakeStateV2::Stake(_m1, s_stake, _),
            pinocchio_stake::state::stake_state_v2::StakeStateV2::Stake(_m2, d_stake, _),
        ) => {
            let s_amt = u64::from_le_bytes(s_stake.delegation.stake);
            let d_amt = u64::from_le_bytes(d_stake.delegation.stake);
            assert_eq!(s_amt, source_extra - amount);
            assert_eq!(d_amt, dest_extra + amount);
            assert_eq!(s_stake.delegation.voter_pubkey, vote_pk.to_bytes());
            assert_eq!(d_stake.delegation.voter_pubkey, vote_pk.to_bytes());
        }
        other => panic!("unexpected states: {:?}", other),
    }
}

#[tokio::test]
async fn move_stake_to_inactive_destination_success() {
    let mut pt = common::program_test();
    let mut ctx = pt.start_with_context().await;
    let program_id = Pubkey::new_from_array(pinocchio_stake::ID);

    let staker = Keypair::new();
    let withdrawer = Keypair::new();

    // Vote account
    let vote = Keypair::new();
    create_vote_like_account(&mut ctx, &vote).await;

    // Source: active with extra
    let rent = ctx.banks_client.get_rent().await.unwrap();
    let space = pinocchio_stake::state::stake_state_v2::StakeStateV2::ACCOUNT_SIZE as u64;
    let reserve = rent.minimum_balance(space as usize);
    let source = Keypair::new();
    let create_src = system_instruction::create_account(&ctx.payer.pubkey(), &source.pubkey(), reserve, space, &program_id);
    let msg = Message::new(&[create_src], Some(&ctx.payer.pubkey()));
    let mut tx = Transaction::new_unsigned(msg);
    tx.try_sign(&[&ctx.payer, &source], ctx.last_blockhash).unwrap();
    ctx.banks_client.process_transaction(tx).await.unwrap();

    let init_src = ixn::initialize_checked(
        &source.pubkey(),
        &Authorized { staker: staker.pubkey(), withdrawer: withdrawer.pubkey() },
    );
    let msg = Message::new(&[init_src], Some(&ctx.payer.pubkey()));
    let mut tx = Transaction::new_unsigned(msg);
    tx.try_sign(&[&ctx.payer, &withdrawer], ctx.last_blockhash).unwrap();
    ctx.banks_client.process_transaction(tx).await.unwrap();

    let extra_src = 2_000_000u64;
    let fund_tx = Transaction::new_signed_with_payer(
        &[system_instruction::transfer(&ctx.payer.pubkey(), &source.pubkey(), extra_src)],
        Some(&ctx.payer.pubkey()),
        &[&ctx.payer],
        ctx.last_blockhash,
    );
    ctx.banks_client.process_transaction(fund_tx).await.unwrap();

    let del_src = ixn::delegate_stake(&source.pubkey(), &staker.pubkey(), &vote.pubkey());
    let msg = Message::new(&[del_src], Some(&ctx.payer.pubkey()));
    let mut tx = Transaction::new_unsigned(msg);
    tx.try_sign(&[&ctx.payer, &staker], ctx.last_blockhash).unwrap();
    ctx.banks_client.process_transaction(tx).await.unwrap();

    // Destination: Initialized (inactive), same authorities
    let dest = Keypair::new();
    let create_dest = system_instruction::create_account(&ctx.payer.pubkey(), &dest.pubkey(), reserve, space, &program_id);
    let msg = Message::new(&[create_dest], Some(&ctx.payer.pubkey()));
    let mut tx = Transaction::new_unsigned(msg);
    tx.try_sign(&[&ctx.payer, &dest], ctx.last_blockhash).unwrap();
    ctx.banks_client.process_transaction(tx).await.unwrap();

    let init_dest = ixn::initialize_checked(
        &dest.pubkey(),
        &Authorized { staker: staker.pubkey(), withdrawer: withdrawer.pubkey() },
    );
    let msg = Message::new(&[init_dest], Some(&ctx.payer.pubkey()));
    let mut tx = Transaction::new_unsigned(msg);
    tx.try_sign(&[&ctx.payer, &withdrawer], ctx.last_blockhash).unwrap();
    ctx.banks_client.process_transaction(tx).await.unwrap();

    // Advance multiple epochs so source becomes fully active
    let slots_per_epoch = ctx.genesis_config().epoch_schedule.slots_per_epoch;
    let mut root_slot = ctx.banks_client.get_root_slot().await.unwrap();
    for _ in 0..64 {
        root_slot += slots_per_epoch;
        ctx.warp_to_slot(root_slot).unwrap();
    }

    // Move stake into inactive destination
    let amount = 400_000u64;
    let src_before = ctx.banks_client.get_account(source.pubkey()).await.unwrap().unwrap();
    let dst_before = ctx.banks_client.get_account(dest.pubkey()).await.unwrap().unwrap();

    let ix = ixn::move_stake(&source.pubkey(), &dest.pubkey(), &staker.pubkey(), amount);
    let msg = Message::new(&[ix], Some(&ctx.payer.pubkey()));
    let mut tx = Transaction::new_unsigned(msg);
    tx.try_sign(&[&ctx.payer, &staker], ctx.last_blockhash).unwrap();
    let res = ctx.banks_client.process_transaction(tx).await;
    assert!(res.is_ok(), "MoveStake to inactive should succeed: {:?}", res);

    let src_after = ctx.banks_client.get_account(source.pubkey()).await.unwrap().unwrap();
    let dst_after = ctx.banks_client.get_account(dest.pubkey()).await.unwrap().unwrap();
    assert_eq!(src_before.lamports - amount, src_after.lamports);
    assert_eq!(dst_before.lamports + amount, dst_after.lamports);

    let dst_state = pinocchio_stake::state::stake_state_v2::StakeStateV2::deserialize(&dst_after.data).unwrap();
    match dst_state {
        pinocchio_stake::state::stake_state_v2::StakeStateV2::Stake(_m, s, _f) => {
            assert_eq!(u64::from_le_bytes(s.delegation.stake), amount);
            assert_eq!(s.delegation.voter_pubkey, vote.pubkey().to_bytes());
        }
        other => panic!("destination should be Stake after move: {:?}", other),
    }
}

#[tokio::test]
async fn move_stake_vote_mismatch_fails() {
    let mut pt = common::program_test();
    let mut ctx = pt.start_with_context().await;
    let program_id = Pubkey::new_from_array(pinocchio_stake::ID);

    let staker = Keypair::new();
    let withdrawer = Keypair::new();

    // Two different vote accounts
    let vote_a = Keypair::new();
    let vote_b = Keypair::new();
    create_vote_like_account(&mut ctx, &vote_a).await;
    create_vote_like_account(&mut ctx, &vote_b).await;

    let source = setup_active_stake(&mut ctx, &program_id, &staker, &withdrawer, &vote_a.pubkey(), 2_000_000).await;
    let dest = setup_active_stake(&mut ctx, &program_id, &staker, &withdrawer, &vote_b.pubkey(), 1_000_000).await;

    // Attempt move -> should fail due to vote mismatch
    let amount = 100_000u64;
    let ix = ixn::move_stake(&source.pubkey(), &dest.pubkey(), &staker.pubkey(), amount);
    let msg = Message::new(&[ix], Some(&ctx.payer.pubkey()));
    let mut tx = Transaction::new_unsigned(msg);
    tx.try_sign(&[&ctx.payer, &staker], ctx.last_blockhash).unwrap();
    let err = ctx.banks_client.process_transaction(tx).await.unwrap_err();
    match err {
        solana_program_test::BanksClientError::TransactionError(te) => {
            // Just assert it failed; specific custom code depends on mapping
            assert!(matches!(te, solana_sdk::transaction::TransactionError::InstructionError(_, _)));
        }
        other => panic!("unexpected banks client error: {:?}", other),
    }
}

#[tokio::test]
async fn move_stake_zero_amount_fails() {
    let mut pt = common::program_test();
    let mut ctx = pt.start_with_context().await;
    let program_id = Pubkey::new_from_array(pinocchio_stake::ID);

    let staker = Keypair::new();
    let withdrawer = Keypair::new();
    let vote = Keypair::new();
    create_vote_like_account(&mut ctx, &vote).await;

    let vote_pk = vote.pubkey();
    let source = setup_active_stake(&mut ctx, &program_id, &staker, &withdrawer, &vote_pk, 1_000_000).await;
    let dest = setup_active_stake(&mut ctx, &program_id, &staker, &withdrawer, &vote_pk, 1_000_000).await;

    // Attempt amount=0 -> InvalidArgument
    let ix = ixn::move_stake(&source.pubkey(), &dest.pubkey(), &staker.pubkey(), 0);
    let msg = Message::new(&[ix], Some(&ctx.payer.pubkey()));
    let mut tx = Transaction::new_unsigned(msg);
    tx.try_sign(&[&ctx.payer, &staker], ctx.last_blockhash).unwrap();
    let err = ctx.banks_client.process_transaction(tx).await.unwrap_err();
    match err {
        solana_program_test::BanksClientError::TransactionError(te) => {
            use solana_sdk::instruction::InstructionError;
            use solana_sdk::transaction::TransactionError;
            match te {
                TransactionError::InstructionError(_, InstructionError::InvalidArgument) => {}
                TransactionError::InstructionError(_, InstructionError::Custom(_)) => {}
                other => panic!("unexpected error: {:?}", other),
            }
        }
        other => panic!("unexpected banks client error: {:?}", other),
    }
}
