#![cfg(feature = "e2e")]
mod common;
use common::*;
use solana_sdk::{
    system_instruction,
    vote::{instruction as vote_instruction, state::{VoteInit, VoteStateV3, VoteStateVersions}},
};

async fn warp_one_epoch(ctx: &mut ProgramTestContext) {
    refresh_blockhash(ctx).await;
    let root_slot = ctx.banks_client.get_root_slot().await.unwrap();
    let slots_per_epoch = ctx.genesis_config().epoch_schedule.slots_per_epoch;
    ctx.warp_to_slot(root_slot + slots_per_epoch).unwrap();
}

async fn create_vote(ctx: &mut ProgramTestContext, node: &Keypair, voter: &Pubkey, withdrawer: &Pubkey, vote_account: &Keypair) {
    let rent = ctx.banks_client.get_rent().await.unwrap();
    let mut ixs = vec![system_instruction::create_account(&ctx.payer.pubkey(), &node.pubkey(), rent.minimum_balance(0), 0, &solana_sdk::system_program::id())];
    ixs.append(&mut vote_instruction::create_account_with_config(
        &ctx.payer.pubkey(),
        &vote_account.pubkey(),
        &VoteInit { node_pubkey: node.pubkey(), authorized_voter: *voter, authorized_withdrawer: *withdrawer, commission: 0 },
        rent.minimum_balance(VoteStateV3::size_of()),
        vote_instruction::CreateVoteAccountConfig { space: VoteStateV3::size_of() as u64, ..Default::default() },
    ));
    let tx = Transaction::new_signed_with_payer(&ixs, Some(&ctx.payer.pubkey()), &[node, vote_account, &ctx.payer], ctx.last_blockhash);
    let _ = ctx.banks_client.process_transaction(tx).await;
}

#[tokio::test]
async fn move_lamports_inactive_conserves_lamports_and_rent() {
    use crate::common::pin_adapter as ixn;
    let mut ctx = common::program_test().start_with_context().await;
    let program_id = Pubkey::new_from_array(pinocchio_stake::ID);

    let staker = Keypair::new();
    let withdrawer = Keypair::new();
    let rent = ctx.banks_client.get_rent().await.unwrap();
    let space = pinocchio_stake::state::stake_state_v2::StakeStateV2::ACCOUNT_SIZE as u64;
    let reserve = rent.minimum_balance(space as usize);
    let a = Keypair::new();
    let b = Keypair::new();
    for kp in [&a, &b] {
        let create = system_instruction::create_account(&ctx.payer.pubkey(), &kp.pubkey(), reserve, space, &program_id);
        let tx = Transaction::new_signed_with_payer(&[create], Some(&ctx.payer.pubkey()), &[&ctx.payer, kp], ctx.last_blockhash);
        ctx.banks_client.process_transaction(tx).await.unwrap();
        let init_ix = ixn::initialize_checked(&kp.pubkey(), &solana_sdk::stake::state::Authorized { staker: staker.pubkey(), withdrawer: withdrawer.pubkey() });
        let tx = Transaction::new_signed_with_payer(&[init_ix], Some(&ctx.payer.pubkey()), &[&ctx.payer, &withdrawer], ctx.last_blockhash);
        ctx.banks_client.process_transaction(tx).await.unwrap();
}

    let topup = reserve * 2;
    let pre_a = ctx.banks_client.get_account(a.pubkey()).await.unwrap().unwrap().lamports;
    let pre_b = ctx.banks_client.get_account(b.pubkey()).await.unwrap().unwrap().lamports;
    transfer(&mut ctx, &a.pubkey(), topup).await;
    let mid_a = ctx.banks_client.get_account(a.pubkey()).await.unwrap().unwrap().lamports;
    let free = mid_a.saturating_sub(reserve);
    let to_move = free / 2;

    let ix = ixn::move_lamports(&a.pubkey(), &b.pubkey(), &staker.pubkey(), to_move);
    let tx = Transaction::new_signed_with_payer(&[ix], Some(&ctx.payer.pubkey()), &[&ctx.payer, &staker], ctx.last_blockhash);
    ctx.banks_client.process_transaction(tx).await.unwrap();

    let post_a = ctx.banks_client.get_account(a.pubkey()).await.unwrap().unwrap().lamports;
    let post_b = ctx.banks_client.get_account(b.pubkey()).await.unwrap().unwrap().lamports;
    assert_eq!(pre_a + pre_b + topup, post_a + post_b);
    assert!(post_a >= reserve && post_b >= reserve);
}

#[tokio::test]
async fn move_stake_to_inactive_conserves_lamports_and_stake() {
    use crate::common::pin_adapter as ixn;
    let mut ctx = common::program_test().start_with_context().await;
    let program_id = Pubkey::new_from_array(pinocchio_stake::ID);

    let staker = Keypair::new();
    let withdrawer = Keypair::new();
    let node = Keypair::new();
    let voter_auth = Keypair::new();
    let withdrawer_auth = Keypair::new();
    let vote = Keypair::new();
    create_vote(&mut ctx, &node, &voter_auth.pubkey(), &withdrawer_auth.pubkey(), &vote).await;

    let rent = ctx.banks_client.get_rent().await.unwrap();
    let space = pinocchio_stake::state::stake_state_v2::StakeStateV2::ACCOUNT_SIZE as u64;
    let reserve = rent.minimum_balance(space as usize);
    let src = Keypair::new();
    let dst = Keypair::new();
    for kp in [&src, &dst] {
        let create = system_instruction::create_account(&ctx.payer.pubkey(), &kp.pubkey(), reserve, space, &program_id);
        let tx = Transaction::new_signed_with_payer(&[create], Some(&ctx.payer.pubkey()), &[&ctx.payer, kp], ctx.last_blockhash);
        ctx.banks_client.process_transaction(tx).await.unwrap();
        let init_ix = ixn::initialize_checked(&kp.pubkey(), &solana_sdk::stake::state::Authorized { staker: staker.pubkey(), withdrawer: withdrawer.pubkey() });
        let tx = Transaction::new_signed_with_payer(&[init_ix], Some(&ctx.payer.pubkey()), &[&ctx.payer, &withdrawer], ctx.last_blockhash);
        ctx.banks_client.process_transaction(tx).await.unwrap();
}

    // Fund source with stake balance and delegate
    let min = common::get_minimum_delegation_lamports(&mut ctx).await;
    transfer(&mut ctx, &src.pubkey(), reserve + min * 2).await;
    let del_ix = ixn::delegate_stake(&src.pubkey(), &staker.pubkey(), &vote.pubkey());
    let tx = Transaction::new_signed_with_payer(&[del_ix], Some(&ctx.payer.pubkey()), &[&ctx.payer, &staker], ctx.last_blockhash);
    ctx.banks_client.process_transaction(tx).await.unwrap();

    // Activate (warp one epoch)
    warp_one_epoch(&mut ctx).await;

    // Pre balances
    let pre_src = ctx.banks_client.get_account(src.pubkey()).await.unwrap().unwrap().lamports;
    let pre_dst = ctx.banks_client.get_account(dst.pubkey()).await.unwrap().unwrap().lamports;

    // Move exactly one minimum delegation to inactive destination
    let mv = min;
    let ix = ixn::move_stake(&src.pubkey(), &dst.pubkey(), &staker.pubkey(), mv);
    let tx = Transaction::new_signed_with_payer(&[ix], Some(&ctx.payer.pubkey()), &[&ctx.payer, &staker], ctx.last_blockhash);
    ctx.banks_client.process_transaction(tx).await.unwrap();

    let post_src = ctx.banks_client.get_account(src.pubkey()).await.unwrap().unwrap().lamports;
    let post_dst = ctx.banks_client.get_account(dst.pubkey()).await.unwrap().unwrap().lamports;
    assert_eq!(pre_src + pre_dst, post_src + post_dst, "lamports conserved");

    // Check stake states: src reduced by mv, dst created with mv
    use pinocchio_stake::state::stake_state_v2::StakeStateV2 as SS;
    let src_acc = ctx.banks_client.get_account(src.pubkey()).await.unwrap().unwrap();
    let dst_acc = ctx.banks_client.get_account(dst.pubkey()).await.unwrap().unwrap();
    let src_st = SS::deserialize(&src_acc.data).unwrap();
    let dst_st = SS::deserialize(&dst_acc.data).unwrap();
    match src_st {
        SS::Stake(_, src_stake, _) => {
            let s = u64::from_le_bytes(src_stake.delegation.stake);
            assert!(s >= min, "source remains at or above minimum");
        }
        _ => panic!("unexpected src state"),
    }
    match dst_st {
        SS::Stake(_, dst_stake, _) => {
            let d = u64::from_le_bytes(dst_stake.delegation.stake);
            assert_eq!(d, mv);
        }
        _ => panic!("unexpected dst state"),
    }
}

#[tokio::test]
async fn move_stake_active_to_active_same_voter_conserves_totals() {
    use crate::common::pin_adapter as ixn;
    let mut ctx = common::program_test().start_with_context().await;
    let program_id = Pubkey::new_from_array(pinocchio_stake::ID);

    // Authorities and vote
    let staker = Keypair::new();
    let withdrawer = Keypair::new();
    let node = Keypair::new();
    let voter_auth = Keypair::new();
    let withdrawer_auth = Keypair::new();
    let vote = Keypair::new();
    create_vote(&mut ctx, &node, &voter_auth.pubkey(), &withdrawer_auth.pubkey(), &vote).await;

    // Create source and dest stake accounts
    let rent = ctx.banks_client.get_rent().await.unwrap();
    let space = pinocchio_stake::state::stake_state_v2::StakeStateV2::ACCOUNT_SIZE as u64;
    let reserve = rent.minimum_balance(space as usize);
    let src = Keypair::new();
    let dst = Keypair::new();
    for kp in [&src, &dst] {
        let create = system_instruction::create_account(&ctx.payer.pubkey(), &kp.pubkey(), reserve, space, &program_id);
        let tx = Transaction::new_signed_with_payer(&[create], Some(&ctx.payer.pubkey()), &[&ctx.payer, kp], ctx.last_blockhash);
        ctx.banks_client.process_transaction(tx).await.unwrap();
        let init_ix = ixn::initialize_checked(&kp.pubkey(), &solana_sdk::stake::state::Authorized { staker: staker.pubkey(), withdrawer: withdrawer.pubkey() });
        let tx = Transaction::new_signed_with_payer(&[init_ix], Some(&ctx.payer.pubkey()), &[&ctx.payer, &withdrawer], ctx.last_blockhash);
        ctx.banks_client.process_transaction(tx).await.unwrap();
    }

    let min = common::get_minimum_delegation_lamports(&mut ctx).await;
    // Fund and delegate both to same vote
    transfer(&mut ctx, &src.pubkey(), reserve + min * 2).await;
    transfer(&mut ctx, &dst.pubkey(), reserve + min).await;
    for kp in [&src, &dst] {
        let del_ix = ixn::delegate_stake(&kp.pubkey(), &staker.pubkey(), &vote.pubkey());
        let tx = Transaction::new_signed_with_payer(&[del_ix], Some(&ctx.payer.pubkey()), &[&ctx.payer, &staker], ctx.last_blockhash);
        ctx.banks_client.process_transaction(tx).await.unwrap();
    }
    warp_one_epoch(&mut ctx).await;

    let pre_src_acc = ctx.banks_client.get_account(src.pubkey()).await.unwrap().unwrap();
    let pre_dst_acc = ctx.banks_client.get_account(dst.pubkey()).await.unwrap().unwrap();
    let pre_total = pre_src_acc.lamports + pre_dst_acc.lamports;

    let mv = min;
    let ix = ixn::move_stake(&src.pubkey(), &dst.pubkey(), &staker.pubkey(), mv);
    let tx = Transaction::new_signed_with_payer(&[ix], Some(&ctx.payer.pubkey()), &[&ctx.payer, &staker], ctx.last_blockhash);
    ctx.banks_client.process_transaction(tx).await.unwrap();

    let post_src_acc = ctx.banks_client.get_account(src.pubkey()).await.unwrap().unwrap();
    let post_dst_acc = ctx.banks_client.get_account(dst.pubkey()).await.unwrap().unwrap();
    let post_total = post_src_acc.lamports + post_dst_acc.lamports;
    assert_eq!(pre_total, post_total);

    // Check stake shares moved
    use pinocchio_stake::state::stake_state_v2::StakeStateV2 as SS;
    match (SS::deserialize(&post_src_acc.data).unwrap(), SS::deserialize(&post_dst_acc.data).unwrap()) {
        (SS::Stake(_, src_stake, _), SS::Stake(_, dst_stake, _)) => {
            let s = u64::from_le_bytes(src_stake.delegation.stake);
            let d = u64::from_le_bytes(dst_stake.delegation.stake);
            assert!(d >= min);
            assert!(s >= min);
        }
        other => panic!("unexpected states: {:?}", other),
    }
    }
