#![cfg(feature = "e2e")]
//! Ensure SetLockupChecked ignores extra non-signer metas and enforces the
//! role signer only at index 1, with optional new custodian at index 2.

mod common;
use common::*;
use solana_sdk::{instruction::{AccountMeta, Instruction}, message::Message};
use crate::common::pin_adapter as ixn;

#[tokio::test]
async fn set_lockup_checked_accepts_extra_non_signer_metas() {
    let mut pt = common::program_test();
    let mut ctx = pt.start_with_context().await;
    let program_id = Pubkey::new_from_array(pinocchio_stake::ID);

    let stake_acc = Keypair::new();
    let staker = Keypair::new();
    let withdrawer = Keypair::new();
    let rent = ctx.banks_client.get_rent().await.unwrap();
    let space = pinocchio_stake::state::stake_state_v2::StakeStateV2::ACCOUNT_SIZE as u64;
    let reserve = rent.minimum_balance(space as usize);
    let create = system_instruction::create_account(&ctx.payer.pubkey(), &stake_acc.pubkey(), reserve, space, &program_id);
    let tx = Transaction::new_signed_with_payer(&[create], Some(&ctx.payer.pubkey()), &[&ctx.payer, &stake_acc], ctx.last_blockhash);
    ctx.banks_client.process_transaction(tx).await.unwrap();

    // InitializeChecked
    let init_ix = ixn::initialize_checked(&stake_acc.pubkey(), &solana_sdk::stake::state::Authorized { staker: staker.pubkey(), withdrawer: withdrawer.pubkey() });
    let tx = Transaction::new_signed_with_payer(&[init_ix], Some(&ctx.payer.pubkey()), &[&ctx.payer, &withdrawer], ctx.last_blockhash);
    ctx.banks_client.process_transaction(tx).await.unwrap();

    // Build a SetLockupChecked with extra non-signer metas appended
    let args = solana_sdk::stake::instruction::LockupArgs { unix_timestamp: None, epoch: Some(2), custodian: None };
    let mut ix = ixn::set_lockup_checked(&stake_acc.pubkey(), &args, &withdrawer.pubkey());
    // Append extra non-signer metas (random accounts)
    let extra1 = Keypair::new().pubkey();
    let extra2 = Keypair::new().pubkey();
    ix.accounts.push(AccountMeta::new(extra1, false));
    ix.accounts.push(AccountMeta::new_readonly(extra2, false));

    let msg = Message::new(&[ix.clone()], Some(&ctx.payer.pubkey()));
    let tx = Transaction::new_signed_with_payer(&[ix], Some(&ctx.payer.pubkey()), &[&ctx.payer, &withdrawer], ctx.last_blockhash);
    assert!(ctx.banks_client.process_transaction(tx).await.is_ok());
}
