#![cfg(feature = "e2e")]
//! Return-data contracts

mod common;
use common::*;

#[tokio::test]
async fn get_minimum_delegation_returns_8_le_bytes() {
    use crate::common::pin_adapter as ixn;
    let mut pt = common::program_test();
    let mut ctx = pt.start_with_context().await;

    let ix = ixn::get_minimum_delegation();
    let tx = Transaction::new_signed_with_payer(&[ix], Some(&ctx.payer.pubkey()), &[&ctx.payer], ctx.last_blockhash);
    let sim = ctx.banks_client.simulate_transaction(tx).await.unwrap();
    let rd = sim.simulation_details.unwrap().return_data.expect("no return data");
    assert_eq!(rd.program_id, solana_sdk::stake::program::id());
    assert_eq!(rd.data.len(), 8, "must be exactly 8 bytes");
    let mut buf = [0u8;8]; buf.copy_from_slice(&rd.data);
    let val = u64::from_le_bytes(buf);
    assert!(val > 0);
}
