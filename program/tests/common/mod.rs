use solana_program_test::{ProgramTest, ProgramTestBanksClientExt};
// Import ReadableAccount from the standalone crate to match AccountSharedData
use solana_account::ReadableAccount;
use std::{env, path::Path, str::FromStr};

pub use solana_program_test::{BanksClient, ProgramTestContext};
pub use solana_sdk::{
    pubkey::Pubkey,
    signature::{Keypair, Signer},
    signers::Signers,
    transaction::Transaction,
    system_instruction,
};

pub fn program_test() -> ProgramTest {
    let mut pt = program_test_without_features(&[]);
    // Provide stake-config for delegate flows that expect it
    add_stake_config_account_to_genesis(&mut pt);
    pt
}

pub fn program_test_without_features(feature_ids: &[Pubkey]) -> ProgramTest {
    let deploy_dir = format!("{}/target/deploy", env!("CARGO_MANIFEST_DIR"));
    env::set_var("BPF_OUT_DIR", &deploy_dir);
    let so_path = Path::new(&deploy_dir).join("pinocchio_stake.so");
    assert!(
        so_path.exists(),
        "SBF artifact not found at {}.\nBuild first: `cargo-build-sbf --no-default-features --features sbf --manifest-path program/Cargo.toml`",
        so_path.display()
    );

    let mut pt = ProgramTest::default();
    pt.prefer_bpf(true);
    // Allow headroom for heavier flows while debugging
    pt.set_compute_max_units(1_000_000);
    for feature in feature_ids {
        pt.deactivate_feature(*feature);
    }
    let program_id = Pubkey::new_from_array(pinocchio_stake::ID);
    pt.add_upgradeable_program_to_genesis("pinocchio_stake", &program_id);
    pt
}

// Shared adapter for instruction translation + state helpers
pub mod pin_adapter;

pub async fn refresh_blockhash(ctx: &mut ProgramTestContext) {
    ctx.last_blockhash = ctx
        .banks_client
        .get_new_latest_blockhash(&ctx.last_blockhash)
        .await
        .unwrap();
}

pub async fn transfer(ctx: &mut ProgramTestContext, recipient: &Pubkey, amount: u64) {
    let tx = Transaction::new_signed_with_payer(
        &[system_instruction::transfer(&ctx.payer.pubkey(), recipient, amount)],
        Some(&ctx.payer.pubkey()),
        &[&ctx.payer],
        ctx.last_blockhash,
    );
    ctx.banks_client.process_transaction(tx).await.unwrap();
}

// Query the active stake program for its minimum delegation requirement (lamports)
pub async fn get_minimum_delegation_lamports(ctx: &mut ProgramTestContext) -> u64 {
    use crate::common::pin_adapter as ixn;
    let ix = ixn::get_minimum_delegation();
    let tx = Transaction::new_signed_with_payer(
        &[ix],
        Some(&ctx.payer.pubkey()),
        &[&ctx.payer],
        ctx.last_blockhash,
    );
    let sim = ctx
        .banks_client
        .simulate_transaction(tx)
        .await
        .expect("simulate get_minimum_delegation");
    if let Some(rd) = sim.simulation_details.and_then(|d| d.return_data) {
        let mut buf = [0u8; 8];
        let n = core::cmp::min(rd.data.len(), 8);
        buf[..n].copy_from_slice(&rd.data[..n]);
        let v = u64::from_le_bytes(buf);
        return v.max(1);
    }
    1
}

// Native baseline: do not override the builtin Stake program
pub fn program_test_native() -> ProgramTest {
    let mut pt = ProgramTest::default();
    pt.prefer_bpf(true);
    pt.set_compute_max_units(1_000_000);

    // Optional: load the official/native Stake program as BPF instead of using the builtin.
    // To enable, set one of the following before running tests:
    // - NATIVE_STAKE_SO_PATH: absolute or relative path to the stake .so file
    //   The filename (without .so) will be used as the program name for lookup.
    //   Example: NATIVE_STAKE_SO_PATH=/path/to/stake_native.so
    // - NATIVE_STAKE_SO_NAME: name of the .so file present in ProgramTest search path
    //   (BPF_OUT_DIR, tests/fixtures, or current dir). Example: native_stake
    if let Ok(so_path) = std::env::var("NATIVE_STAKE_SO_PATH") {
        use std::path::Path;
        let p = Path::new(&so_path);
        if p.exists() {
            if let Some(dir) = p.parent() {
                // Point ProgramTest loader at the directory containing the .so
                std::env::set_var("BPF_OUT_DIR", dir);
                // Ensure a predictable name is available: copy to native_stake.so if needed
                let target = dir.join("native_stake.so");
                if !target.exists() {
                    let _ = std::fs::copy(&p, &target);
                }
            }
            // Load under canonical stake program ID using a static program name
            pt.add_upgradeable_program_to_genesis("native_stake", &solana_sdk::stake::program::id());
            // Also add the stake-config account to genesis so the stake program can read it
            add_stake_config_account_to_genesis(&mut pt);
        }
    } else if let Ok(name) = std::env::var("NATIVE_STAKE_SO_NAME") {
        // Expect `<name>.so` to be discoverable in ProgramTest's default search path.
        let static_name: &'static str = Box::leak(name.into_boxed_str());
        pt.add_upgradeable_program_to_genesis(static_name, &solana_sdk::stake::program::id());
        add_stake_config_account_to_genesis(&mut pt);
    }

    // Auto-detect a local fixtures .so if present (no env needed)
    // Looks for `tests/fixtures/solana_stake_program.so` and loads it under the
    // canonical Stake program ID.
    let fixtures_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
    let fixtures_so = fixtures_dir.join("solana_stake_program.so");
    if fixtures_so.exists() {
        // Point loader at fixtures dir and override builtin Stake at genesis
        std::env::set_var("BPF_OUT_DIR", &fixtures_dir);
        pt.add_upgradeable_program_to_genesis("solana_stake_program", &solana_sdk::stake::program::id());
        add_stake_config_account_to_genesis(&mut pt);
    }

    // Optional: load native Vote program as BPF too to ensure its state layout
    // matches the Stake BPF you provided.
    if let Ok(vote_path) = std::env::var("NATIVE_VOTE_SO_PATH") {
        use std::path::Path;
        let p = Path::new(&vote_path);
        if p.exists() {
            if let Some(dir) = p.parent() {
                std::env::set_var("BPF_OUT_DIR", dir);
                let target = dir.join("native_vote.so");
                if !target.exists() {
                    let _ = std::fs::copy(&p, &target);
                }
            }
            pt.add_upgradeable_program_to_genesis("native_vote", &solana_sdk::vote::program::id());
        }
    } else if let Ok(name) = std::env::var("NATIVE_VOTE_SO_NAME") {
        let static_name: &'static str = Box::leak(name.into_boxed_str());
        pt.add_upgradeable_program_to_genesis(static_name, &solana_sdk::vote::program::id());
    }

    pt
}

fn add_stake_config_account_to_genesis(pt: &mut ProgramTest) {
    // Build a minimal, rent-exempt stake-config account, matching what the
    // runtime/builtin normally inserts at genesis for the builtin stake program.
    use solana_sdk::{account::Account, rent::Rent};
    // Use the upstream helper to create a valid stake-config account
    let shared = solana_stake_program::config::create_account(0, &solana_stake_program::config::Config::default());
    let lamports = Rent::default().minimum_balance(shared.data().len()).max(1);
    let account = Account {
        lamports,
        data: shared.data().to_vec(),
        owner: solana_sdk::pubkey::Pubkey::from_str("Config1111111111111111111111111111111111111").unwrap(),
        executable: false,
        rent_epoch: 0,
    };
    pt.add_genesis_account(solana_sdk::stake::config::id(), account);
}
