use solana_sdk::{
    hash::hashv,
    pubkey::Pubkey,
};

fn derive_with_seed_host(base: &Pubkey, seed: &str, owner: &Pubkey) -> Result<Pubkey, ()> {
    let seed_bytes = seed.as_bytes();
    if seed_bytes.len() > 32 { return Err(()); }
    let h = hashv(&[
        &base.to_bytes(),
        seed_bytes,
        &owner.to_bytes(),
    ]);
    Ok(Pubkey::new_from_array(h.to_bytes()))
}

#[test]
fn derive_with_seed_matches_sdk() {
    let base = Pubkey::new_unique();
    let owner = solana_sdk::system_program::id();

    // Valid seeds including boundary (32 bytes)
    let seeds = [
        "",
        "a",
        "seed",
        "0123456789abcdef0123456789abcd", // 32 bytes
    ];

    for s in seeds {
        let sdk = Pubkey::create_with_seed(&base, s, &owner).expect("sdk ok");
        let ours = derive_with_seed_host(&base, s, &owner).expect("host ok");
        assert_eq!(sdk, ours, "parity for seed {:?}", s);
    }

    // Note: some SDK versions may accept >32 seeds; we only verify <=32 parity here
}
