pub const MAXIMUM_SIGNERS: usize = 32;
pub const DEFAULT_WARMUP_COOLDOWN_RATE: f64 = 0.25;
pub const FEATURE_STAKE_RAISE_MINIMUM_DELEGATION_TO_1_SOL: bool = false;
pub const LAMPORTS_PER_SOL: u64 = 1_000_000_000;
pub const NEW_WARMUP_COOLDOWN_RATE: f64 = 0.09;

// feature_set::reduce_stake_warmup_cooldown changed the warmup/cooldown from
// 25% to 9%. a function is provided by the sdk,
// new_warmup_cooldown_rate_epoch(), which returns the epoch this change
// happened. this function is not available to bpf programs. however, we dont
// need it. the number is necessary to calculate historical effective stake from
// stake history, but we only care that stake we are dealing with in the present
// epoch has been fully (de)activated. this means, as long as one epoch has
// passed since activation where all prior stake had escaped warmup/cooldown,
// we can pretend the rate has always beein 9% without issue. so we do that
pub const PERPETUAL_NEW_WARMUP_COOLDOWN_RATE_EPOCH: Option<[u8; 8]> = Some([0; 8]);
