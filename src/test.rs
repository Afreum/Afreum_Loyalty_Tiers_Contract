#![cfg(test)]

use super::*;
use soroban_sdk::{
    testutils::{Address as _, Ledger},
    Address, BytesN, Env, Vec,
};
use types::LoyaltyTier;

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

fn test_keypair(env: &Env) -> (BytesN<32>, ed25519_dalek::SigningKey) {
    let seed = [1u8; 32];
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&seed);
    let verifying_key = signing_key.verifying_key();
    let pub_key = BytesN::from_array(env, &verifying_key.to_bytes());
    (pub_key, signing_key)
}

fn test_keypair_2(env: &Env) -> (BytesN<32>, ed25519_dalek::SigningKey) {
    let seed = [2u8; 32];
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&seed);
    let verifying_key = signing_key.verifying_key();
    let pub_key = BytesN::from_array(env, &verifying_key.to_bytes());
    (pub_key, signing_key)
}

/// Canonical 72-byte message sign helper.
/// Layout: address_bytes(32) || timestamp(8 BE) || afrx_balance(16 BE) || total_balance(16 BE)
fn sign72(
    signing_key: &ed25519_dalek::SigningKey,
    address_bytes: &[u8; 32],
    timestamp: u64,
    afrx_balance: i128,
    total_balance: i128,
) -> [u8; 64] {
    use ed25519_dalek::Signer;
    let mut msg = [0u8; 72];
    msg[0..32].copy_from_slice(address_bytes);
    msg[32..40].copy_from_slice(&timestamp.to_be_bytes());
    msg[40..56].copy_from_slice(&afrx_balance.to_be_bytes());
    msg[56..72].copy_from_slice(&total_balance.to_be_bytes());
    signing_key.sign(&msg).to_bytes()
}

fn addr_bytes(env: &Env) -> ([u8; 32], BytesN<32>) {
    let raw = [42u8; 32];
    (raw, BytesN::from_array(env, &raw))
}

fn make_sig(
    env: &Env,
    signing_key: &ed25519_dalek::SigningKey,
    addr_raw: &[u8; 32],
    ts: u64,
    afrx: i128,
    total: i128,
) -> BytesN<64> {
    BytesN::from_array(env, &sign72(signing_key, addr_raw, ts, afrx, total))
}

fn default_tiers(env: &Env) -> Vec<LoyaltyTier> {
    let bonus_issuer = Address::generate(env);
    let mut tiers = Vec::new(env);
    for (id, name, afrx_req, general_fee, trading_fee, withdrawal_fee) in [
        ("1", "Silver",    0u32, "1",   "1",   "1"),
        ("2", "Gold",     10u32, "0.5", "0.5", "0.5"),
        ("3", "Vibranium",25u32, "0",   "0",   "0"),
    ] {
        tiers.push_back(LoyaltyTier {
            id:               soroban_sdk::String::from_str(env, id),
            name:             soroban_sdk::String::from_str(env, name),
            bonus_asset:      soroban_sdk::String::from_str(env, "AFRX"),
            bonus_issuer:     bonus_issuer.clone(),
            withdrawal_fee:   soroban_sdk::String::from_str(env, withdrawal_fee),
            active:           soroban_sdk::String::from_str(env, "1"),
            afr_apy_30:       soroban_sdk::String::from_str(env, "4"),
            afr_bonus_30:     soroban_sdk::String::from_str(env, "0"),
            afrx_apy_30:      soroban_sdk::String::from_str(env, "3"),
            afrx_bonus_30:    soroban_sdk::String::from_str(env, "0"),
            axxx_apy_30:      soroban_sdk::String::from_str(env, "2"),
            axxx_bonus_30:    soroban_sdk::String::from_str(env, "0"),
            fiat_apy_30:      soroban_sdk::String::from_str(env, "0"),
            fiat_bonus_30:    soroban_sdk::String::from_str(env, "1"),
            afr_apy_90:       soroban_sdk::String::from_str(env, "7"),
            afr_bonus_90:     soroban_sdk::String::from_str(env, "0"),
            afrx_apy_90:      soroban_sdk::String::from_str(env, "5"),
            afrx_bonus_90:    soroban_sdk::String::from_str(env, "0"),
            axxx_apy_90:      soroban_sdk::String::from_str(env, "4"),
            axxx_bonus_90:    soroban_sdk::String::from_str(env, "0"),
            fiat_apy_90:      soroban_sdk::String::from_str(env, "0"),
            fiat_bonus_90:    soroban_sdk::String::from_str(env, "2"),
            afr_apy_180:      soroban_sdk::String::from_str(env, "10"),
            afr_bonus_180:    soroban_sdk::String::from_str(env, "0"),
            afrx_apy_180:     soroban_sdk::String::from_str(env, "8"),
            afrx_bonus_180:   soroban_sdk::String::from_str(env, "0"),
            axxx_apy_180:     soroban_sdk::String::from_str(env, "6"),
            axxx_bonus_180:   soroban_sdk::String::from_str(env, "0"),
            fiat_apy_180:     soroban_sdk::String::from_str(env, "0"),
            fiat_bonus_180:   soroban_sdk::String::from_str(env, "3"),
            afrx_req,
            bonus_asset_type: soroban_sdk::String::from_str(env, "credit_alphanum4"),
            logo:             soroban_sdk::String::from_str(env, "QmTest"),
            general_fee:      soroban_sdk::String::from_str(env, general_fee),
            trading_fee:      soroban_sdk::String::from_str(env, trading_fee),
        });
    }
    tiers
}

fn setup() -> (Env, LoyaltyTierContractClient<'static>, ed25519_dalek::SigningKey, Address) {
    let env = Env::default();
    env.mock_all_auths();

    let contract_id = env.register(LoyaltyTierContract, ());
    let client = LoyaltyTierContractClient::new(&env, &contract_id);

    let admin = Address::generate(&env);
    let (pub_key, signing_key) = test_keypair(&env);
    let allowed_issuers = Vec::new(&env);
    let tiers = default_tiers(&env);

    client.init(&admin, &7u32, &allowed_issuers, &tiers, &pub_key, &900u64);
    env.ledger().with_mut(|l| l.timestamp = 1_000_000);

    (env, client, signing_key, admin)
}

// ---------------------------------------------------------------------------
// init tests
// ---------------------------------------------------------------------------

#[test]
fn test_init_sets_tiers() {
    let (_env, client, _, _) = setup();
    assert_eq!(client.get_tiers().len(), 3);
}

#[test]
fn test_init_guard_prevents_reinit() {
    let (env, client, _, admin) = setup();
    let (pub_key, _) = test_keypair(&env);
    let tiers = default_tiers(&env);
    let issuers = Vec::new(&env);
    let err = client
        .try_init(&admin, &7u32, &issuers, &tiers, &pub_key, &900u64)
        .unwrap_err()
        .unwrap();
    assert_eq!(err, Error::AlreadyInitialized.into());
}

#[test]
fn test_init_rejects_empty_tiers() {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register(LoyaltyTierContract, ());
    let client = LoyaltyTierContractClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    let (pub_key, _) = test_keypair(&env);
    let empty: Vec<LoyaltyTier> = Vec::new(&env);
    let issuers = Vec::new(&env);
    let err = client
        .try_init(&admin, &7u32, &issuers, &empty, &pub_key, &900u64)
        .unwrap_err()
        .unwrap();
    assert_eq!(err, Error::EmptyTiers.into());
}

// Fix #5 — catch-all tier validation
#[test]
fn test_init_rejects_tiers_without_catchall() {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register(LoyaltyTierContract, ());
    let client = LoyaltyTierContractClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    let (pub_key, _) = test_keypair(&env);
    let issuers = Vec::new(&env);

    // Build a tiers array with no afrx_req = 0 entry
    let bonus_issuer = Address::generate(&env);
    let mut bad_tiers: Vec<LoyaltyTier> = Vec::new(&env);
    bad_tiers.push_back(LoyaltyTier {
        id: soroban_sdk::String::from_str(&env, "1"),
        name: soroban_sdk::String::from_str(&env, "Gold"),
        bonus_asset: soroban_sdk::String::from_str(&env, "AFRX"),
        bonus_issuer: bonus_issuer.clone(),
        withdrawal_fee: soroban_sdk::String::from_str(&env, "0.5"),
        active: soroban_sdk::String::from_str(&env, "1"),
        afr_apy_30: soroban_sdk::String::from_str(&env, "4"),
        afr_bonus_30: soroban_sdk::String::from_str(&env, "0"),
        afrx_apy_30: soroban_sdk::String::from_str(&env, "3"),
        afrx_bonus_30: soroban_sdk::String::from_str(&env, "0"),
        axxx_apy_30: soroban_sdk::String::from_str(&env, "2"),
        axxx_bonus_30: soroban_sdk::String::from_str(&env, "0"),
        fiat_apy_30: soroban_sdk::String::from_str(&env, "0"),
        fiat_bonus_30: soroban_sdk::String::from_str(&env, "1"),
        afr_apy_90: soroban_sdk::String::from_str(&env, "7"),
        afr_bonus_90: soroban_sdk::String::from_str(&env, "0"),
        afrx_apy_90: soroban_sdk::String::from_str(&env, "5"),
        afrx_bonus_90: soroban_sdk::String::from_str(&env, "0"),
        axxx_apy_90: soroban_sdk::String::from_str(&env, "4"),
        axxx_bonus_90: soroban_sdk::String::from_str(&env, "0"),
        fiat_apy_90: soroban_sdk::String::from_str(&env, "0"),
        fiat_bonus_90: soroban_sdk::String::from_str(&env, "2"),
        afr_apy_180: soroban_sdk::String::from_str(&env, "10"),
        afr_bonus_180: soroban_sdk::String::from_str(&env, "0"),
        afrx_apy_180: soroban_sdk::String::from_str(&env, "8"),
        afrx_bonus_180: soroban_sdk::String::from_str(&env, "0"),
        axxx_apy_180: soroban_sdk::String::from_str(&env, "6"),
        axxx_bonus_180: soroban_sdk::String::from_str(&env, "0"),
        fiat_apy_180: soroban_sdk::String::from_str(&env, "0"),
        fiat_bonus_180: soroban_sdk::String::from_str(&env, "3"),
        afrx_req: 10, // no catch-all
        bonus_asset_type: soroban_sdk::String::from_str(&env, "credit_alphanum4"),
        logo: soroban_sdk::String::from_str(&env, "QmTest"),
        general_fee: soroban_sdk::String::from_str(&env, "0.5"),
        trading_fee: soroban_sdk::String::from_str(&env, "0.5"),
    });

    let err = client
        .try_init(&admin, &7u32, &issuers, &bad_tiers, &pub_key, &900u64)
        .unwrap_err()
        .unwrap();
    assert_eq!(err, Error::NoCatchAllTier.into());
}

// ---------------------------------------------------------------------------
// Admin auth tests (review gap: non-admin rejection)
// ---------------------------------------------------------------------------

/// Verify that setter functions on an uninitialised contract fail.
/// In production, require_admin → require_initialized traps before any
/// storage write, preventing any unauthorised mutation.
#[test]
fn test_setters_fail_on_uninitialised_contract() {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register(LoyaltyTierContract, ());
    let client = LoyaltyTierContractClient::new(&env, &contract_id);

    // Every setter should fail with NotInitialized before touching storage
    assert_eq!(
        client.try_set_resolution(&300u64).unwrap_err().unwrap(),
        Error::NotInitialized.into()
    );
    assert_eq!(
        client.try_set_loyalty_tiers(&default_tiers(&env)).unwrap_err().unwrap(),
        Error::NotInitialized.into()
    );
    assert_eq!(
        client.try_set_rates_signing_key(&BytesN::from_array(&env, &[0u8; 32]))
            .unwrap_err()
            .unwrap(),
        Error::NotInitialized.into()
    );
}

/// Verify that `require_admin` rejects a call where the admin's auth is not
/// present. Uses a fresh env with NO mocked auths after init.
#[test]
fn test_non_admin_set_loyalty_tiers_rejected() {
    // Phase 1: init with mock_all_auths
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register(LoyaltyTierContract, ());
    let client = LoyaltyTierContractClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    let (pub_key, _) = test_keypair(&env);
    client.init(&admin, &7u32, &Vec::new(&env), &default_tiers(&env), &pub_key, &900u64);

    // Phase 2: reset to empty auths — admin.require_auth() will now trap
    env.mock_auths(&[]);
    let result = client.try_set_loyalty_tiers(&default_tiers(&env));
    assert!(result.is_err());
}

#[test]
fn test_set_loyalty_tiers_empty_rejected() {
    let (env, client, _, _) = setup();
    let empty: Vec<LoyaltyTier> = Vec::new(&env);
    let err = client
        .try_set_loyalty_tiers(&empty)
        .unwrap_err()
        .unwrap();
    assert_eq!(err, Error::EmptyTiers.into());
}

#[test]
fn test_set_loyalty_tiers_without_catchall_rejected() {
    let (env, client, _, _) = setup();
    let bonus_issuer = Address::generate(&env);
    let mut no_catchall: Vec<LoyaltyTier> = Vec::new(&env);
    no_catchall.push_back(LoyaltyTier {
        id: soroban_sdk::String::from_str(&env, "1"),
        name: soroban_sdk::String::from_str(&env, "Gold"),
        bonus_asset: soroban_sdk::String::from_str(&env, "AFRX"),
        bonus_issuer,
        withdrawal_fee: soroban_sdk::String::from_str(&env, "0.5"),
        active: soroban_sdk::String::from_str(&env, "1"),
        afr_apy_30: soroban_sdk::String::from_str(&env, "4"),
        afr_bonus_30: soroban_sdk::String::from_str(&env, "0"),
        afrx_apy_30: soroban_sdk::String::from_str(&env, "3"),
        afrx_bonus_30: soroban_sdk::String::from_str(&env, "0"),
        axxx_apy_30: soroban_sdk::String::from_str(&env, "2"),
        axxx_bonus_30: soroban_sdk::String::from_str(&env, "0"),
        fiat_apy_30: soroban_sdk::String::from_str(&env, "0"),
        fiat_bonus_30: soroban_sdk::String::from_str(&env, "1"),
        afr_apy_90: soroban_sdk::String::from_str(&env, "7"),
        afr_bonus_90: soroban_sdk::String::from_str(&env, "0"),
        afrx_apy_90: soroban_sdk::String::from_str(&env, "5"),
        afrx_bonus_90: soroban_sdk::String::from_str(&env, "0"),
        axxx_apy_90: soroban_sdk::String::from_str(&env, "4"),
        axxx_bonus_90: soroban_sdk::String::from_str(&env, "0"),
        fiat_apy_90: soroban_sdk::String::from_str(&env, "0"),
        fiat_bonus_90: soroban_sdk::String::from_str(&env, "2"),
        afr_apy_180: soroban_sdk::String::from_str(&env, "10"),
        afr_bonus_180: soroban_sdk::String::from_str(&env, "0"),
        afrx_apy_180: soroban_sdk::String::from_str(&env, "8"),
        afrx_bonus_180: soroban_sdk::String::from_str(&env, "0"),
        axxx_apy_180: soroban_sdk::String::from_str(&env, "6"),
        axxx_bonus_180: soroban_sdk::String::from_str(&env, "0"),
        fiat_apy_180: soroban_sdk::String::from_str(&env, "0"),
        fiat_bonus_180: soroban_sdk::String::from_str(&env, "3"),
        afrx_req: 10,
        bonus_asset_type: soroban_sdk::String::from_str(&env, "credit_alphanum4"),
        logo: soroban_sdk::String::from_str(&env, "QmTest"),
        general_fee: soroban_sdk::String::from_str(&env, "0.5"),
        trading_fee: soroban_sdk::String::from_str(&env, "0.5"),
    });
    let err = client
        .try_set_loyalty_tiers(&no_catchall)
        .unwrap_err()
        .unwrap();
    assert_eq!(err, Error::NoCatchAllTier.into());
}

// ---------------------------------------------------------------------------
// get_loyalty_tier — tier boundary tests
// ---------------------------------------------------------------------------

fn get_tier(
    client: &LoyaltyTierContractClient,
    env: &Env,
    signing_key: &ed25519_dalek::SigningKey,
    afrx_pct_num: i128,
    total: i128,
) -> soroban_sdk::String {
    let afrx = (afrx_pct_num * total) / 100;
    let ts = 1_000_000u64;
    let (addr_raw, addr_b) = addr_bytes(env);
    let sig = make_sig(env, signing_key, &addr_raw, ts, afrx, total);
    let addr = Address::generate(env);
    client.get_loyalty_tier(&addr, &addr_b, &ts, &afrx, &total, &sig).name
}

#[test]
fn test_tier_silver_at_zero_pct() {
    let (env, client, sk, _) = setup();
    assert_eq!(get_tier(&client, &env, &sk, 0, 1_000_000_000), soroban_sdk::String::from_str(&env, "Silver"));
}

#[test]
fn test_tier_silver_at_9_pct() {
    let (env, client, sk, _) = setup();
    assert_eq!(get_tier(&client, &env, &sk, 9, 1_000_000_000), soroban_sdk::String::from_str(&env, "Silver"));
}

#[test]
fn test_tier_gold_at_10_pct() {
    let (env, client, sk, _) = setup();
    assert_eq!(get_tier(&client, &env, &sk, 10, 1_000_000_000), soroban_sdk::String::from_str(&env, "Gold"));
}

#[test]
fn test_tier_gold_at_24_pct() {
    let (env, client, sk, _) = setup();
    assert_eq!(get_tier(&client, &env, &sk, 24, 1_000_000_000), soroban_sdk::String::from_str(&env, "Gold"));
}

#[test]
fn test_tier_vibranium_at_25_pct() {
    let (env, client, sk, _) = setup();
    assert_eq!(get_tier(&client, &env, &sk, 25, 1_000_000_000), soroban_sdk::String::from_str(&env, "Vibranium"));
}

#[test]
fn test_tier_vibranium_at_100_pct() {
    let (env, client, sk, _) = setup();
    let total = 1_000_000_000i128;
    let ts = 1_000_000u64;
    let (addr_raw, addr_b) = addr_bytes(&env);
    let sig = make_sig(&env, &sk, &addr_raw, ts, total, total);
    let addr = Address::generate(&env);
    let tier = client.get_loyalty_tier(&addr, &addr_b, &ts, &total, &total, &sig);
    assert_eq!(tier.name, soroban_sdk::String::from_str(&env, "Vibranium"));
}

#[test]
fn test_tier_silver_when_total_balance_zero() {
    let (env, client, sk, _) = setup();
    let ts = 1_000_000u64;
    let (addr_raw, addr_b) = addr_bytes(&env);
    let sig = make_sig(&env, &sk, &addr_raw, ts, 0, 0);
    let addr = Address::generate(&env);
    let tier = client.get_loyalty_tier(&addr, &addr_b, &ts, &0, &0, &sig);
    assert_eq!(tier.name, soroban_sdk::String::from_str(&env, "Silver"));
}

// ---------------------------------------------------------------------------
// Signature & timestamp gate tests
// ---------------------------------------------------------------------------

#[test]
fn test_invalid_signature_rejected() {
    let (env, client, _, _) = setup();
    let addr = Address::generate(&env);
    let (_, addr_b) = addr_bytes(&env);
    let bad_sig = BytesN::from_array(&env, &[0u8; 64]);
    assert!(client.try_get_loyalty_tier(&addr, &addr_b, &1_000_000u64, &0, &1_000_000_000, &bad_sig).is_err());
}

#[test]
fn test_expired_timestamp_rejected() {
    let (env, client, sk, _) = setup();
    // Ledger = 1_000_000, resolution = 900 → 999_099 is too old
    let stale_ts = 999_099u64;
    let (addr_raw, addr_b) = addr_bytes(&env);
    let sig = make_sig(&env, &sk, &addr_raw, stale_ts, 0, 1_000_000_000);
    let addr = Address::generate(&env);
    let err = client
        .try_get_loyalty_tier(&addr, &addr_b, &stale_ts, &0, &1_000_000_000, &sig)
        .unwrap_err()
        .unwrap();
    assert_eq!(err, Error::RatesTooOld.into());
}

#[test]
fn test_fresh_timestamp_accepted() {
    let (env, client, sk, _) = setup();
    let fresh_ts = 999_100u64;
    let total = 1_000_000_000i128;
    let (addr_raw, addr_b) = addr_bytes(&env);
    let sig = make_sig(&env, &sk, &addr_raw, fresh_ts, 0, total);
    let addr = Address::generate(&env);
    let tier = client.get_loyalty_tier(&addr, &addr_b, &fresh_ts, &0, &total, &sig);
    assert_eq!(tier.name, soroban_sdk::String::from_str(&env, "Silver"));
}

// Fix #3 — future timestamp guard
#[test]
fn test_future_timestamp_rejected() {
    let (env, client, sk, _) = setup();
    // Ledger = 1_000_000; FUTURE_TOLERANCE = 60 → anything > 1_000_060 is too future
    let future_ts = 1_000_061u64;
    let total = 1_000_000_000i128;
    let (addr_raw, addr_b) = addr_bytes(&env);
    let sig = make_sig(&env, &sk, &addr_raw, future_ts, 0, total);
    let addr = Address::generate(&env);
    let err = client
        .try_get_loyalty_tier(&addr, &addr_b, &future_ts, &0, &total, &sig)
        .unwrap_err()
        .unwrap();
    assert_eq!(err, Error::RatesTooOld.into());
}

#[test]
fn test_timestamp_at_future_tolerance_boundary_accepted() {
    let (env, client, sk, _) = setup();
    // Exactly at boundary: now(1_000_000) + FUTURE_TOLERANCE(60) = 1_000_060 — accepted
    let boundary_ts = 1_000_060u64;
    let total = 1_000_000_000i128;
    let (addr_raw, addr_b) = addr_bytes(&env);
    let sig = make_sig(&env, &sk, &addr_raw, boundary_ts, 0, total);
    let addr = Address::generate(&env);
    let tier = client.get_loyalty_tier(&addr, &addr_b, &boundary_ts, &0, &total, &sig);
    assert_eq!(tier.name, soroban_sdk::String::from_str(&env, "Silver"));
}

// Fix #1 — address binding: payload signed for addr_A cannot be used for addr_B
#[test]
fn test_address_bound_payload_rejected_for_different_address() {
    let (env, client, sk, _) = setup();
    let ts = 1_000_000u64;
    let total = 1_000_000_000i128;
    // Sign for address A's bytes
    let addr_a_raw = [10u8; 32];
    let sig_for_a = make_sig(&env, &sk, &addr_a_raw, ts, 0, total);
    // Attempt to use addr_A's signature with addr_B's bytes
    let addr_b_bytes = BytesN::from_array(&env, &[20u8; 32]);
    let addr = Address::generate(&env);
    // Should fail — signature doesn't cover addr_B's bytes
    assert!(client
        .try_get_loyalty_tier(&addr, &addr_b_bytes, &ts, &0, &total, &sig_for_a)
        .is_err());
}

// Key rotation test (review gap)
#[test]
fn test_key_rotation_old_sig_fails_new_sig_passes() {
    let (env, client, old_sk, _) = setup();
    let ts = 1_000_000u64;
    let total = 1_000_000_000i128;
    let (addr_raw, addr_b) = addr_bytes(&env);

    // Signature with old key — currently valid
    let old_sig = make_sig(&env, &old_sk, &addr_raw, ts, 0, total);
    let addr = Address::generate(&env);
    client.get_loyalty_tier(&addr, &addr_b, &ts, &0, &total, &old_sig);

    // Rotate to new key
    let (new_pub_key, new_sk) = test_keypair_2(&env);
    client.set_rates_signing_key(&new_pub_key);

    // Old signature must now fail
    assert!(client
        .try_get_loyalty_tier(&addr, &addr_b, &ts, &0, &total, &old_sig)
        .is_err());

    // New signature passes
    let new_sig = make_sig(&env, &new_sk, &addr_raw, ts, 0, total);
    let tier = client.get_loyalty_tier(&addr, &addr_b, &ts, &0, &total, &new_sig);
    assert_eq!(tier.name, soroban_sdk::String::from_str(&env, "Silver"));
}

// set_loyalty_tiers replacement reflected in subsequent lookups (review gap)
#[test]
fn test_set_loyalty_tiers_affects_subsequent_lookups() {
    let (env, client, sk, _) = setup();
    let ts = 1_000_000u64;
    let total = 1_000_000_000i128;
    let (addr_raw, addr_b) = addr_bytes(&env);

    // With default tiers, 25% → Vibranium
    let afrx = total / 4; // 25%
    let sig = make_sig(&env, &sk, &addr_raw, ts, afrx, total);
    let addr = Address::generate(&env);
    let tier = client.get_loyalty_tier(&addr, &addr_b, &ts, &afrx, &total, &sig);
    assert_eq!(tier.name, soroban_sdk::String::from_str(&env, "Vibranium"));

    // Replace tiers: only Silver (afrx_req = 0)
    let bonus_issuer = Address::generate(&env);
    let mut single_tier: Vec<LoyaltyTier> = Vec::new(&env);
    single_tier.push_back(LoyaltyTier {
        id: soroban_sdk::String::from_str(&env, "1"),
        name: soroban_sdk::String::from_str(&env, "Basic"),
        bonus_asset: soroban_sdk::String::from_str(&env, "AFRX"),
        bonus_issuer,
        withdrawal_fee: soroban_sdk::String::from_str(&env, "2"),
        active: soroban_sdk::String::from_str(&env, "1"),
        afr_apy_30: soroban_sdk::String::from_str(&env, "1"),
        afr_bonus_30: soroban_sdk::String::from_str(&env, "0"),
        afrx_apy_30: soroban_sdk::String::from_str(&env, "1"),
        afrx_bonus_30: soroban_sdk::String::from_str(&env, "0"),
        axxx_apy_30: soroban_sdk::String::from_str(&env, "1"),
        axxx_bonus_30: soroban_sdk::String::from_str(&env, "0"),
        fiat_apy_30: soroban_sdk::String::from_str(&env, "0"),
        fiat_bonus_30: soroban_sdk::String::from_str(&env, "0"),
        afr_apy_90: soroban_sdk::String::from_str(&env, "1"),
        afr_bonus_90: soroban_sdk::String::from_str(&env, "0"),
        afrx_apy_90: soroban_sdk::String::from_str(&env, "1"),
        afrx_bonus_90: soroban_sdk::String::from_str(&env, "0"),
        axxx_apy_90: soroban_sdk::String::from_str(&env, "1"),
        axxx_bonus_90: soroban_sdk::String::from_str(&env, "0"),
        fiat_apy_90: soroban_sdk::String::from_str(&env, "0"),
        fiat_bonus_90: soroban_sdk::String::from_str(&env, "0"),
        afr_apy_180: soroban_sdk::String::from_str(&env, "1"),
        afr_bonus_180: soroban_sdk::String::from_str(&env, "0"),
        afrx_apy_180: soroban_sdk::String::from_str(&env, "1"),
        afrx_bonus_180: soroban_sdk::String::from_str(&env, "0"),
        axxx_apy_180: soroban_sdk::String::from_str(&env, "1"),
        axxx_bonus_180: soroban_sdk::String::from_str(&env, "0"),
        fiat_apy_180: soroban_sdk::String::from_str(&env, "0"),
        fiat_bonus_180: soroban_sdk::String::from_str(&env, "0"),
        afrx_req: 0,
        bonus_asset_type: soroban_sdk::String::from_str(&env, "credit_alphanum4"),
        logo: soroban_sdk::String::from_str(&env, "QmTest"),
        general_fee: soroban_sdk::String::from_str(&env, "2"),
        trading_fee: soroban_sdk::String::from_str(&env, "2"),
    });
    client.set_loyalty_tiers(&single_tier);

    // Same payload, same 25% AFRX — now resolves to Basic (only tier)
    let sig2 = make_sig(&env, &sk, &addr_raw, ts, afrx, total);
    let tier2 = client.get_loyalty_tier(&addr, &addr_b, &ts, &afrx, &total, &sig2);
    assert_eq!(tier2.name, soroban_sdk::String::from_str(&env, "Basic"));
}

// allowed_issuers getter/setter (Fix #2)
#[test]
fn test_set_and_get_allowed_issuers() {
    let (env, client, _, _) = setup();
    let issuer = Address::generate(&env);
    let mut new_issuers: Vec<Address> = Vec::new(&env);
    new_issuers.push_back(issuer.clone());
    client.set_allowed_issuers(&new_issuers);
    let stored = client.get_allowed_issuers();
    assert_eq!(stored.len(), 1);
    assert_eq!(stored.get(0).unwrap(), issuer);
}
