#![no_std]

mod types;
#[cfg(test)]
mod test;

use soroban_sdk::{
    contract, contractimpl, contractmeta, panic_with_error,
    Address, Bytes, BytesN, Env, Map, String, Vec,
};

use types::{DataKey, LoyaltyTier};

contractmeta!(
    key = "Description",
    val = "Afreum Loyalty Tier Contract v0.1.0"
);

/// How many seconds into the future a payload timestamp may be.
/// Guards against payloads signed with far-future timestamps that would
/// remain valid for resolution + FUTURE_TOLERANCE seconds.
const FUTURE_TOLERANCE: u64 = 60;

// ---------------------------------------------------------------------------
// Error codes
// ---------------------------------------------------------------------------
#[soroban_sdk::contracterror]
#[derive(Copy, Clone, Debug, PartialEq)]
#[repr(u32)]
pub enum Error {
    AlreadyInitialized  = 1,
    NotInitialized      = 2,
    Unauthorized        = 3,
    InvalidSignature    = 4,
    RatesTooOld         = 5,
    LoyaltyTierNotFound = 6,
    EmptyTiers          = 7,
    /// No tier with afrx_req = 0 — every user would fail lookup below minimum
    NoCatchAllTier      = 8,
}

// ---------------------------------------------------------------------------
// Contract
// ---------------------------------------------------------------------------
#[contract]
pub struct LoyaltyTierContract;

#[contractimpl]
impl LoyaltyTierContract {

    // -----------------------------------------------------------------------
    // init — callable once; admin must authorise the call
    // -----------------------------------------------------------------------
    pub fn init(
        env: Env,
        admin: Address,
        decimals: u32,
        allowed_issuers: Vec<Address>,
        loyalty_tiers: Vec<LoyaltyTier>,
        rates_signing_key: BytesN<32>,
        resolution: u64,
    ) {
        // Fix #4: admin must sign the init transaction
        admin.require_auth();

        if env.storage().instance().has(&DataKey::Initialized) {
            panic_with_error!(&env, Error::AlreadyInitialized);
        }

        // Fix #5: require at least one catch-all tier (afrx_req = 0)
        Self::validate_tiers(&env, &loyalty_tiers);

        env.storage().instance().set(&DataKey::Admin,           &admin);
        env.storage().instance().set(&DataKey::Decimals,        &decimals);
        env.storage().instance().set(&DataKey::AllowedIssuers,  &allowed_issuers);
        env.storage().instance().set(&DataKey::LoyaltyTiers,    &loyalty_tiers);
        env.storage().instance().set(&DataKey::RatesSigningKey, &rates_signing_key);
        env.storage().instance().set(&DataKey::Resolution,      &resolution);
        env.storage().instance().set(&DataKey::Initialized,     &true);
    }

    // -----------------------------------------------------------------------
    // update — upgrade contract WASM (admin only)
    //
    // new_wasm_hash must be the hash of a WASM blob already uploaded to the
    // network via `stellar contract install`.  After this call the contract
    // runs the new code while keeping all existing storage intact.
    // -----------------------------------------------------------------------
    pub fn update(env: Env, new_wasm_hash: BytesN<32>) {
        Self::require_admin(&env);
        env.deployer().update_current_contract_wasm(new_wasm_hash);
    }

    // -----------------------------------------------------------------------
    // set_admin
    // -----------------------------------------------------------------------
    pub fn set_admin(env: Env, new_admin: Address) {
        Self::require_admin(&env);
        env.storage().instance().set(&DataKey::Admin, &new_admin);
    }

    // -----------------------------------------------------------------------
    // set_loyalty_tiers — replaces the entire tiers array
    // -----------------------------------------------------------------------
    pub fn set_loyalty_tiers(env: Env, tiers: Vec<LoyaltyTier>) {
        Self::require_admin(&env);
        // Fix #5: enforce catch-all tier on updates too
        Self::validate_tiers(&env, &tiers);
        env.storage().instance().set(&DataKey::LoyaltyTiers, &tiers);
    }

    // -----------------------------------------------------------------------
    // set_decimals
    // -----------------------------------------------------------------------
    pub fn set_decimals(env: Env, decimals: u32) {
        Self::require_admin(&env);
        env.storage().instance().set(&DataKey::Decimals, &decimals);
    }

    // -----------------------------------------------------------------------
    // set_rates_signing_key
    // -----------------------------------------------------------------------
    pub fn set_rates_signing_key(env: Env, key: BytesN<32>) {
        Self::require_admin(&env);
        env.storage().instance().set(&DataKey::RatesSigningKey, &key);
    }

    // -----------------------------------------------------------------------
    // set_resolution
    // -----------------------------------------------------------------------
    pub fn set_resolution(env: Env, resolution: u64) {
        Self::require_admin(&env);
        env.storage().instance().set(&DataKey::Resolution, &resolution);
    }

    // -----------------------------------------------------------------------
    // Fix #2: set_allowed_issuers — admin can update the issuer list
    // (filtering is enforced by the backend when building the signed payload;
    //  this stored list is the authoritative source the backend must respect)
    // -----------------------------------------------------------------------
    pub fn set_allowed_issuers(env: Env, issuers: Vec<Address>) {
        Self::require_admin(&env);
        env.storage().instance().set(&DataKey::AllowedIssuers, &issuers);
    }

    // -----------------------------------------------------------------------
    // Fix #2: get_allowed_issuers — public read
    // -----------------------------------------------------------------------
    pub fn get_allowed_issuers(env: Env) -> Vec<Address> {
        Self::require_initialized(&env);
        env.storage().instance().get(&DataKey::AllowedIssuers).unwrap()
    }

    // -----------------------------------------------------------------------
    // get_init — public config snapshot (excludes tiers; use get_tiers for those)
    // -----------------------------------------------------------------------
    pub fn get_init(env: Env) -> Map<String, String> {
        Self::require_initialized(&env);
        let s = env.storage().instance();
        let mut m: Map<String, String> = Map::new(&env);

        let admin: Address      = s.get(&DataKey::Admin).unwrap();
        let decimals: u32       = s.get(&DataKey::Decimals).unwrap();
        let resolution: u64     = s.get(&DataKey::Resolution).unwrap();
        let key: BytesN<32>     = s.get(&DataKey::RatesSigningKey).unwrap();

        m.set(String::from_str(&env, "admin"),              admin.to_string());
        m.set(String::from_str(&env, "decimals"),           u32_to_string(&env, decimals));
        m.set(String::from_str(&env, "resolution"),         u64_to_string(&env, resolution));
        // rates_signing_key returned as 64-char hex string
        let key_array: [u8; 32] = key.into();
        m.set(String::from_str(&env, "rates_signing_key"),  bytes_to_hex(&env, &key_array));
        m
    }

    // -----------------------------------------------------------------------
    // get_tiers — public read of stored tiers
    // -----------------------------------------------------------------------
    pub fn get_tiers(env: Env) -> Vec<LoyaltyTier> {
        Self::require_initialized(&env);
        env.storage().instance().get(&DataKey::LoyaltyTiers).unwrap()
    }

    // -----------------------------------------------------------------------
    // get_loyalty_tier
    //
    // Parameters:
    //   address       - Stellar address being queried (for event logging)
    //   address_bytes - Raw 32-byte Ed25519 public key of the address.
    //                   Included in the signed message to bind the payload
    //                   to a specific account (Fix #1).
    //                   DESIGN CONSTRAINT: The Soroban SDK does not provide a
    //                   way to extract raw key bytes from an Address on-chain,
    //                   so address_bytes must be supplied by the caller and is
    //                   not validated against address. The Fiat contract MUST
    //                   always derive address_bytes from the invoker's own
    //                   32-byte Ed25519 public key — never an arbitrary value.
    //   timestamp     - Unix timestamp (seconds) when the backend signed
    //   afrx_balance  - AFRX balance (wallet + open offers), 7 decimals
    //   total_balance - Total balance across allowed_issuers, 7 decimals
    //   signature     - Ed25519 signature over canonical 72-byte message:
    //                   address_bytes(32) || timestamp(8 BE) ||
    //                   afrx_balance(16 BE) || total_balance(16 BE)
    //
    // Returns the matching LoyaltyTier or panics.
    // -----------------------------------------------------------------------
    pub fn get_loyalty_tier(
        env: Env,
        address: Address,
        address_bytes: BytesN<32>,
        timestamp: u64,
        afrx_balance: i128,
        total_balance: i128,
        signature: BytesN<64>,
    ) -> LoyaltyTier {
        Self::require_initialized(&env);

        // -- Gate 1: Ed25519 signature over canonical 72-byte message --------
        // Fix #1: address_bytes are now part of the signed message, binding
        // the payload to a specific account.
        let signing_key: BytesN<32> = env
            .storage()
            .instance()
            .get(&DataKey::RatesSigningKey)
            .unwrap();

        let msg = Self::build_msg(&env, &address_bytes, timestamp, afrx_balance, total_balance);
        env.crypto().ed25519_verify(&signing_key, &msg, &signature);
        // ed25519_verify traps on invalid signature

        // -- Gate 2: timestamp freshness (Fix #3: guard both past and future) -
        let resolution: u64 = env
            .storage()
            .instance()
            .get(&DataKey::Resolution)
            .unwrap();
        let now = env.ledger().timestamp();

        // Reject if too old
        if now > timestamp.saturating_add(resolution) {
            panic_with_error!(&env, Error::RatesTooOld);
        }
        // Fix #3: reject if too far in the future
        if timestamp > now.saturating_add(FUTURE_TOLERANCE) {
            panic_with_error!(&env, Error::RatesTooOld);
        }

        // -- Tier calculation ------------------------------------------------
        let afrx_pct: i128 = if total_balance <= 0 {
            0
        } else {
            (afrx_balance * 100) / total_balance
        };

        // Sort tiers by afrx_req descending, return first where afrx_pct >= afrx_req
        let tiers: Vec<LoyaltyTier> = env
            .storage()
            .instance()
            .get(&DataKey::LoyaltyTiers)
            .unwrap();

        let len = tiers.len();
        let mut indices: Vec<u32> = Vec::new(&env);
        for i in 0..len {
            indices.push_back(i);
        }

        // Bubble sort indices by afrx_req descending (small N, acceptable)
        for i in 0..len {
            for j in 0..len.saturating_sub(1).saturating_sub(i) {
                let a = tiers.get(indices.get(j).unwrap()).unwrap().afrx_req;
                let b = tiers.get(indices.get(j + 1).unwrap()).unwrap().afrx_req;
                if a < b {
                    let tmp = indices.get(j).unwrap();
                    indices.set(j, indices.get(j + 1).unwrap());
                    indices.set(j + 1, tmp);
                }
            }
        }

        for idx in indices.iter() {
            let tier = tiers.get(idx).unwrap();
            if afrx_pct >= tier.afrx_req as i128 {
                env.events().publish(
                    (soroban_sdk::symbol_short!("tier"),),
                    (address.clone(), tier.id.clone()),
                );
                return tier;
            }
        }

        panic_with_error!(&env, Error::LoyaltyTierNotFound);
    }

    // -----------------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------------

    /// Canonical 72-byte message signed by the Afreum backend:
    /// address_bytes(32) || timestamp(8 BE) || afrx_balance(16 BE) || total_balance(16 BE)
    fn build_msg(
        env: &Env,
        address_bytes: &BytesN<32>,
        timestamp: u64,
        afrx_balance: i128,
        total_balance: i128,
    ) -> Bytes {
        let mut msg = Bytes::from(address_bytes.clone());
        msg.append(&Bytes::from_array(env, &timestamp.to_be_bytes()));
        msg.append(&Bytes::from_array(env, &afrx_balance.to_be_bytes()));
        msg.append(&Bytes::from_array(env, &total_balance.to_be_bytes()));
        msg
    }

    /// Validate tier array: must not be empty and must have at least one
    /// catch-all tier (afrx_req = 0) so all users always resolve to a tier.
    fn validate_tiers(env: &Env, tiers: &Vec<LoyaltyTier>) {
        if tiers.is_empty() {
            panic_with_error!(env, Error::EmptyTiers);
        }
        let has_catchall = tiers.iter().any(|t| t.afrx_req == 0);
        if !has_catchall {
            panic_with_error!(env, Error::NoCatchAllTier);
        }
    }

    fn require_initialized(env: &Env) {
        if !env.storage().instance().has(&DataKey::Initialized) {
            panic_with_error!(env, Error::NotInitialized);
        }
    }

    fn require_admin(env: &Env) {
        Self::require_initialized(env);
        let admin: Address = env.storage().instance().get(&DataKey::Admin).unwrap();
        admin.require_auth();
    }
}

// ---------------------------------------------------------------------------
// Free helpers (no_std)
// ---------------------------------------------------------------------------

fn u32_to_string(env: &Env, mut n: u32) -> String {
    if n == 0 {
        return String::from_str(env, "0");
    }
    let mut buf = [0u8; 10];
    let mut pos = 10usize;
    while n > 0 {
        pos -= 1;
        buf[pos] = b'0' + (n % 10) as u8;
        n /= 10;
    }
    String::from_str(env, core::str::from_utf8(&buf[pos..]).unwrap_or("?"))
}

fn u64_to_string(env: &Env, mut n: u64) -> String {
    if n == 0 {
        return String::from_str(env, "0");
    }
    let mut buf = [0u8; 20];
    let mut pos = 20usize;
    while n > 0 {
        pos -= 1;
        buf[pos] = b'0' + (n % 10) as u8;
        n /= 10;
    }
    String::from_str(env, core::str::from_utf8(&buf[pos..]).unwrap_or("?"))
}

/// Encode raw bytes as a lowercase hex string (e.g. 32 bytes → 64 chars).
fn bytes_to_hex(env: &Env, bytes: &[u8]) -> String {
    const HEX: &[u8] = b"0123456789abcdef";
    let mut buf = [0u8; 64]; // max 32 bytes = 64 hex chars
    let len = bytes.len().min(32);
    for i in 0..len {
        buf[i * 2]     = HEX[(bytes[i] >> 4) as usize];
        buf[i * 2 + 1] = HEX[(bytes[i] & 0x0f) as usize];
    }
    String::from_str(env, core::str::from_utf8(&buf[..len * 2]).unwrap_or("?"))
}
