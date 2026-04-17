use soroban_sdk::{contracttype, Address, String};

#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub struct LoyaltyTier {
    pub id: String,
    pub name: String,
    pub bonus_asset: String,
    pub bonus_issuer: Address,
    pub withdrawal_fee: String,
    pub active: String,
    // 30-day period
    pub afr_apy_30: String,
    pub afr_bonus_30: String,
    pub afrx_apy_30: String,
    pub afrx_bonus_30: String,
    pub axxx_apy_30: String,
    pub axxx_bonus_30: String,
    pub fiat_apy_30: String,
    pub fiat_bonus_30: String,
    // 90-day period
    pub afr_apy_90: String,
    pub afr_bonus_90: String,
    pub afrx_apy_90: String,
    pub afrx_bonus_90: String,
    pub axxx_apy_90: String,
    pub axxx_bonus_90: String,
    pub fiat_apy_90: String,
    pub fiat_bonus_90: String,
    // 180-day period
    pub afr_apy_180: String,
    pub afr_bonus_180: String,
    pub afrx_apy_180: String,
    pub afrx_bonus_180: String,
    pub axxx_apy_180: String,
    pub axxx_bonus_180: String,
    pub fiat_apy_180: String,
    pub fiat_bonus_180: String,
    // Tier config
    pub afrx_req: u32,
    pub bonus_asset_type: String,
    pub logo: String,
    pub general_fee: String,
    pub trading_fee: String,
}

#[contracttype]
pub enum DataKey {
    Initialized,
    Admin,
    Decimals,
    AllowedIssuers,
    LoyaltyTiers,
    RatesSigningKey,
    Resolution,
}
