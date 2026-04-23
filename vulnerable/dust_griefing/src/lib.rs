//! VULNERABLE: Dust Griefing via Unrestricted Deposits
//!
//! A vault contract where `deposit()` accepts any amount, including 1-unit
//! "dust" deposits. An attacker can create thousands of tiny deposits across
//! many addresses, bloating persistent storage and inflating TTL extension
//! costs for all legitimate users.
//!
//! VULNERABILITY: No minimum deposit threshold — `deposit(1)` is valid.

#![no_std]
use soroban_sdk::{contract, contractimpl, contracttype, Address, Env};

#[contracttype]
pub enum DataKey {
    Balance(Address),
}

fn get_balance(env: &Env, user: &Address) -> i128 {
    env.storage()
        .persistent()
        .get(&DataKey::Balance(user.clone()))
        .unwrap_or(0)
}

fn set_balance(env: &Env, user: &Address, amount: i128) {
    env.storage()
        .persistent()
        .set(&DataKey::Balance(user.clone()), &amount);
}

#[contract]
pub struct DustGriefingVault;

#[contractimpl]
impl DustGriefingVault {
    /// VULNERABLE: accepts any amount >= 1, including dust (e.g. 1 unit).
    /// Missing: assert!(amount >= MIN_DEPOSIT, "below minimum");
    pub fn deposit(env: Env, user: Address, amount: i128) {
        user.require_auth();
        // ❌ No minimum deposit check — dust deposits bloat storage
        let bal = get_balance(&env, &user);
        set_balance(&env, &user, bal + amount);
    }

    pub fn balance(env: Env, user: Address) -> i128 {
        get_balance(&env, &user)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::{testutils::Address as _, Address, Env};

    #[test]
    fn test_normal_deposit_works() {
        let env = Env::default();
        let contract_id = env.register_contract(None, DustGriefingVault);
        let client = DustGriefingVaultClient::new(&env, &contract_id);

        let alice = Address::generate(&env);
        env.mock_all_auths();
        client.deposit(&alice, &1_000_000);
        assert_eq!(client.balance(&alice), 1_000_000);
    }

    /// Demonstrates the vulnerability: a dust deposit of 1 unit succeeds.
    /// An attacker can repeat this across thousands of addresses to bloat storage.
    #[test]
    fn test_dust_deposit_succeeds() {
        let env = Env::default();
        let contract_id = env.register_contract(None, DustGriefingVault);
        let client = DustGriefingVaultClient::new(&env, &contract_id);

        let attacker = Address::generate(&env);
        env.mock_all_auths();
        // ❌ Dust deposit of 1 unit is accepted — demonstrates the vulnerability
        client.deposit(&attacker, &1);
        assert_eq!(client.balance(&attacker), 1);
    }
}
