//! SECURE: Admin-gated Pause
//!
//! Fixes `unprotected_pause` by requiring admin auth before `pause()` or
//! `unpause()` can be called.
//!
//! FIX: `admin.require_auth()` in both `pause()` and `unpause()`.

#![no_std]
use soroban_sdk::{contract, contractimpl, contracttype, Address, Env};

#[contracttype]
pub enum DataKey {
    Admin,
    Paused,
    Balance(Address),
}

#[contract]
pub struct SecurePausable;

#[contractimpl]
impl SecurePausable {
    pub fn initialize(env: Env, admin: Address) {
        if env.storage().persistent().has(&DataKey::Admin) {
            panic!("already initialized");
        }
        env.storage().persistent().set(&DataKey::Admin, &admin);
        env.storage().persistent().set(&DataKey::Paused, &false);
    }

    /// ✅ Only the admin can pause the contract.
    pub fn pause(env: Env) {
        let admin: Address = env
            .storage()
            .persistent()
            .get(&DataKey::Admin)
            .expect("not initialized");
        admin.require_auth();
        env.storage().persistent().set(&DataKey::Paused, &true);
    }

    /// ✅ Only the admin can unpause the contract.
    pub fn unpause(env: Env) {
        let admin: Address = env
            .storage()
            .persistent()
            .get(&DataKey::Admin)
            .expect("not initialized");
        admin.require_auth();
        env.storage().persistent().set(&DataKey::Paused, &false);
    }

    pub fn mint(env: Env, to: Address, amount: i128) {
        let key = DataKey::Balance(to);
        let current: i128 = env.storage().persistent().get(&key).unwrap_or(0);
        env.storage().persistent().set(&key, &(current + amount));
    }

    pub fn transfer(env: Env, from: Address, to: Address, amount: i128) {
        let paused: bool = env
            .storage()
            .persistent()
            .get(&DataKey::Paused)
            .unwrap_or(false);
        if paused {
            panic!("contract is paused");
        }

        from.require_auth();

        let from_key = DataKey::Balance(from.clone());
        let to_key = DataKey::Balance(to);
        let from_bal: i128 = env.storage().persistent().get(&from_key).unwrap_or(0);
        env.storage()
            .persistent()
            .set(&from_key, &(from_bal - amount));
        let to_bal: i128 = env.storage().persistent().get(&to_key).unwrap_or(0);
        env.storage().persistent().set(&to_key, &(to_bal + amount));
    }

    pub fn balance(env: Env, account: Address) -> i128 {
        env.storage()
            .persistent()
            .get(&DataKey::Balance(account))
            .unwrap_or(0)
    }

    pub fn is_paused(env: Env) -> bool {
        env.storage()
            .persistent()
            .get(&DataKey::Paused)
            .unwrap_or(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::{testutils::Address as _, Address, Env};

    fn setup() -> (Env, Address, SecurePausableClient<'static>) {
        let env = Env::default();
        let contract_id = env.register_contract(None, SecurePausable);
        let client = SecurePausableClient::new(&env, &contract_id);
        let admin = Address::generate(&env);
        client.initialize(&admin);
        (env, admin, client)
    }

    #[test]
    fn test_admin_can_pause_and_unpause() {
        let (env, _admin, client) = setup();
        env.mock_all_auths();

        client.pause();
        assert!(client.is_paused());

        client.unpause();
        assert!(!client.is_paused());
    }

    /// Attacker cannot pause — require_auth enforces admin-only access.
    #[test]
    #[should_panic]
    fn test_attacker_cannot_pause() {
        let (_env, _admin, client) = setup();
        // No mock_all_auths — should panic because admin auth is required.
        client.pause();
    }

    #[test]
    #[should_panic(expected = "contract is paused")]
    fn test_transfer_fails_when_paused() {
        let (env, _admin, client) = setup();

        let alice = Address::generate(&env);
        client.mint(&alice, &1000);

        env.mock_all_auths();
        client.pause();

        let bob = Address::generate(&env);
        client.transfer(&alice, &bob, &500);
    }

    #[test]
    fn test_transfer_succeeds_when_unpaused() {
        let (env, _admin, client) = setup();

        let alice = Address::generate(&env);
        let bob = Address::generate(&env);
        client.mint(&alice, &1000);

        env.mock_all_auths();
        client.transfer(&alice, &bob, &400);

        assert_eq!(client.balance(&alice), 600);
        assert_eq!(client.balance(&bob), 400);
    }
}
