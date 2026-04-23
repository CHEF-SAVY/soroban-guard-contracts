//! VULNERABLE: Allowance is not decremented after `transfer_from`.
//!
//! This ERC20-like token exposes `approve`, `transfer`, and `transfer_from`.
//! The vulnerable version allows a spender to reuse the same allowance
//! indefinitely because `transfer_from` does not decrement it.

#![no_std]

use soroban_sdk::{contract, contractimpl, contracttype, Address, Env};

#[contracttype]
pub enum DataKey {
    Balance(Address),
    Allowance(Address, Address),
}

fn get_balance(env: &Env, account: &Address) -> i128 {
    env.storage()
        .persistent()
        .get(&DataKey::Balance(account.clone()))
        .unwrap_or(0)
}

fn set_balance(env: &Env, account: &Address, amount: i128) {
    env.storage()
        .persistent()
        .set(&DataKey::Balance(account.clone()), &amount);
}

fn get_allowance(env: &Env, owner: &Address, spender: &Address) -> i128 {
    env.storage()
        .persistent()
        .get(&DataKey::Allowance(owner.clone(), spender.clone()))
        .unwrap_or(0)
}

fn set_allowance(env: &Env, owner: &Address, spender: &Address, amount: i128) {
    env.storage()
        .persistent()
        .set(&DataKey::Allowance(owner.clone(), spender.clone()), &amount);
}

fn do_transfer(env: &Env, from: &Address, to: &Address, amount: i128) {
    let from_balance = get_balance(env, from);
    let to_balance = get_balance(env, to);

    let new_from = from_balance
        .checked_sub(amount)
        .expect("transfer: insufficient balance");
    let new_to = to_balance.checked_add(amount).expect("transfer: overflow");

    set_balance(env, from, new_from);
    set_balance(env, to, new_to);
}

#[contract]
pub struct AllowanceNotDecrementedToken;

#[contractimpl]
impl AllowanceNotDecrementedToken {
    pub fn mint(env: Env, to: Address, amount: i128) {
        let current = get_balance(&env, &to);
        let next = current.checked_add(amount).expect("mint: overflow");
        set_balance(&env, &to, next);
    }

    pub fn approve(env: Env, owner: Address, spender: Address, amount: i128) {
        owner.require_auth();
        set_allowance(&env, &owner, &spender, amount);
    }

    pub fn transfer(env: Env, from: Address, to: Address, amount: i128) {
        from.require_auth();
        do_transfer(&env, &from, &to, amount);
    }

    pub fn transfer_from(
        env: Env,
        spender: Address,
        from: Address,
        to: Address,
        amount: i128,
    ) {
        spender.require_auth();

        let allowance = get_allowance(&env, &from, &spender);
        assert!(allowance >= amount, "transfer_from: allowance insufficient");

        // ❌ VULNERABILITY: allowance is never decremented.
        // The spender can reuse the same allowance multiple times.
        do_transfer(&env, &from, &to, amount);
    }

    pub fn transfer_from_secure(
        env: Env,
        spender: Address,
        from: Address,
        to: Address,
        amount: i128,
    ) {
        spender.require_auth();

        let allowance = get_allowance(&env, &from, &spender);
        assert!(allowance >= amount, "transfer_from_secure: allowance insufficient");

        do_transfer(&env, &from, &to, amount);
        set_allowance(&env, &from, &spender, allowance - amount);
    }

    pub fn balance(env: Env, account: Address) -> i128 {
        get_balance(&env, &account)
    }

    pub fn allowance(env: Env, owner: Address, spender: Address) -> i128 {
        get_allowance(&env, &owner, &spender)
    }
}
