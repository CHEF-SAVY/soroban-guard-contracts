//! VULNERABLE: Flash loan lender without repayment checks.
//!
//! This contract exposes `flash_loan`, which transfers funds and invokes an
//! external callback without verifying the loan was returned.
//! `flash_loan_secure` fixes the vulnerability by verifying the lender's
//! balance after the callback.

#![no_std]

use soroban_sdk::{contract, contractimpl, contracttype, Address, Env};

#[contracttype]
pub enum DataKey {
    Balance(Address),
    Lender,
}

#[contract]
pub struct FlashLoanNoCheck;

#[contract]
pub trait FlashLoanReceiver {
    fn on_flash_loan(&self, amount: i128);
}

pub mod callback {
    pub use super::FlashLoanReceiverClient as Client;
}

#[contract]
pub struct Borrower;

#[contracttype]
pub enum BorrowerConfigKey {
    Lender,
    BorrowerAddress,
    ShouldRepay,
}

#[contractimpl]
impl FlashLoanNoCheck {
    fn get_balance(env: &Env, account: Address) -> i128 {
        env.storage()
            .persistent()
            .get(&DataKey::Balance(account))
            .unwrap_or(0)
    }

    fn set_balance(env: &Env, account: Address, amount: i128) {
        env.storage()
            .persistent()
            .set(&DataKey::Balance(account), &amount);
    }

    pub fn initialize(env: Env, lender_address: Address) {
        env.storage()
            .persistent()
            .set(&DataKey::Lender, &lender_address);
    }

    fn get_lender_address(env: &Env) -> Address {
        env.storage()
            .persistent()
            .get(&DataKey::Lender)
            .expect("lender not initialized")
    }

    pub fn mint(env: Env, to: Address, amount: i128) {
        let current = Self::get_balance(&env, to.clone());
        let new_balance = current.checked_add(amount).expect("mint: overflow");
        Self::set_balance(&env, to, new_balance);
    }

    pub fn transfer(env: Env, from: Address, to: Address, amount: i128) {
        let from_balance = Self::get_balance(&env, from.clone());
        let to_balance = Self::get_balance(&env, to.clone());

        let new_from = from_balance
            .checked_sub(amount)
            .expect("transfer: insufficient balance");
        let new_to = to_balance.checked_add(amount).expect("transfer: overflow");

        Self::set_balance(&env, from, new_from);
        Self::set_balance(&env, to, new_to);
    }

    pub fn balance(env: Env, account: Address) -> i128 {
        Self::get_balance(&env, account)
    }

    pub fn flash_loan(env: Env, borrower: Address, amount: i128) {
        let lender_address = Self::get_lender_address(&env);
        let lender_balance = Self::get_balance(&env, lender_address.clone());
        assert!(
            lender_balance >= amount,
            "flash_loan: insufficient liquidity"
        );

        // ❌ VULNERABLE: funds are transferred to the borrower, but we do not
        // verify that the loan was returned after the callback.
        Self::transfer(env.clone(), lender_address.clone(), borrower.clone(), amount);
        callback::Client::new(&env, &borrower).on_flash_loan(&amount);
    }

    pub fn flash_loan_secure(env: Env, borrower: Address, amount: i128) {
        let lender_address = Self::get_lender_address(&env);
        let initial_balance = Self::get_balance(&env, lender_address.clone());
        assert!(
            initial_balance >= amount,
            "flash_loan_secure: insufficient liquidity"
        );

        Self::transfer(env.clone(), lender_address.clone(), borrower.clone(), amount);
        callback::Client::new(&env, &borrower).on_flash_loan(&amount);

        let final_balance = Self::get_balance(&env, lender_address);
        assert!(
            final_balance >= initial_balance,
            "Flash loan not repaid"
        );
    }
}

#[contractimpl]
impl Borrower {
    pub fn configure(env: Env, lender: Address, borrower_address: Address, should_repay: bool) {
        env.storage()
            .persistent()
            .set(&BorrowerConfigKey::Lender, &lender);
        env.storage()
            .persistent()
            .set(&BorrowerConfigKey::BorrowerAddress, &borrower_address);
        env.storage()
            .persistent()
            .set(&BorrowerConfigKey::ShouldRepay, &should_repay);
    }

    pub fn on_flash_loan(env: Env, amount: i128) {
        let should_repay: bool = env
            .storage()
            .persistent()
            .get(&BorrowerConfigKey::ShouldRepay)
            .unwrap_or(false);

        if !should_repay {
            return;
        }

        let lender: Address = env
            .storage()
            .persistent()
            .get(&BorrowerConfigKey::Lender)
            .expect("borrower lender not configured");
        let borrower_address: Address = env
            .storage()
            .persistent()
            .get(&BorrowerConfigKey::BorrowerAddress)
            .expect("borrower address not configured");

        FlashLoanNoCheckClient::new(&env, &lender).transfer(&borrower_address, &lender, &amount);
    }
}

#[cfg(test)]
mod tests;
