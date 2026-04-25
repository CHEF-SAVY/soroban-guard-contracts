#![no_std]
use soroban_sdk::{contract, contractimpl, Env};

#[contract]
pub struct ProtectedFeeWithdraw;

#[contractimpl]
impl ProtectedFeeWithdraw {
    pub fn placeholder(_env: Env) {}
}
