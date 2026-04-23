# Soroban Vulnerability Reference

Each entry maps to a contract in `vulnerable/` and its secure mirror in `secure/`.

---

## 1. Missing Authorization (`missing_auth`)

**Contract:** `vulnerable/missing_auth` → `secure/secure_vault`

### What it is

Soroban's auth model requires every state-mutating function to call
`address.require_auth()` for the address whose resources are being modified.
Without this call the Soroban host places no restriction on who can invoke the
function — any account can submit a valid transaction.

### Vulnerable code

```rust
pub fn transfer(env: Env, from: Address, to: Address, amount: i128) {
    // ❌ No require_auth — anyone can drain `from`
    let from_balance = env.storage().persistent().get(&DataKey::Balance(from.clone())).unwrap_or(0);
    env.storage().persistent().set(&DataKey::Balance(from), &(from_balance - amount));
}
```

### Secure fix

```rust
pub fn transfer(env: Env, from: Address, to: Address, amount: i128) {
    from.require_auth(); // ✅ Only `from` can authorise this transfer
    // ...
}
```

### Impact

- Complete fund theft: any attacker can transfer the entire balance of any account.
- Severity: **Critical**

---

## 2. Unchecked Arithmetic (`unchecked_math`)

**Contract:** `vulnerable/unchecked_math` → `secure/secure_vault`

### What it is

Rust's integer types wrap on overflow in `--release` builds unless
`overflow-checks = true` is set in the Cargo profile. Even with that flag,
relying on a panic is not the same as explicitly handling the error. The correct
approach is `checked_mul` / `checked_add` which return `Option` and force the
developer to handle the overflow case.

### Vulnerable code

```rust
// ❌ Raw * — overflows silently without overflow-checks = true
let reward = staked * rate * elapsed;
```

### Secure fix

```rust
let reward = staked
    .checked_mul(rate).expect("reward: overflow")
    .checked_mul(elapsed).expect("reward: overflow");
```

### Impact

- Reward calculation produces wildly incorrect values (wraps to near-zero or
  near-max), enabling either free reward extraction or denial of rewards.
- Severity: **High**

---

## 3. Unprotected Admin Functions (`unprotected_admin`)

**Contract:** `vulnerable/unprotected_admin` → `secure/protected_admin`

### What it is

Admin-only functions (`set_admin`, `upgrade`) that do not verify the caller is
the current admin. Because Soroban does not have implicit access control, any
account can call these functions and take over the contract.

### Vulnerable code

```rust
pub fn set_admin(env: Env, new_admin: Address) {
    // ❌ No require_auth on the current admin
    env.storage().persistent().set(&DataKey::Admin, &new_admin);
}

pub fn upgrade(env: Env, new_wasm_hash: BytesN<32>) {
    // ❌ Anyone can replace the contract WASM
    env.deployer().update_current_contract_wasm(new_wasm_hash);
}
```

### Secure fix

```rust
pub fn set_admin(env: Env, new_admin: Address) {
    let current: Address = env.storage().persistent().get(&DataKey::Admin).unwrap();
    current.require_auth(); // ✅ Only the current admin can rotate
    env.storage().persistent().set(&DataKey::Admin, &new_admin);
}
```

### Impact

- Full contract takeover: attacker becomes admin and can drain funds, upgrade
  to malicious WASM, or brick the contract.
- Severity: **Critical**

---

## 4. Unsafe Storage Writes (`unsafe_storage`)

**Contract:** `vulnerable/unsafe_storage` → `secure/protected_admin`

### What it is

A public function that writes to persistent storage keyed by an `Address`
argument without verifying the caller owns that address. Any account can pass
any address and overwrite that account's data.

### Vulnerable code

```rust
pub fn set_profile(env: Env, account: Address, display_name: String, kyc_level: u32) {
    // ❌ No require_auth — anyone can write to any account's slot
    env.storage().persistent().set(&DataKey::Profile(account), &Profile { display_name, kyc_level });
}
```

### Secure fix

```rust
pub fn set_profile(env: Env, account: Address, display_name: String, kyc_level: u32) {
    account.require_auth(); // ✅ Only the account owner can update their profile
    env.storage().persistent().set(&DataKey::Profile(account), &Profile { display_name, kyc_level });
}
```

### Impact

- Data integrity violation: KYC levels, display names, or any stored metadata
  can be forged or wiped by any attacker.
- Severity: **High**

---

## 5. Missing Events (`missing_events`)

**Contract:** `vulnerable/missing_events` → `secure/secure_vault`

### What it is

Soroban contracts should emit events for all state changes using
`env.events().publish()` so that off-chain indexers, wallets, and users can
track contract activity. Without events, external systems cannot reliably
monitor token mints, burns, or other state mutations, leading to inconsistent
views of the contract state.

### Vulnerable code

```rust
pub fn mint(env: Env, to: Address, amount: i128) {
    // ❌ No env.events().publish() — off-chain indexers are blind to this
    let key = DataKey::Balance(to);
    let current: i128 = env.storage().persistent().get(&key).unwrap_or(0);
    env.storage().persistent().set(&key, &(current + amount));
}

pub fn burn(env: Env, from: Address, amount: i128) {
    // ❌ No env.events().publish() — off-chain indexers are blind to this
    let key = DataKey::Balance(from);
    let current: i128 = env.storage().persistent().get(&key).unwrap_or(0);
    env.storage().persistent().set(&key, &(current - amount));
}
```

### Secure fix

```rust
pub fn mint(env: Env, to: Address, amount: i128) {
    // ... state mutation ...
    env.events().publish((symbol_short!("mint"),), (to, amount)); // ✅ Emit event
}

pub fn burn(env: Env, from: Address, amount: i128) {
    from.require_auth();
    // ... state mutation ...
    env.events().publish((symbol_short!("burn"),), (from, amount)); // ✅ Emit event
}
```

### Impact

- Off-chain tracking failure: Indexers, wallets, and explorers cannot track
  token supply changes, leading to incorrect balances and transaction histories.
- Inconsistent state views: Different indexers may have different views of
  total supply and account balances.
- Severity: **Medium**

---

## General Soroban Security Checklist

| Check | Description |
|---|---|
| `require_auth` on every mutating fn | Every function that reads or writes resources belonging to an address must call `address.require_auth()` |
| Checked arithmetic | Use `checked_add`, `checked_sub`, `checked_mul` for all financial calculations |
| Admin gate on privileged fns | `initialize`, `upgrade`, `set_admin`, `pause` must verify the caller is the stored admin |
| Storage key ownership | Storage keys that include an `Address` must only be written after `address.require_auth()` |
| Event emission on state changes | Every state-mutating function must call `env.events().publish()` with relevant data for off-chain tracking |
| No re-initialization | Guard `initialize` with a check that the contract hasn't already been set up |
