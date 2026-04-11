# soroban-guard-contracts

A library of sample Soroban smart contracts — both vulnerable and secure — used
for testing the [Soroban Guard](https://github.com/Veritas-Vaults-Network/soroban-guard-core)
scanner, plus an on-chain scan result registry.

Part of the [Veritas Vaults Network](https://github.com/Veritas-Vaults-Network) org.

---

## Sister repos

| Repo | Purpose |
|---|---|
| [soroban-guard-core](https://github.com/Veritas-Vaults-Network/soroban-guard-core) | CLI scanner |
| [soroban-guard-web](https://github.com/Veritas-Vaults-Network/soroban-guard-web) | Web dashboard |

---

## Project structure

```
soroban-guard-contracts/
├── vulnerable/
│   ├── missing_auth/       # transfer() with no require_auth()
│   ├── unchecked_math/     # staking rewards with raw u64 arithmetic
│   ├── unprotected_admin/  # set_admin() / upgrade() open to anyone
│   └── unsafe_storage/     # public writes to any account's storage slot
├── secure/
│   ├── secure_vault/       # fixed token: auth + checked math
│   └── protected_admin/    # fixed admin + profile registry
├── registry/               # on-chain scan result registry contract
├── docs/
│   └── vulnerabilities.md  # explains each vulnerability with examples
├── CONTRIBUTING.md
└── Cargo.toml
```

---

## Contracts

### Vulnerable

| Crate | Context | Vulnerability |
|---|---|---|
| `missing_auth` | Token contract | `transfer()` mutates balances without `require_auth()` |
| `unchecked_math` | Staking contract | Reward calc uses raw `*` on `u64` — overflows silently |
| `unprotected_admin` | Escrow contract | `set_admin()` and `upgrade()` have no caller check |
| `unsafe_storage` | KYC registry | Any caller can write to any account's storage slot |

### Secure

| Crate | Fixes |
|---|---|
| `secure_vault` | `require_auth` on transfer + `checked_sub`/`checked_add` |
| `protected_admin` | Admin auth on `set_admin`/`upgrade` + account auth on profile writes |

### Registry

`registry` — an on-chain contract that stores scan findings keyed by contract
address. Only verified scanners (managed by the admin) can submit results.
Supports full scan history per contract.

```
submit_scan(scanner, contract_address, findings_hash, severity_counts)
get_scan(contract_address) -> Option<ScanResult>
get_history(contract_address) -> Vec<ScanResult>
```

---

## Quick start

```bash
# Build all contracts
cargo build

# Run all tests
cargo test

# Run tests for a single contract
cargo test -p missing-auth
cargo test -p registry
```

See [CONTRIBUTING.md](./CONTRIBUTING.md) for full setup instructions and how to
add new vulnerable contract examples.

---

## Vulnerability reference

See [docs/vulnerabilities.md](./docs/vulnerabilities.md) for a detailed
explanation of each vulnerability class with code examples and fixes.
