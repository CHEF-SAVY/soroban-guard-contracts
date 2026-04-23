# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2025-01-01

### Added

- `vulnerable/missing_auth`: token contract with missing `require_auth` on transfer
- `vulnerable/unchecked_math`: staking contract with raw arithmetic overflow
- `vulnerable/unprotected_admin`: admin function without authentication check
- `vulnerable/unsafe_storage`: contract with unsafe storage patterns
- `secure/secure_vault`: vault contract with proper access controls
- `secure/protected_admin`: admin contract with protected functions
- `registry`: registry contract for managing scans and scanners
