# Ethereum smart-contract threat model

Scope: SAFER's Ethereum fixed-price product escrow, optional price adapter,
wallet ownership link, D1 metadata, and browser wallet boundary. This document
uses the [OWASP Smart Contract Top 10 2026](https://scs.owasp.org/sctop10/) and
the [OWASP SC03 Price Oracle Manipulation guidance](https://scs.owasp.org/sctop10/SC03-PriceOracleManipulation/).

## Trust boundaries and assets

- User private keys remain in an EIP-1193 wallet. The application receives only
  an address, one exact SIWE-style message, and its signature.
- D1 stores the marketplace account/address binding and one-time challenge
  hashes. It is not an authority for token ownership or an on-chain settlement.
- `SaferMarketEscrow` holds only one allowlisted ERC-20 and is the authority for
  funded order state and liabilities.
- Listing descriptions, images, chat, moderation, and shipping information stay
  off-chain; none can alter the signed on-chain amount.
- Admin and arbiter are distinct roles and must be multisigs in production.

## OWASP attack/control mapping

| OWASP item and attack vector | Implemented defense | Verification |
|---|---|---|
| SC01 Access Control: unauthorized pause, dispute resolution, or asset recovery | OpenZeppelin delayed default-admin transfer; separate `ARBITER_ROLE`; participant checks; recovery limited to balances above `totalLiability`. | `testOnlyArbiterCanResolveDispute`; role checks in `SaferMarketEscrow.sol` |
| SC02 Business Logic: invalid state transitions, trapped funds, seller non-delivery | Explicit `None → Funded → Shipped → Released/Disputed` state machine; seller refund; buyer timeout refund; pause stops new exposure but not already-funded exits. | `testBuyerCanRecoverFundsWhenSellerMissesDeadline`; `testPauseBlocksNewFundingButDoesNotTrapExistingBuyerFunds` |
| SC03 Price Oracle Manipulation: flash-loan spot manipulation, short TWAP, stale/stuck feeds, outliers | Core settlement has no oracle: the exact token and amount are bound into the seller's EIP-712 signature. Optional `SaferOracleGuard` requires 3–7 immutable feed addresses, a majority quorum, freshness/completed rounds, 18-decimal normalization, hard bounds, median/outlier filtering, update interval, and maximum price-change circuit breaker; it fails closed. Feed independence and sufficiently long TWAP remain deployment requirements. | Six oracle tests including manipulated spot, stale rounds, source divergence, failure isolation, and abrupt-change rejection |
| SC04 Flash Loan Attacks: temporary liquidity changes an AMM price | No AMM reserve/spot price, balance, or same-transaction voting input is used by escrow. Optional oracle median and persisted change limit prevent a one-block value from directly becoming settlement truth. | Fixed signed amount test and SC03 tests |
| SC05 Lack of Input Validation: zero parties, self-trade, wrong chain/token, zero amount, unbounded deadlines | Constructor and `fund` validate chain, contract code, participants, token, amount, signature deadline, and a maximum 30-day fulfillment window. API validates checksum-compatible addresses, chain IDs, body allowlists, sizes, and signature encodings. | `testFrontRunnerCannotReplaceBoundBuyer`, expired/tampered tests; `lib/web3.ts` and API schema checks |
| SC06 Unchecked External Calls: ERC-20 false return, reverting feed | `SafeERC20`; balance-before/after exactness rejects transfer-tax/rebasing behavior; oracle calls use `try/catch` and still require quorum. | fee-on-transfer and feed-revert tests |
| SC07 Arithmetic/Precision: decimal mismatch, rounding, liability corruption | Solidity 0.8.35 checked arithmetic; fixed token base units; oracle decimals normalized with overflow bounds; even-count median avoids addition overflow; liabilities updated before transfer. | decimal normalization test; Foundry build/tests |
| SC08 Reentrancy: malicious token callback reenters release/refund/fund | `nonReentrant`, checks-effects-interactions, state and liability updated before token calls, one immutable token. | code review plus state/replay tests; production requires fuzz/invariant audit |
| SC09 Integer Overflow/Underflow | Compiler checked arithmetic plus explicit upper bounds before multiplication and liability accounting. | compilation and oracle boundary logic |
| SC10 Proxy/Upgradeability: malicious implementation upgrade or storage collision | Contracts are intentionally non-upgradeable with immutable token/chain/feed configuration. Migration requires a new reviewed deployment and explicit UI/runtime configuration change. | architecture constraint |

## Wallet-link replay and phishing controls

The backend creates the exact message. It contains the HTTPS domain, URI,
Ethereum chain ID, 32-character nonce, issued time, and five-minute expiry. D1
stores only hashes of the challenge token and message. Linking verifies the
logged-in session, same-origin CSRF token, user, chain, address, expiry, exact
message hash, and EOA or ERC-1271-compatible signature. A conditional update
consumes the challenge once before the address is stored. Addresses are unique
per chain. The signed statement explicitly says that it grants no transfer
authority.

## Remaining deployment controls

1. Use Sepolia first; mainnet remains disabled until an independent audit.
2. Verify that each oracle source is economically independent and based on an
   adequate TWAP for the asset/liquidity profile. Multiple addresses from one
   underlying market are not independent sources.
3. Set conservative hard bounds, staleness, deviation, update interval, and
   maximum-change values from documented market-risk analysis.
4. Monitor `EscrowFunded`, dispute, release/refund, pause/role changes, and
   `SafePriceUpdated`; alert on quorum failures, stale state, and liability/balance
   differences.
5. Use multisigs, hardware-backed signers, least privilege, a tested pause and
   recovery runbook, and no private key in source or hosted environment values.
6. Add independent Slither, fuzz/invariant, and manual review results to the
   course report before mainnet activation.
