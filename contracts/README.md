# SAFER Ethereum contracts

The on-chain settlement path is a fixed-price ERC-20 escrow. The seller signs
the exact order using EIP-712 and the buyer funds that order. The core escrow
does **not** read a spot-price oracle, so an oracle cannot change the amount
that the buyer and seller approved.

`SaferOracleGuard` is an optional adapter for a future currency-conversion
feature. It must not be inserted into the escrow path until the selected feeds,
update policy, economic assumptions, and incident response have been audited.

## Local verification

Use Solidity 0.8.35 and Foundry:

```sh
forge fmt --check
forge test
forge build --sizes
```

The tests cover replay, signature tampering, front-running, fee-on-transfer
tokens, reentrancy-sensitive exits, paused exits, stale/incomplete feeds,
single-source manipulation, source divergence, and price-change rate limits.

## Sepolia deployment gate

Start on Sepolia (`11155111`). Before deployment, choose:

- an audited ERC-20 payment token with known decimals and no transfer fee;
- a multisig admin address and a separate multisig arbiter address;
- a private HTTPS RPC endpoint whose hostname is allowlisted;
- monitoring for every escrow, dispute, pause, role, and oracle event.

Deploy `SaferMarketEscrow(admin, arbiter, token, 11155111)`, verify its source on
the explorer, and configure the resulting contract/token addresses as hosted
runtime values. Do not put a private key, seed phrase, or RPC credential in this
repository or a browser bundle. Prefer a hardware wallet or an encrypted
keystore for the deployment transaction.

Mainnet activation is intentionally gated on an independent audit, multisig
runbook exercise, invariant/fuzz testing, and an incident-response drill.
