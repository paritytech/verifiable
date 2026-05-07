# Verifiable

Cryptographic proof of membership in a set without revealing which member produced
the proof. Built on ring VRFs, it provides unlinkable, deterministic pseudonymic
aliases under each context.

A member proves they belong to a group (identified by a `Members` commitment)
under a given `context`, producing a `Proof` and a context-specific `Alias`.
Different contexts yield unlinkable aliases for the same member. An optional
`message` can be bound to the proof.

## Core trait

The [`Verifiable`] trait defines the full API:

- **Ring construction**: `start_members` / `push_members` / `finish_members`
  build a `Members` commitment from public keys.
- **Proof creation** (prover-side, behind the `prover` feature):
  `open` prepares a commitment, then `create` (single context) or
  `create_multi_context` (multiple contexts in one proof) produces the proof
  and alias(es).
- **Proof validation**: `validate` / `validate_multi_context` verify a proof
  and return the alias(es). `batch_validate` verifies multiple independent proofs
  efficiently.
- **Plain signatures**: `sign` / `verify_signature` for non-anonymous signatures
  attributable to a specific member.

A [`Receipt`] convenience type bundles a proof with its alias and message for
the common single-context workflow.

## Implementation

The provided implementation uses the Bandersnatch curve (BLS12-381 pairing)
via [`ark-vrf`](https://github.com/davxy/ark-vrf):

- `RingVrfVerifiable<S>` -- generic over any `RingSuiteExt` suite
- `BandersnatchVrfVerifiable` -- concrete type alias for the Bandersnatch suite

Ring capacity is configured via `RingDomainSize` (2^11, 2^12, or 2^16),
supporting up to 16127 members.

## Features

| Feature | Description |
|---|---|
| `std` (default) | Enables `prover`, std support, and parallel proving |
| `prover` | Proof generation (`open`, `create`, `create_multi_context`) |
| `builder-params` | Includes precomputed ring builder params for building ring commitments |
| `no-std-prover` | Deterministic prover for `no_std` environments (testing only) |
| `mock` | Exposes the `mock` module with a non-cryptographic `Mock` implementation for tests |

For verifier-only builds (e.g. on-chain), disable default features.

## License

GPL-3.0-or-later WITH Classpath-exception-2.0
