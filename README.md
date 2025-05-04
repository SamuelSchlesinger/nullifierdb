# NullifierDB

A specialized database for storing and validating cryptographic nullifiers, optimized for zero-knowledge proof systems.

## Overview

NullifierDB provides a fast, reliable way to store and check cryptographic nullifiers:

- Fast O(1) lookups with HashSet-based structure
- Automatic persistence with durability guarantees 
- Robust file corruption handling and repair
- Exclusive file locking for multi-process safety

## API Reference

### Creating and Opening

```rust
// Create new database
let db = NullifierDB::create("/path/to/db")?;

// Open existing database
let db = NullifierDB::recover("/path/to/db")?;
```

### Core Operations

```rust
// Insert nullifier (returns true if new, false if already exists)
let is_new = db.insert(nullifier)?;

// Check if nullifier exists
if db.contains(&nullifier) {
    // Nullifier already used
}

// Get count of nullifiers
let count = db.len();

// Explicitly flush, sync and close
db.flush_and_close()?;
```

## Implementation Details

- **Storage**: 32-byte Curve25519 Scalar values in append-only file
- **Memory**: HashSet for O(1) lookups
- **Durability**: All inserts sync to disk by default
- **Concurrency**: File-level locking prevents concurrent access
- **Error Handling**: Comprehensive error types with context

## Performance Notes

- **Memory Usage**: O(n) - Scales linearly with number of nullifiers
- **Lookup Speed**: O(1) HashSet operations (see benchmarks)
- **Recovery Time**: O(n) - Linear with database size
- **Insert Cost**: Hash computation + file append + sync

## Common Use Cases

- ZK proof systems (nullifier verification)
- Blockchain double-spend prevention
- Cryptographic voting systems (one-time credential verification)
- Privacy-preserving authentication

## Dependencies

- curve25519-dalek: For Curve25519 Scalar operations
