# NullifierDB

A specialized database for storing and validating cryptographic nullifiers, particularly useful in zero-knowledge proof systems.

## Overview

NullifierDB provides an efficient way to store and check membership of cryptographic nullifiers. It's designed to:

1. Store nullifiers as Curve25519 Scalar values
2. Quickly verify if a nullifier has already been used (preventing double-spending)
3. Persist data between sessions with automatic recovery
4. Maintain data integrity

## Technical Implementation

- **Storage Format**: Nullifiers are stored as 32-byte values (Curve25519 Scalar)
- **In-Memory Structure**: HashSet for O(1) lookups
- **Persistence**: File-based storage with automatic recovery
- **Error Handling**: Graceful handling of file corruption

## API Reference

### `NullifierDB::insert`

```rust
pub fn insert(&mut self, scalar: Scalar) -> Option<bool>
```

Inserts a new nullifier into the database.

- **Parameters**:
  - `scalar`: The Curve25519 Scalar value to insert
- **Returns**:
  - `Some(true)`: If the nullifier was new and successfully inserted
  - `Some(false)`: If the nullifier already existed in the database
  - `None`: If an error occurred during insertion

### `NullifierDB::recover`

```rust
pub fn recover(path: &Path) -> Option<NullifierDB>
```

Recovers a NullifierDB from an existing file.

- **Parameters**:
  - `path`: Path to the database file
- **Returns**:
  - `Some(NullifierDB)`: If recovery was successful
  - `None`: If the file doesn't exist or is corrupted

## Technical Notes

1. The database automatically handles file corruption by:
   - Validating all loaded Scalar values
   - Truncating files to valid 32-byte boundaries
   - Positioning the writer at the end of the file for append operations

2. The implementation uses a combination of:
   - In-memory HashSet for fast lookups
   - Sequential file writes for durability
   - BufWriter for improved write performance

3. Recovery process:
   - Reads all nullifiers from the file
   - Builds an in-memory HashSet
   - Repairs file if necessary (truncating to valid 32-byte boundaries)
   - Positions writer at the end for future appends

## Use Cases

Ideal for applications requiring cryptographic uniqueness guarantees, such as:

- Zero-knowledge proof systems
- Blockchain implementations (preventing double-spending)
- Cryptocurrency mixers
- Privacy-preserving authentication systems

## Dependencies

- curve25519-dalek (v4.1.3): For Scalar operations on the Curve25519 elliptic curve
