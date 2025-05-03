# NullifierDB Design Document

## Overview

NullifierDB is a specialized database designed for storing and validating cryptographic nullifiers. It is primarily intended for use in zero-knowledge proof systems, blockchain applications, and other cryptographic protocols where preventing double-spending or ensuring uniqueness is critical.

## Core Design Principles

1. **Simplicity**: Focused on a single task - storing and checking nullifiers
2. **Reliability**: Ensures data integrity with proper validation and error handling
3. **Performance**: Optimized for fast lookups and append operations
4. **Durability**: Ensures nullifiers are properly persisted before confirmation

## Technical Architecture

### Data Structures

1. **In-Memory Component**:
   - Uses a `HashSet<Scalar>` for O(1) lookup performance
   - Minimizes memory usage while providing fast access

2. **Persistent Storage**:
   - Simple append-only file format
   - Each nullifier stored as a fixed-size 32-byte Scalar value
   - No indexing or metadata overhead

### Operations

1. **Insert Operation**:
   - Check if nullifier exists in memory (HashSet)
   - If new, append to file and flush to ensure durability
   - Return status indicating whether nullifier was new

2. **Recovery Operation**:
   - Read all nullifiers from file into memory
   - Validate each nullifier as a canonical Curve25519 Scalar
   - Repair file if necessary by truncating to valid 32-byte boundaries
   - Position writer at end of file for future appends

### Error Handling

- Uses `Option<T>` return types to gracefully handle errors
- Validates cryptographic values to ensure database integrity
- Attempts to repair corrupted files during recovery

## Performance Characteristics

### Time Complexity
- Lookup: O(1) - HashSet-based in-memory lookups
- Insert: O(1) - Single append operation to file
- Recovery: O(n) - Linear scan of all nullifiers in the file

### Space Complexity
- Storage: O(n) - Each nullifier requires exactly 32 bytes on disk
- Memory: O(n) - All nullifiers are loaded into memory for fast lookups

## Scalability Considerations

The current implementation has some scalability limitations:

1. **Memory Usage**: All nullifiers are stored in memory, which could become problematic for very large datasets
2. **No Sharding**: No built-in support for distributing data across multiple nodes
3. **Single Writer**: No concurrent write optimizations

For future versions, considerations might include:
- Bloom filter pre-filtering for memory optimization
- Memory-mapped files for improved performance on larger datasets
- Potential B-tree or LSM-tree based storage for better scaling

## Security Considerations

1. **Data Integrity**: Validates all Scalar values to ensure they're canonical
2. **File Corruption**: Handles and repairs file corruption when possible
3. **No Authentication**: Current design does not include access controls or authentication mechanisms

## Use Case Examples

1. **ZK Proof System**:
   - Store nullifiers to prevent double-spending in a privacy-preserving payment system
   - Quickly verify a nullifier hasn't been used before

2. **Blockchain Implementation**:
   - Efficient storage and validation of transaction nullifiers
   - Prevent replay attacks or double-spending

3. **Cryptographic Voting System**:
   - Ensure each voting credential is used only once
   - Maintain voter privacy while preventing fraud