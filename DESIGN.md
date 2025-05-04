# NullifierDB Design

## Design Goals

1. **Performance**: Fast O(1) lookups for nullifier verification
2. **Reliability**: Robust error handling and automatic recovery
3. **Durability**: Data persistence with fsync guarantees
4. **Simplicity**: Focused API for nullifier storage and verification

## Architecture

### Storage Model

```
┌─────────────────┐      ┌─────────────────┐
│  In-Memory      │      │  Persistent     │
│  HashSet<Scalar>│◄────►│  Storage File   │
└─────────────────┘      └─────────────────┘
     Fast lookups         Durability guarantees
```

- **Memory**: HashSet provides O(1) lookups
- **Storage**: Append-only file with 32-byte scalar entries
- **Concurrency**: File-level locking for multi-process safety

### Key Operations

#### Insert
1. Check HashSet for existence
2. If new: append to file, flush buffers, sync to disk
3. Return true/false indicating if nullifier was new

#### Recovery
1. Acquire file lock
2. Read all nullifiers sequentially
3. Validate each as canonical Curve25519 Scalar
4. Add valid scalars to HashSet
5. Repair file if needed (truncate to valid boundaries)

## Performance Profile

Operation | Complexity | Bottleneck
----------|------------|----------
Lookup    | O(1)       | HashSet operation (memory)
Insert    | O(1)       | File sync (disk I/O)
Recovery  | O(n)       | File read (disk I/O)

## Error Handling Strategy

- **Comprehensive Error Types**: Detailed context for all failure modes
- **Data Validation**: Verify scalars are canonical when loading
- **Automatic Repair**: Truncate corrupted files to valid boundaries
- **Leak Prevention**: Release locks on error or during drop

## Scalability Constraints

- **Memory Usage**: All nullifiers must fit in memory
- **Maximum Size**: Limited by available RAM
- **Single Writer**: No concurrent write support

## Future Optimizations

1. **Memory Efficiency**: Bloom filter pre-filtering
2. **I/O Performance**: Memory-mapped files, batched operations
3. **Concurrency**: Fine-grained locking or lock-free algorithms
4. **Distribution**: Sharding support for horizontal scaling
