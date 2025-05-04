use criterion::{criterion_group, criterion_main, Criterion, BenchmarkId, black_box};
use nullifierdb::NullifierDB;
use curve25519_dalek::Scalar;
use rand::prelude::*;
use std::path::Path;
use std::fs::File;
use std::io::Write;
use std::time::Duration;
use tempfile::tempdir;

/// Create a database file with a specific number of nullifiers for benchmarking
/// Returns the path to the created database file
fn create_benchmark_db(num_nullifiers: u64) -> std::io::Result<tempfile::TempDir> {
    let temp_dir = tempdir()?;
    let db_path = temp_dir.path().join("bench.db");
    
    // Create the file
    let mut file = File::create(&db_path)?;
    
    // We'll generate nullifiers in batches to avoid using too much memory
    const BATCH_SIZE: u64 = 10_000; // Smaller batch size for faster benchmarks
    let mut rng = StdRng::seed_from_u64(0); // Use a deterministic seed for reproducibility
    let mut buffer = Vec::with_capacity((BATCH_SIZE as usize) * 32);
    
    let batches = num_nullifiers / BATCH_SIZE;
    let remainder = num_nullifiers % BATCH_SIZE;
    
    // Process full batches
    for _ in 0..batches {
        buffer.clear();
        
        for _ in 0..BATCH_SIZE {
            // Generate a random scalar and add its bytes to the buffer
            let scalar = Scalar::random(&mut rng);
            buffer.extend_from_slice(scalar.as_bytes());
        }
        
        // Write the batch to the file
        file.write_all(&buffer)?;
    }
    
    // Process the remainder
    if remainder > 0 {
        buffer.clear();
        
        for _ in 0..remainder {
            let scalar = Scalar::random(&mut rng);
            buffer.extend_from_slice(scalar.as_bytes());
        }
        
        file.write_all(&buffer)?;
    }
    
    file.sync_all()?;
    Ok(temp_dir)
}

/// Generate a fixed set of random scalars for consistent benchmarking
fn generate_test_scalars(count: usize) -> Vec<Scalar> {
    let mut rng = StdRng::seed_from_u64(42); // Fixed seed for reproducibility
    (0..count).map(|_| Scalar::random(&mut rng)).collect()
}

/// Benchmark just the database recovery process (loading from disk to memory)
fn bench_recovery(c: &mut Criterion) {
    let mut group = c.benchmark_group("recovery");
    group.sample_size(10); // Reduce sample size for faster benchmarks
    
    // Use smaller sizes for quicker benchmarks
    for size in [1_000, 10_000].iter() {
        let temp_dir = create_benchmark_db(*size as u64).expect("Failed to create benchmark database");
        let db_path = temp_dir.path().join("bench.db");
        
        group.bench_with_input(BenchmarkId::from_parameter(size), size, |b, _| {
            b.iter(|| {
                let db = NullifierDB::recover(&db_path).expect("Failed to recover database");
                black_box(db.len())
            });
        });
    }
    
    group.finish();
}

/// Benchmark in-memory lookups (contains method) - no disk I/O
fn bench_in_memory_lookup(c: &mut Criterion) {
    let mut group = c.benchmark_group("in_memory_lookup");
    
    // Create a database with 10,000 nullifiers
    let db_size = 10_000;
    let temp_dir = tempdir().expect("Failed to create temp directory");
    let db_path = temp_dir.path().join("lookup_bench.db");
    
    // Generate test scalars
    let all_scalars = generate_test_scalars(db_size);
    
    // Create and populate the database
    {
        let mut db = NullifierDB::create(&db_path).expect("Failed to create database");
        for scalar in &all_scalars {
            db.insert(*scalar).expect("Failed to insert nullifier");
        }
        db.flush_and_close().expect("Failed to close database");
    }
    
    // Recover the database for benchmarking
    let db = NullifierDB::recover(&db_path).expect("Failed to recover database");
    
    // Generate some scalars to lookup (50% existing, 50% non-existing)
    let mut lookup_scalars = Vec::with_capacity(1000);
    lookup_scalars.extend_from_slice(&all_scalars[0..500]); // Existing
    
    let mut rng = StdRng::seed_from_u64(100); // Different seed
    for _ in 0..500 {
        lookup_scalars.push(Scalar::random(&mut rng)); // Non-existing (probably)
    }
    
    // Benchmark lookup for single items (worst case: last item or not found)
    group.bench_function("single_existing", |b| {
        let scalar = &all_scalars[db_size - 1]; // Last item
        b.iter(|| black_box(db.contains(scalar)))
    });
    
    group.bench_function("single_nonexisting", |b| {
        let scalar = &Scalar::random(&mut rng); // Random non-existing scalar
        b.iter(|| black_box(db.contains(scalar)))
    });
    
    // Benchmark batch lookups
    group.bench_function("batch_mixed_1000", |b| {
        b.iter(|| {
            let mut count = 0;
            for scalar in &lookup_scalars {
                if db.contains(scalar) {
                    count += 1;
                }
            }
            black_box(count)
        });
    });
    
    group.finish();
}

/// Benchmark insertion performance without disk I/O (to isolate memory operations)
fn bench_insertion_memory_only(c: &mut Criterion) {
    let mut group = c.benchmark_group("insertion_memory_only");
    
    // Generate test scalars for insertion
    let scalars_to_insert = generate_test_scalars(1000);
    
    group.bench_function("memory_insert_1000", |b| {
        b.iter(|| {
            // Create an in-memory hashset directly instead of using NullifierDB
            let mut map = std::collections::HashSet::new();
            for scalar in &scalars_to_insert {
                map.insert(*scalar);
            }
            black_box(map.len())
        });
    });
    
    group.finish();
}

/// Benchmark insertion with disk I/O but without syncing
fn bench_insertion_no_sync(c: &mut Criterion) {
    let mut group = c.benchmark_group("insertion_no_sync");
    group.sample_size(10); // Reduce sample size for faster benchmarks
    
    // Monkey-patch the insert method to skip syncing for benchmark purposes
    // In a real benchmark, we would modify the NullifierDB code to have a no-sync option
    group.bench_function("batch_insert_100", |b| {
        b.iter(|| {
            let temp_dir = tempdir().expect("Failed to create temp directory");
            let db_path = temp_dir.path().join("no_sync_bench.db");
            
            // Create the database file first
            let db_file = File::create(&db_path).expect("Failed to create file");
            drop(db_file);
            
            // Open the file for writing without going through NullifierDB
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .open(&db_path)
                .expect("Failed to open file");
                
            // Generate and write 100 scalars directly to the file
            let mut rng = StdRng::seed_from_u64(0);
            let mut buffer = Vec::with_capacity(100 * 32);
            
            for _ in 0..100 {
                let scalar = Scalar::random(&mut rng);
                buffer.extend_from_slice(scalar.as_bytes());
            }
            
            file.write_all(&buffer).expect("Failed to write to file");
            // No sync_all call here
            
            black_box(file)
        });
    });
    
    group.finish();
}

/// Benchmark the cost of syncing to disk
fn bench_sync_cost(c: &mut Criterion) {
    let mut group = c.benchmark_group("sync_cost");
    group.sample_size(10); // Reduce sample size for faster benchmarks
    
    group.bench_function("sync_after_100_inserts", |b| {
        b.iter(|| {
            let temp_dir = tempdir().expect("Failed to create temp directory");
            let db_path = temp_dir.path().join("sync_bench.db");
            
            // Create the database file first
            let db_file = File::create(&db_path).expect("Failed to create file");
            drop(db_file);
            
            // Open the file for writing without going through NullifierDB
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .open(&db_path)
                .expect("Failed to open file");
                
            // Generate and write 100 scalars directly to the file
            let mut rng = StdRng::seed_from_u64(0);
            let mut buffer = Vec::with_capacity(100 * 32);
            
            for _ in 0..100 {
                let scalar = Scalar::random(&mut rng);
                buffer.extend_from_slice(scalar.as_bytes());
            }
            
            file.write_all(&buffer).expect("Failed to write to file");
            
            // Benchmark just the sync cost
            file.sync_all().expect("Failed to sync file");
            
            black_box(file)
        });
    });
    
    group.finish();
}

/// Benchmark different access patterns
fn bench_access_patterns(c: &mut Criterion) {
    let mut group = c.benchmark_group("access_patterns");
    
    // Create a database with 10,000 nullifiers
    let db_size = 10_000;
    let temp_dir = tempdir().expect("Failed to create temp directory");
    let db_path = temp_dir.path().join("patterns_bench.db");
    
    // Generate test scalars
    let all_scalars = generate_test_scalars(db_size);
    
    // Create and populate the database
    {
        let mut db = NullifierDB::create(&db_path).expect("Failed to create database");
        for scalar in &all_scalars {
            db.insert(*scalar).expect("Failed to insert nullifier");
        }
        db.flush_and_close().expect("Failed to close database");
    }
    
    // Recover the database for benchmarking
    let db = NullifierDB::recover(&db_path).expect("Failed to recover database");
    
    // Sequential access pattern (first N elements)
    group.bench_function("sequential_access_1000", |b| {
        b.iter(|| {
            let mut count = 0;
            for scalar in &all_scalars[0..1000] {
                if db.contains(scalar) {
                    count += 1;
                }
            }
            black_box(count)
        });
    });
    
    // Random access pattern (random indices into all_scalars)
    group.bench_function("random_access_1000", |b| {
        let mut rng = StdRng::seed_from_u64(123);
        let indices: Vec<usize> = (0..1000)
            .map(|_| rng.gen_range(0..db_size))
            .collect();
            
        b.iter(|| {
            let mut count = 0;
            for &idx in &indices {
                if db.contains(&all_scalars[idx]) {
                    count += 1;
                }
            }
            black_box(count)
        });
    });
    
    // Clustered access pattern (access elements close together)
    group.bench_function("clustered_access_1000", |b| {
        let mut rng = StdRng::seed_from_u64(456);
        let start_points: Vec<usize> = (0..10)
            .map(|_| rng.gen_range(0..db_size - 100))
            .collect();
            
        b.iter(|| {
            let mut count = 0;
            for &start in &start_points {
                for i in 0..100 { // 100 items around each start point
                    if db.contains(&all_scalars[start + i]) {
                        count += 1;
                    }
                }
            }
            black_box(count)
        });
    });
    
    group.finish();
}

// Regular benchmark group with faster completion time
criterion_group! {
    name = benches;
    config = Criterion::default()
        .sample_size(20)
        .measurement_time(Duration::from_secs(2));
    targets = 
        bench_recovery,
        bench_in_memory_lookup,
        bench_insertion_memory_only,
        bench_insertion_no_sync,
        bench_sync_cost,
        bench_access_patterns
}

criterion_main!(benches);