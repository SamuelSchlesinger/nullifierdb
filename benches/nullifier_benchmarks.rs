use criterion::{criterion_group, criterion_main, Criterion, BenchmarkId};
use nullifierdb::NullifierDB;
use curve25519_dalek::Scalar;
use rand::prelude::*;
use std::path::Path;
use std::fs::File;
use std::io::Write;
use std::time::Duration;
use tempfile::tempdir;

/// Create a database file with a specific number of nullifiers for benchmarking
fn create_benchmark_db(path: &Path, num_nullifiers: u64) -> std::io::Result<()> {
    println!("Creating benchmark database with {} nullifiers...", num_nullifiers);
    
    // Create the file
    let mut file = File::create(path)?;
    
    // We'll generate nullifiers in batches to avoid using too much memory
    const BATCH_SIZE: u64 = 100_000;
    let mut rng = StdRng::seed_from_u64(0); // Use a deterministic seed for reproducibility
    let mut buffer = Vec::with_capacity((BATCH_SIZE as usize) * 32);
    
    let batches = num_nullifiers / BATCH_SIZE;
    let remainder = num_nullifiers % BATCH_SIZE;
    
    // Process full batches
    for i in 0..batches {
        println!("Writing batch {}/{}", i+1, batches);
        buffer.clear();
        
        for _ in 0..BATCH_SIZE {
            // Generate a random scalar and add its bytes to the buffer
            let scalar = Scalar::random(&mut rng);
            buffer.extend_from_slice(scalar.as_bytes());
        }
        
        // Write the batch to the file
        file.write_all(&buffer)?;
        file.sync_all()?;
    }
    
    // Process the remainder
    if remainder > 0 {
        println!("Writing final batch of {} nullifiers", remainder);
        buffer.clear();
        
        for _ in 0..remainder {
            let scalar = Scalar::random(&mut rng);
            buffer.extend_from_slice(scalar.as_bytes());
        }
        
        file.write_all(&buffer)?;
        file.sync_all()?;
    }
    
    println!("Benchmark database created successfully");
    Ok(())
}

/// Benchmark the recovery of a NullifierDB with various sizes
fn bench_recovery(c: &mut Criterion) {
    let sizes = vec![
        // Start with smaller sizes for default benchmarks
        1_000,
        10_000,
        100_000,
        // Medium sizes - comment/uncomment as needed
        // 1_000_000,
        // 10_000_000,
    ];
    
    let mut group = c.benchmark_group("nullifier_db_recovery");
    
    for size in sizes {
        // Create a temporary directory for this benchmark
        let temp_dir = tempdir().expect("Failed to create temp directory");
        let db_path = temp_dir.path().join(format!("bench_{}.db", size));
        
        // Create the benchmark database
        create_benchmark_db(&db_path, size).expect("Failed to create benchmark database");
        
        // Add a benchmark for this size
        group.bench_with_input(BenchmarkId::from_parameter(size), &size, |b, _| {
            b.iter(|| {
                // Benchmark just the recovery operation
                let db = NullifierDB::recover(&db_path).expect("Failed to recover database");
                
                // Ensure the compiler doesn't optimize away the operation
                assert_eq!(db.len(), size as usize);
            });
        });
    }
    
    group.finish();
}

/// Benchmark the very large database recovery (100M or 1B nullifiers)
/// This function is separate because it requires special configuration
fn bench_large_recovery(c: &mut Criterion) {
    let size: u64 = 100_000_000;
    
    // Configure the benchmark with longer measurement time and fewer samples
    let mut group = c.benchmark_group("nullifier_db_large_recovery");
    group.sample_size(10);
    group.measurement_time(Duration::from_secs(60));
    
    // Create a temporary directory for this benchmark
    let temp_dir = tempdir().expect("Failed to create temp directory");
    let db_path = temp_dir.path().join(format!("large_bench_{}.db", size));
    
    // Check if file exists first (to allow reusing previously created test file)
    if !db_path.exists() {
        println!("Creating a large database with {} nullifiers. This will take significant time and disk space...", size);
        create_benchmark_db(&db_path, size).expect("Failed to create benchmark database");
    } else {
        println!("Using existing benchmark database file at {:?}", db_path);
    }
    
    // Run the benchmark
    group.bench_with_input(BenchmarkId::from_parameter(size), &size, |b, &size| {
        b.iter(|| {
            // Benchmark just the recovery operation
            let db = NullifierDB::recover(&db_path).expect("Failed to recover database");
            
            // Ensure the compiler doesn't optimize away the operation
            assert_eq!(db.len(), size as usize);
        });
    });
    
    group.finish();
    
    println!("Benchmark complete. Database file remains at {:?} for potential reuse", db_path);
    println!("Consider moving this file to a permanent location if you want to reuse it for future benchmarks.");
}

/// Benchmark insertion performance
fn bench_insertion(c: &mut Criterion) {
    let sizes = vec![
        1_000,
        10_000,
        // Larger sizes will be quite slow due to syncing
        // 100_000, 
    ];
    
    let mut group = c.benchmark_group("nullifier_db_insertion");
    
    for size in sizes {
        // Create a temporary directory for this benchmark
        let temp_dir = tempdir().expect("Failed to create temp directory");
        let db_path = temp_dir.path().join(format!("insert_bench_{}.db", size));
        
        // Add a benchmark for this size
        group.bench_with_input(BenchmarkId::from_parameter(size), &size, |b, &size| {
            b.iter(|| {
                // Create a new database
                let mut db = NullifierDB::create(&db_path).expect("Failed to create database");
                
                // Generate and insert random nullifiers
                let mut rng = StdRng::seed_from_u64(0); // Deterministic seed
                for _ in 0..size {
                    let scalar = Scalar::random(&mut rng);
                    db.insert(scalar).expect("Failed to insert nullifier");
                }
                
                // Ensure the compiler doesn't optimize away the operations
                assert_eq!(db.len(), size as usize);
                
                // Clean up for the next iteration
                drop(db);
                std::fs::remove_file(&db_path).ok();
            });
        });
    }
    
    group.finish();
}

/// Benchmark lookup performance
fn bench_lookup(c: &mut Criterion) {
    let db_size = 100_000; // Fixed size for the database
    let lookup_counts = vec![100, 1_000, 10_000]; // Number of lookups to perform
    
    // Create a temporary directory for this benchmark
    let temp_dir = tempdir().expect("Failed to create temp directory");
    let db_path = temp_dir.path().join("lookup_bench.db");
    
    // Create a deterministic set of scalars
    let mut rng = StdRng::seed_from_u64(0);
    let mut all_scalars = Vec::with_capacity(db_size);
    for _ in 0..db_size {
        all_scalars.push(Scalar::random(&mut rng));
    }
    
    // Create and populate the database
    {
        println!("Creating database for lookup benchmarks with {} nullifiers", db_size);
        let mut db = NullifierDB::create(&db_path).expect("Failed to create database");
        for scalar in &all_scalars {
            db.insert(*scalar).expect("Failed to insert nullifier");
        }
        db.flush_and_close().expect("Failed to close database");
    }
    
    // Recover the database for benchmarking
    let db = NullifierDB::recover(&db_path).expect("Failed to recover database");
    
    let mut group = c.benchmark_group("nullifier_db_lookup");
    for count in lookup_counts {
        group.bench_with_input(BenchmarkId::from_parameter(count), &count, |b, &count| {
            // Select a slice of scalars for lookup
            let lookup_scalars = &all_scalars[0..count as usize];
            
            b.iter(|| {
                // Perform the lookups
                let mut found_count = 0;
                for scalar in lookup_scalars {
                    if db.contains(scalar) {
                        found_count += 1;
                    }
                }
                
                // All should be found
                assert_eq!(found_count, count);
            });
        });
    }
    group.finish();
}

// Regular benchmarks group for normal use
criterion_group!(
    name = benches;
    config = Criterion::default();
    targets = bench_recovery, bench_insertion, bench_lookup
);

// Separate group for large database benchmarks that shouldn't run by default
criterion_group!(
    name = large_benches;
    config = Criterion::default().sample_size(10).measurement_time(Duration::from_secs(60));
    targets = bench_large_recovery
);

// Main entry point that runs the regular benchmarks by default
criterion_main!(benches);

// To run the regular benchmarks:
// cargo bench --bench nullifier_benchmarks

// To run the large database benchmarks:
// cargo bench --bench nullifier_benchmarks --features="large-benchmarks" large_benches
