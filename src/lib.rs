use std::fs::File;
use std::path::Path;
use std::io::{self, BufReader, BufWriter, Read, Write, ErrorKind, SeekFrom, Seek};
use std::collections::HashSet;
use std::fmt;
use curve25519_dalek::Scalar;
use log::{warn, debug};

/// NullifierDB is a specialized database for storing cryptographic nullifiers.
/// 
/// It provides:
/// - O(1) lookups via an in-memory HashSet
/// - Persistent storage via append-only file writes 
/// - Automatic recovery from existing files
/// - Data integrity validation through careful file handling
/// - File-based concurrency control for multi-process safety
pub struct NullifierDB {
    /// File writer for persisting nullifiers
    writer: BufWriter<File>,
    /// In-memory set for fast lookups
    map: HashSet<Scalar>,
    /// Path to the database file (used for locking)
    db_path: std::path::PathBuf,
    /// Path to the lock file (created during exclusive access)
    lock_path: std::path::PathBuf,
    /// Flag to track if we own the lock
    lock_acquired: bool,
}

/// Error types that can occur during NullifierDB operations
#[derive(Debug)]
pub enum NullifierError {
    /// File system related errors
    Io {
        /// The underlying IO error
        source: io::Error,
        /// Context describing what operation was being performed
        context: &'static str,
    },
    
    /// The database file doesn't exist at the specified path
    FileNotFound {
        /// The path that was attempted to be opened
        path: String,
    },
    
    /// Data corruption errors
    InvalidScalar {
        /// Position in the file where the invalid scalar was found
        position: u64,
        /// The raw bytes that failed to convert to a valid scalar
        bytes: [u8; 32],
    },
    
    /// File size is not a multiple of 32 bytes (scalar size)
    CorruptedFileSize {
        /// Actual file size
        size: u64,
        /// Calculated valid size (nearest multiple of 32)
        valid_size: u64,
    },
    
    /// Error during file truncation when repairing
    TruncateError {
        /// The underlying IO error
        source: io::Error,
        /// The size the file was being truncated to
        target_size: u64,
    },
    
    /// Error when writing a nullifier to persistent storage
    WriteError {
        /// The underlying IO error
        source: io::Error,
        /// The scalar that was being written
        scalar: Scalar,
    },
    
    /// Error when flushing data to persistent storage
    FlushError {
        /// The underlying IO error
        source: io::Error,
    },
    
    /// Error when syncing data to disk
    SyncError {
        /// The underlying IO error
        source: io::Error,
    },
    
    /// Database is already locked by another process or thread
    DatabaseLocked {
        /// Path to the database file
        path: String,
    },
    
    /// Cannot create lock file
    LockFileCreationError {
        /// Path to the lock file
        path: String,
        /// The underlying IO error
        source: io::Error,
    },
    
    /// Failed to release lock
    LockReleaseError {
        /// Path to the lock file
        path: String,
        /// The underlying IO error
        source: io::Error,
    },
}

impl fmt::Display for NullifierError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io { source, context } => 
                write!(f, "IO error during {}: {}", context, source),
                
            Self::FileNotFound { path } => 
                write!(f, "Database file not found at path: {}", path),
                
            Self::InvalidScalar { position, bytes } => 
                write!(f, "Invalid scalar data at position {}: {:?}", position, bytes),
                
            Self::CorruptedFileSize { size, valid_size } => 
                write!(f, "Corrupted file size {} bytes (not a multiple of 32). Valid size would be {} bytes", 
                       size, valid_size),
                
            Self::TruncateError { source, target_size } => 
                write!(f, "Failed to truncate file to {} bytes: {}", target_size, source),
                
            Self::WriteError { source, scalar: _ } => 
                write!(f, "Failed to write nullifier to persistent storage: {}", source),
                
            Self::FlushError { source } => 
                write!(f, "Failed to flush data to persistent storage: {}", source),
                
            Self::SyncError { source } => 
                write!(f, "Failed to sync data to disk: {}", source),
                
            Self::DatabaseLocked { path } => 
                write!(f, "Database is already locked by another process at path: {}", path),
                
            Self::LockFileCreationError { path, source } => 
                write!(f, "Failed to create lock file at {}: {}", path, source),
                
            Self::LockReleaseError { path, source } => 
                write!(f, "Failed to release lock file at {}: {}", path, source),
        }
    }
}

impl std::error::Error for NullifierError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            Self::TruncateError { source, .. } => Some(source),
            Self::WriteError { source, .. } => Some(source),
            Self::FlushError { source } => Some(source),
            Self::SyncError { source } => Some(source),
            Self::LockFileCreationError { source, .. } => Some(source),
            Self::LockReleaseError { source, .. } => Some(source),
            _ => None,
        }
    }
}

impl From<io::Error> for NullifierError {
    fn from(error: io::Error) -> Self {
        match error.kind() {
            ErrorKind::NotFound => Self::FileNotFound { 
                path: error.to_string() 
            },
            _ => Self::Io { 
                source: error, 
                context: "unspecified operation" 
            },
        }
    }
}

impl NullifierDB {
    /// Acquires an exclusive lock on the database
    /// 
    /// # Arguments
    /// 
    /// * `db_path` - Path to the database file
    /// 
    /// # Returns
    /// 
    /// * `Ok(())` - If the lock was acquired successfully
    /// * `Err(NullifierError)` - If an error occurred during lock acquisition
    fn acquire_lock(&mut self) -> Result<(), NullifierError> {
        if self.lock_acquired {
            return Ok(()); // Lock already acquired
        }
        
        // Check if lock file already exists
        if self.lock_path.exists() {
            // Check if the lock file is stale (process that created it might have crashed)
            // In a real production system, you'd want to check if the process ID in the lock file
            // is still running, but for simplicity, we'll just check if the lock file is older than
            // a certain threshold (e.g., 10 minutes)
            match std::fs::metadata(&self.lock_path) {
                Ok(metadata) => {
                    if let Ok(modified_time) = metadata.modified() {
                        if let Ok(age) = modified_time.elapsed() {
                            // Check if lock is older than 10 minutes
                            if age > std::time::Duration::from_secs(600) {
                                // Lock file is stale, remove it
                                if let Err(e) = std::fs::remove_file(&self.lock_path) {
                                    return Err(NullifierError::Io {
                                        source: e,
                                        context: "removing stale lock file",
                                    });
                                }
                                debug!("Removed stale lock file at {:?}", self.lock_path);
                            } else {
                                // Lock file exists and is not stale
                                return Err(NullifierError::DatabaseLocked {
                                    path: self.db_path.to_string_lossy().to_string(),
                                });
                            }
                        }
                    }
                }
                Err(e) => {
                    return Err(NullifierError::Io {
                        source: e,
                        context: "checking lock file metadata",
                    });
                }
            }
        }
        
        // Create lock file
        let mut lock_file = File::create(&self.lock_path).map_err(|e| {
            NullifierError::LockFileCreationError {
                path: self.lock_path.to_string_lossy().to_string(),
                source: e,
            }
        })?;
        
        // Write process ID to lock file for debugging
        use std::io::Write;
        if let Err(e) = writeln!(lock_file, "{}", std::process::id()) {
            return Err(NullifierError::Io {
                source: e,
                context: "writing process ID to lock file",
            });
        }
        
        self.lock_acquired = true;
        Ok(())
    }
    
    /// Releases the exclusive lock on the database
    /// 
    /// # Returns
    /// 
    /// * `Ok(())` - If the lock was released successfully
    /// * `Err(NullifierError)` - If an error occurred during lock release
    fn release_lock(&mut self) -> Result<(), NullifierError> {
        if !self.lock_acquired {
            return Ok(()); // No lock to release
        }
        
        // Remove lock file
        std::fs::remove_file(&self.lock_path).map_err(|e| {
            NullifierError::LockReleaseError {
                path: self.lock_path.to_string_lossy().to_string(),
                source: e,
            }
        })?;
        
        self.lock_acquired = false;
        Ok(())
    }

    /// Creates a new empty NullifierDB at the specified path.
    ///
    /// If the file already exists, it will be overwritten with an empty database.
    ///
    /// # Arguments
    ///
    /// * `path` - Path where the database file should be created
    ///
    /// # Returns
    ///
    /// * `Ok(NullifierDB)` - If creating the database was successful
    /// * `Err(NullifierError)` - If an error occurred during creation
    ///
    /// # Errors
    ///
    /// This function can return the following errors:
    ///
    /// * `NullifierError::Io` - If the file cannot be created or opened due to permission issues,
    ///   non-existent parent directory, or other I/O errors
    /// * `NullifierError::DatabaseLocked` - If the database is already locked by another process
    /// * `NullifierError::LockFileCreationError` - If the lock file cannot be created
    pub fn create(path: &Path) -> Result<NullifierDB, NullifierError> {
        // First, prepare the lock path
        let lock_path = path.with_extension("lock");
        
        // Create a database instance but don't acquire the lock yet
        let mut db = NullifierDB {
            writer: BufWriter::new(File::create(path).map_err(|e| NullifierError::Io { 
                source: e, 
                context: "creating new database file" 
            })?),
            map: HashSet::new(),
            db_path: path.to_path_buf(),
            lock_path,
            lock_acquired: false,
        };
        
        // Now acquire the lock
        db.acquire_lock()?;
        
        Ok(db)
    }
    
    /// Inserts a new nullifier into the database.
    ///
    /// # Arguments
    ///
    /// * `scalar` - The Curve25519 Scalar value to insert as a nullifier
    ///
    /// # Returns
    ///
    /// * `Ok(true)` - If the nullifier was new and was successfully inserted
    /// * `Ok(false)` - If the nullifier already existed in the database
    /// * `Err(NullifierError)` - If an error occurred during the write or flush operation
    ///
    /// # Errors
    ///
    /// This function can return the following errors:
    /// 
    /// * `NullifierError::WriteError` - If the write operation to the file fails
    /// * `NullifierError::FlushError` - If the flush operation fails after writing
    /// * `NullifierError::SyncError` - If the sync operation to disk fails
    pub fn insert(&mut self, scalar: Scalar) -> Result<bool, NullifierError> {
        if self.map.insert(scalar) {
            // New nullifier: write to persistent storage
            self.writer.write_all(scalar.as_bytes())
                .map_err(|err| NullifierError::WriteError { source: err, scalar })?;
            
            // Flush to ensure data is sent to OS
            self.writer.flush()
                .map_err(|err| NullifierError::FlushError { source: err })?;

            // Sync to ensure OS syncs data to disk
            let file = self.writer.get_mut();
            file.sync_all()
                .map_err(|err| NullifierError::SyncError { source: err })?;
            
            Ok(true)
        } else {
            // Nullifier already exists
            Ok(false)
        }
    }

    /// Recovers a NullifierDB from an existing file.
    ///
    /// This method:
    /// 1. Acquires an exclusive lock on the database
    /// 2. Reads all nullifiers from the file
    /// 3. Validates each nullifier as a canonical Curve25519 Scalar
    /// 4. Builds an in-memory HashSet for fast lookups
    /// 5. Repairs the file if necessary (truncating to valid 32-byte boundaries)
    /// 6. Positions the writer at the end for future appends
    ///
    /// # Arguments
    ///
    /// * `path` - Path to the database file
    ///
    /// # Returns
    ///
    /// * `Ok(NullifierDB)` - If recovery was successful
    /// * `Err(NullifierError)` - If an error occurred during recovery
    ///
    /// # Errors
    ///
    /// This function can return the following errors:
    ///
    /// * `NullifierError::FileNotFound` - If the database file does not exist
    /// * `NullifierError::Io` - If an I/O error occurs during file operations
    /// * `NullifierError::InvalidScalar` - If corrupt or invalid scalar data is found
    /// * `NullifierError::CorruptedFileSize` - If the file size is not a multiple of 32 bytes
    /// * `NullifierError::TruncateError` - If file truncation fails during repair
    /// * `NullifierError::DatabaseLocked` - If the database is already locked by another process
    /// * `NullifierError::LockFileCreationError` - If the lock file cannot be created
    pub fn recover(path: &Path) -> Result<NullifierDB, NullifierError> {
        // Prepare lock path
        let lock_path = path.with_extension("lock");
        
        // Create a temporary file path for the initial writer 
        // We'll use a simple approach without external dependencies
        let temp_path = std::env::temp_dir().join(format!("temp_nullifier_{}", std::process::id()));
        let temp_file = File::create(&temp_path).map_err(|e| NullifierError::Io {
            source: e,
            context: "creating temporary file",
        })?;
        // Clean up the temporary file immediately after creating it
        std::fs::remove_file(&temp_path).ok();
        
        // Create a database instance but don't populate it yet
        let mut db = NullifierDB {
            writer: BufWriter::new(temp_file),
            map: HashSet::new(),
            db_path: path.to_path_buf(),
            lock_path,
            lock_acquired: false,
        };
        
        // Now acquire the lock before proceeding with recovery
        db.acquire_lock()?;
        
        // Open the file for reading
        let file = File::open(path).map_err(|e| {
            // Make sure to release the lock if we encounter an error
            let _ = db.release_lock();
            
            if e.kind() == ErrorKind::NotFound {
                NullifierError::FileNotFound { path: path.display().to_string() }
            } else {
                NullifierError::Io { source: e, context: "opening database file for reading" }
            }
        })?;
        
        let mut reader = BufReader::new(file);
        let mut buffer = [0u8; 32];
        let mut position: u64 = 0;
        
        // Read all nullifiers from the file
        loop {
            match reader.read_exact(&mut buffer) {
                Ok(_) => {
                    // Validate the bytes as a canonical Scalar
                    if let Some(scalar) = Scalar::from_canonical_bytes(buffer).into() {
                        db.map.insert(scalar);
                    } else {
                        // Invalid scalar data found - release lock before returning error
                        let _ = db.release_lock();
                        return Err(NullifierError::InvalidScalar { 
                            position, 
                            bytes: buffer 
                        });
                    }
                    position += 32;
                }
                Err(e) => {
                    match e.kind() {
                        ErrorKind::UnexpectedEof => {
                            // End of file reached - normal exit condition
                            break;
                        }
                        _ => {
                            // Other I/O error - release lock before returning error
                            let _ = db.release_lock();
                            return Err(NullifierError::Io { 
                                source: e, 
                                context: "reading nullifiers from database file" 
                            });
                        }
                    }
                }
            } 
        }

        // Reopen the file for writing and potential repair
        let mut file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
            .map_err(|e| {
                // Release lock before returning error
                let _ = db.release_lock();
                NullifierError::Io { 
                    source: e, 
                    context: "reopening database file for writing" 
                }
            })?;
            
        let metadata = file.metadata()
            .map_err(|e| {
                // Release lock before returning error
                let _ = db.release_lock();
                NullifierError::Io { 
                    source: e, 
                    context: "retrieving file metadata" 
                }
            })?;
            
        let len = metadata.len();
        
        // Ensure file size is a multiple of 32 bytes (Scalar size)
        if len % 32 != 0 {
            let valid_size = 32 * (len / 32);
            
            // Create a specific error for this corrupted file size
            let corruption_error = NullifierError::CorruptedFileSize {
                size: len,
                valid_size,
            };
            
            // Log this corruption
            warn!("{}", corruption_error);
            
            // Truncate to the nearest valid boundary to repair corruption
            if let Err(e) = file.set_len(valid_size) {
                // Release lock before returning error
                let _ = db.release_lock();
                return Err(NullifierError::TruncateError { 
                    source: e, 
                    target_size: valid_size 
                });
            }
        }
        
        // Position the writer at the end for appending
        if let Err(e) = file.seek(SeekFrom::End(0)) {
            // Release lock before returning error
            let _ = db.release_lock();
            return Err(NullifierError::Io { 
                source: e, 
                context: "positioning file writer at end of file" 
            });
        }

        // Now replace the temporary writer with the real one
        db.writer = BufWriter::new(file);
        
        // Return the reconstructed and locked NullifierDB
        Ok(db)
    }
    
    /// Checks if a nullifier exists in the database.
    ///
    /// This is an O(1) operation that only checks the in-memory HashSet.
    ///
    /// # Arguments
    ///
    /// * `scalar` - The Curve25519 Scalar value to check
    ///
    /// # Returns
    ///
    /// * `true` - If the nullifier exists in the database
    /// * `false` - If the nullifier does not exist in the database
    pub fn contains(&self, scalar: &Scalar) -> bool {
        self.map.contains(scalar)
    }
    
    /// Returns the number of nullifiers in the database.
    ///
    /// # Returns
    ///
    /// * `usize` - The number of nullifiers in the database
    pub fn len(&self) -> usize {
        self.map.len()
    }
    
    /// Checks if the database is empty.
    ///
    /// # Returns
    ///
    /// * `true` - If the database contains no nullifiers
    /// * `false` - If the database contains at least one nullifier
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }
    
    /// Explicitly flushes all pending writes, syncs to disk, releases the lock, and closes the database.
    ///
    /// This is useful when you want to ensure all data is durably written to disk
    /// before the database is dropped. The function performs three operations:
    /// 1. Flushes the buffer to the operating system
    /// 2. Syncs the file to ensure the OS writes the data to the physical storage
    /// 3. Releases the exclusive lock on the database
    ///
    /// # Returns
    ///
    /// * `Ok(())` - If the flush, sync, and lock release operations were successful
    /// * `Err(NullifierError)` - If an error occurred during flush, sync, or lock release
    ///
    /// # Errors
    ///
    /// This function can return the following errors:
    ///
    /// * `NullifierError::FlushError` - If the flush operation fails
    /// * `NullifierError::SyncError` - If the sync operation fails
    /// * `NullifierError::LockReleaseError` - If releasing the lock fails
    pub fn flush_and_close(mut self) -> Result<(), NullifierError> {
        // First flush buffers to OS
        self.writer.flush()
            .map_err(|err| NullifierError::FlushError { source: err })?;
            
        // Then sync to ensure OS writes to disk
        let file = self.writer.get_mut();
        file.sync_all()
            .map_err(|err| NullifierError::SyncError { source: err })?;
        
        // Release the lock
        self.release_lock()?;
            
        Ok(())
    }
}

impl Drop for NullifierDB {
    fn drop(&mut self) {
        // Attempt to flush any pending writes when the database is dropped
        // We can only log errors here, as we can't return Result from drop
        if let Err(e) = self.writer.flush() {
            warn!("Failed to flush NullifierDB during drop: {}", e);
            // Even if flush fails, try to release the lock
        } else {
            // Try to sync to disk
            match self.writer.get_mut().sync_all() {
                Ok(_) => {
                    if log::log_enabled!(log::Level::Debug) {
                        debug!("Successfully synced NullifierDB to disk during drop");
                    }
                },
                Err(e) => {
                    warn!("Failed to sync NullifierDB to disk during drop: {}", e);
                    // In a production system, this is a serious error that should trigger
                    // a monitoring alert, as it means data may be lost or corrupted
                    warn!("DATA INTEGRITY RISK: NullifierDB failed to sync to disk on drop");
                },
            }
        }
        
        // Always try to release the lock, even if flush/sync failed
        if self.lock_acquired {
            if let Err(e) = self.release_lock() {
                warn!("Failed to release NullifierDB lock during drop: {}", e);
                warn!("LOCK FILE LEAK: Database lock file was not properly removed at: {:?}", self.lock_path);
            } else if log::log_enabled!(log::Level::Debug) {
                debug!("Successfully released NullifierDB lock during drop");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    /// Helper function to create a random Scalar for testing
    fn random_scalar() -> Scalar {
        Scalar::random(&mut rand::thread_rng())
    }

    #[test]
    fn test_create_and_insert() -> Result<(), NullifierError> {
        let temp_dir = tempdir().expect("Failed to create temp dir");
        let db_path = temp_dir.path().join("nullifiers.db");
        
        // Create a new database
        let mut db = NullifierDB::create(&db_path)?;
        
        // Insert a nullifier
        let nullifier = random_scalar();
        let result = db.insert(nullifier)?;
        assert!(result, "Expected insert to return true for a new nullifier");
        
        // Try to insert the same nullifier again
        let result = db.insert(nullifier)?;
        assert!(!result, "Expected insert to return false for an existing nullifier");
        
        // Check if the nullifier exists
        assert!(db.contains(&nullifier), "Expected nullifier to exist in the database");
        
        // Check the length
        assert_eq!(db.len(), 1, "Expected database to contain 1 nullifier");
        
        // Insert another nullifier
        let nullifier2 = random_scalar();
        let result = db.insert(nullifier2)?;
        assert!(result, "Expected insert to return true for a new nullifier");
        
        // Check the length again
        assert_eq!(db.len(), 2, "Expected database to contain 2 nullifiers");
        
        // Close the database
        db.flush_and_close()?;
        
        Ok(())
    }
    
    #[test]
    fn test_recover() -> Result<(), NullifierError> {
        let temp_dir = tempdir().expect("Failed to create temp dir");
        let db_path = temp_dir.path().join("nullifiers.db");
        
        // Create a set of nullifiers to insert
        let nullifiers = vec![random_scalar(), random_scalar(), random_scalar()];
        
        // Create and populate the database
        {
            let mut db = NullifierDB::create(&db_path)?;
            
            for nullifier in &nullifiers {
                db.insert(*nullifier)?;
            }
            
            // Database is dropped here, which should flush
        }
        
        // Recover the database from the file
        let recovered_db = NullifierDB::recover(&db_path)?;
        
        // Check the length
        assert_eq!(recovered_db.len(), nullifiers.len(), 
                  "Recovered database should have the same number of nullifiers");
        
        // Check that all nullifiers exist
        for nullifier in &nullifiers {
            assert!(recovered_db.contains(nullifier), 
                   "Expected nullifier to exist in the recovered database");
        }
        
        Ok(())
    }
    
    #[test]
    fn test_error_file_not_found() {
        let temp_dir = tempdir().expect("Failed to create temp dir");
        let nonexistent_path = temp_dir.path().join("does_not_exist.db");
        
        // Try to recover a database from a non-existent file
        let result = NullifierDB::recover(&nonexistent_path);
        
        // Check that we get a FileNotFound error
        match result {
            Err(NullifierError::FileNotFound { .. }) => { /* Expected error */ },
            Ok(_) => panic!("Expected FileNotFound error, got Ok"),
            Err(e) => panic!("Expected FileNotFound error, got {:?}", e),
        }
    }
    
    #[test]
    fn test_repair_corrupted_file() -> Result<(), NullifierError> {
        let temp_dir = tempdir().expect("Failed to create temp dir");
        let db_path = temp_dir.path().join("corrupted.db");
        
        // Create a database and add some nullifiers
        let nullifiers = vec![random_scalar(), random_scalar()];
        {
            let mut db = NullifierDB::create(&db_path)?;
            for n in &nullifiers {
                db.insert(*n)?;
            }
            // Database is dropped here and should flush
        }
        
        // Corrupt the file by appending some extra bytes (not a full 32-byte scalar)
        {
            let mut file = fs::OpenOptions::new().append(true).open(&db_path)
                .expect("Failed to open file for corruption");
            
            // Write 10 bytes (not a complete scalar) to corrupt the file
            file.write_all(&[1, 2, 3, 4, 5, 6, 7, 8, 9, 10])
                .expect("Failed to write corrupting bytes");
            
            // File is closed and flushed here
        }
        
        // Attempt to recover the database, which should fix the corruption
        let recovered_db = NullifierDB::recover(&db_path)?;
        
        // Check that all the valid nullifiers were recovered
        assert_eq!(recovered_db.len(), nullifiers.len(), 
                  "Expected all valid nullifiers to be recovered");
        
        for n in &nullifiers {
            assert!(recovered_db.contains(n), 
                   "Expected nullifier to exist in the recovered database");
        }
        
        // Verify the file size is now a multiple of 32
        let metadata = fs::metadata(&db_path).expect("Failed to get file metadata");
        assert_eq!(metadata.len() % 32, 0, 
                  "Expected file size to be a multiple of 32 bytes after repair");
        
        Ok(())
    }
    
    #[test]
    fn test_invalid_scalar_error() {
        let temp_dir = tempdir().expect("Failed to create temp dir");
        let db_path = temp_dir.path().join("invalid_scalar.db");
        
        // Create an empty file first
        std::fs::File::create(&db_path).expect("Failed to create file");
        
        // Write an invalid scalar (32 bytes of 0xFF, which exceeds the Ed25519 curve order)
        {
            let mut file = std::fs::OpenOptions::new().write(true).open(&db_path)
                .expect("Failed to open file for writing invalid scalar");
                
            // Fill with 0xFF bytes which will create an invalid scalar
            let invalid_scalar_bytes = [0xFF; 32];
            file.write_all(&invalid_scalar_bytes)
                .expect("Failed to write invalid scalar bytes");
        }
        
        // Try to recover the database, which should fail with InvalidScalar error
        let result = NullifierDB::recover(&db_path);
        
        // Check that we get an InvalidScalar error
        match result {
            Err(NullifierError::InvalidScalar { position, bytes }) => {
                assert_eq!(position, 0, "Expected position to be 0");
                assert_eq!(bytes, [0xFF; 32], "Expected bytes to match the invalid scalar");
            },
            Ok(_) => panic!("Expected InvalidScalar error, got Ok"),
            Err(e) => panic!("Expected InvalidScalar error, got {:?}", e),
        }
    }
    
    #[test]
    fn test_sync_durability() -> Result<(), Box<dyn std::error::Error>> {
        let temp_dir = tempdir()?;
        let db_path = temp_dir.path().join("sync_test.db");
        
        // Create a set of nullifiers to insert
        let nullifiers = vec![random_scalar(), random_scalar(), random_scalar()];
        
        // Test that data properly persists with sync calls
        {
            // Create and populate database with sync
            let mut db = NullifierDB::create(&db_path)?;
            for nullifier in &nullifiers {
                db.insert(*nullifier)?; // This now includes sync_all
            }
            
            // Explicit close with sync
            db.flush_and_close()?;
        }
        
        // Verify data persistence by reopening
        {
            let recovered_db = NullifierDB::recover(&db_path)?;
            assert_eq!(recovered_db.len(), nullifiers.len(), 
                      "Database should contain all nullifiers after sync");
            
            for nullifier in &nullifiers {
                assert!(recovered_db.contains(nullifier), 
                       "Each nullifier should exist after sync");
            }
        }
        
        Ok(())
    }
}
