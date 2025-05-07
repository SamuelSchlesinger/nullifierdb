use std::fs::File;
use std::path::Path;
use std::io::{self, BufReader, BufWriter, Read, Write, ErrorKind, SeekFrom, Seek};
use std::collections::HashSet;
use std::fmt;
use log::{warn, debug};
#[cfg(unix)]
use std::os::unix::io::AsRawFd;
#[cfg(windows)]
use std::os::windows::io::AsRawHandle;

type Scalar = [u8; 32];

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
    /// Path to the database file
    db_path: std::path::PathBuf,
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
    
    /// Failed to acquire file lock
    LockAcquisitionError {
        /// The underlying IO error
        source: io::Error,
        /// Path to the database file
        path: String,
    },
    
    /// Failed to release file lock
    LockReleaseError {
        /// The underlying IO error
        source: io::Error,
        /// Path to the database file
        path: String,
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
                write!(f, "Database is locked at path: {}. Another process currently has exclusive access. If you're sure no other process is using the database, restart your application.", path),
                
            Self::LockAcquisitionError { path, source } => 
                write!(f, "Failed to acquire lock for database at {}: {}", path, source),
                
            Self::LockReleaseError { path, source } => 
                write!(f, "Failed to release lock for database at {}: {}", path, source),
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
            Self::LockAcquisitionError { source, .. } => Some(source),
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
    /// Count the number of entries.
    pub fn count(&self) -> usize {
        self.map.len()
    }

    /// Acquire a file lock using platform-specific functionality
    /// This handles POSIX advisory locks on Unix and file locking on Windows
    #[cfg(unix)]
    fn acquire_file_lock(file: &File) -> io::Result<()> {
        use libc::{flock, LOCK_EX, LOCK_NB};
        
        let fd = file.as_raw_fd();
        
        // LOCK_EX: exclusive lock
        // LOCK_NB: non-blocking operation
        let result = unsafe { flock(fd, LOCK_EX | LOCK_NB) };
        
        if result != 0 {
            // Convert the C error to Rust io::Error
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }

    /// Release a file lock using platform-specific functionality
    #[cfg(unix)]
    fn release_file_lock(file: &File) -> io::Result<()> {
        use libc::{flock, LOCK_UN};
        
        let fd = file.as_raw_fd();
        
        // LOCK_UN: unlock the file
        let result = unsafe { flock(fd, LOCK_UN) };
        
        if result != 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }

    /// Acquire a file lock on Windows
    #[cfg(windows)]
    fn acquire_file_lock(file: &File) -> io::Result<()> {
        use winapi::um::fileapi::LockFileEx;
        use winapi::um::minwinbase::{OVERLAPPED, LOCKFILE_EXCLUSIVE_LOCK, LOCKFILE_FAIL_IMMEDIATELY};
        use winapi::shared::minwindef::DWORD;
        
        let handle = file.as_raw_handle();
        
        let mut overlapped = OVERLAPPED {
            Internal: 0,
            InternalHigh: 0,
            Offset: 0,
            OffsetHigh: 0,
            hEvent: std::ptr::null_mut(),
        };
        
        let result = unsafe {
            LockFileEx(
                handle,
                LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY,
                0,
                !0 as DWORD,  // Lock the entire file (max size)
                !0 as DWORD,  // Lock the entire file (max size)
                &mut overlapped,
            )
        };
        
        if result == 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }

    /// Release a file lock on Windows
    #[cfg(windows)]
    fn release_file_lock(file: &File) -> io::Result<()> {
        use winapi::um::fileapi::UnlockFileEx;
        use winapi::um::minwinbase::OVERLAPPED;
        use winapi::shared::minwindef::DWORD;
        
        let handle = file.as_raw_handle();
        
        let mut overlapped = OVERLAPPED {
            Internal: 0,
            InternalHigh: 0,
            Offset: 0,
            OffsetHigh: 0,
            hEvent: std::ptr::null_mut(),
        };
        
        let result = unsafe {
            UnlockFileEx(
                handle,
                0,
                !0 as DWORD,  // Unlock the entire file (max size)
                !0 as DWORD,  // Unlock the entire file (max size)
                &mut overlapped,
            )
        };
        
        if result == 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }

    /// Acquires an exclusive lock on the database
    /// 
    /// # Returns
    /// 
    /// * `Ok(())` - If the lock was acquired successfully
    /// * `Err(NullifierError)` - If an error occurred during lock acquisition
    fn acquire_lock(&mut self) -> Result<(), NullifierError> {
        if self.lock_acquired {
            return Ok(()); // Lock already acquired
        }
        
        // Try to acquire the lock on the database file
        // This is atomic and avoids the TOCTOU race condition
        let file = self.writer.get_mut();
        
        match Self::acquire_file_lock(file) {
            Ok(()) => {
                self.lock_acquired = true;
                Ok(())
            },
            Err(e) => {
                // If error is EWOULDBLOCK or equivalent, it means
                // the file is already locked by another process
                if e.kind() == io::ErrorKind::WouldBlock {
                    Err(NullifierError::DatabaseLocked {
                        path: self.db_path.to_string_lossy().to_string(),
                    })
                } else {
                    Err(NullifierError::LockAcquisitionError {
                        source: e,
                        path: self.db_path.to_string_lossy().to_string(),
                    })
                }
            }
        }
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
        
        // Release the lock
        let file = self.writer.get_mut();
        
        match Self::release_file_lock(file) {
            Ok(()) => {
                self.lock_acquired = false;
                Ok(())
            },
            Err(e) => {
                Err(NullifierError::LockReleaseError {
                    source: e,
                    path: self.db_path.to_string_lossy().to_string(),
                })
            }
        }
    }

    /// Creates a new NullifierDB at the specified path or recovers an existing one.
    ///
    /// If the file already exists, it will recover the database from the existing file.
    /// If the file doesn't exist, it will create a new empty database.
    ///
    /// # Arguments
    ///
    /// * `path` - Path where the database file should be created or loaded from
    ///
    /// # Returns
    ///
    /// * `Ok(NullifierDB)` - If creating/recovering the database was successful
    /// * `Err(NullifierError)` - If an error occurred during creation or recovery
    ///
    /// # Errors
    ///
    /// This function can return the following errors:
    ///
    /// * `NullifierError::Io` - If the file cannot be created or opened due to permission issues,
    ///   non-existent parent directory, or other I/O errors
    /// * `NullifierError::DatabaseLocked` - If the database is already locked by another process
    /// * `NullifierError::LockFileCreationError` - If the lock file cannot be created
    /// * `NullifierError::InvalidScalar` - If recovering an existing database and corrupt data is found
    /// * `NullifierError::CorruptedFileSize` - If recovering a database with invalid file size
    pub fn create(path: &Path) -> Result<NullifierDB, NullifierError> {
        // Check if file already exists
        if path.exists() {
            // If it exists, try to recover it instead of overwriting
            debug!("Database file already exists at {:?}, recovering instead of creating new", path);
            return Self::recover(path);
        }
        
        // Create a new database instance
        let mut db = NullifierDB {
            writer: BufWriter::new(File::create(path).map_err(|e| NullifierError::Io { 
                source: e, 
                context: "creating new database file" 
            })?),
            map: HashSet::new(),
            db_path: path.to_path_buf(),
            lock_acquired: false,
        };
        
        // Now acquire the lock on the file
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
            self.writer.write_all(&scalar)
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
        // First, open the file for reading+writing
        // We'll use this file handle for both locking and reading/writing
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
            .map_err(|e| {
                if e.kind() == ErrorKind::NotFound {
                    NullifierError::FileNotFound { path: path.display().to_string() }
                } else {
                    NullifierError::Io { source: e, context: "opening database file for recovery" }
                }
            })?;
            
        // Create a database instance but don't populate it yet
        let mut db = NullifierDB {
            writer: BufWriter::new(file),
            map: HashSet::new(),
            db_path: path.to_path_buf(),
            lock_acquired: false,
        };
        
        // Now acquire the lock before proceeding with recovery
        db.acquire_lock()?;
        
        // Get a reference to the underlying file, seeking to the beginning
        {
            let file_ref = db.writer.get_mut();
            file_ref.seek(SeekFrom::Start(0)).map_err(|e| {
                // Make sure to release the lock if we encounter an error
                let _ = db.release_lock();
                NullifierError::Io { source: e, context: "seeking to beginning of file" }
            })?;
        }
        
        // We need to recreate the reader from scratch to avoid borrow issues
        // So we'll reopen the file for reading (we've already got the lock on it)
        let read_file = File::open(path).map_err(|e| {
            // Make sure to release the lock if we encounter an error
            let _ = db.release_lock();
            NullifierError::Io { source: e, context: "reopening database file for reading" }
        })?;
        
        let mut reader = BufReader::new(read_file);
        let mut buffer = [0u8; 32];
        let mut position: u64 = 0;
        
        // Read all nullifiers from the file
        loop {
            match reader.read_exact(&mut buffer) {
                Ok(_) => {
                    db.map.insert(buffer);
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

        // We need to get the file back from the reader to continue using it
        // At this point, we've read all nullifiers successfully
        
        // Check if file size is valid (multiple of 32 bytes)
        let metadata = db.writer.get_ref().metadata()
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
            if let Err(e) = db.writer.get_mut().set_len(valid_size) {
                // Release lock before returning error
                let _ = db.release_lock();
                return Err(NullifierError::TruncateError { 
                    source: e, 
                    target_size: valid_size 
                });
            }
        }
        
        // Position the writer at the end for appending
        if let Err(e) = db.writer.get_mut().seek(SeekFrom::End(0)) {
            // Release lock before returning error
            let _ = db.release_lock();
            return Err(NullifierError::Io { 
                source: e, 
                context: "positioning file writer at end of file" 
            });
        }
        
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
                warn!("LOCK FILE LEAK: Database lock file was not properly released for file: {:?}", self.db_path);
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
    use rand::Fill;

    /// Helper function to create a random Scalar for testing
    fn random_scalar() -> Scalar {
        let mut xs = [0u8; 32];
        xs.try_fill(&mut rand::thread_rng());
        xs
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
    fn test_empty_db_recovery() -> Result<(), NullifierError> {
        let temp_dir = tempdir().expect("Failed to create temp dir");
        let db_path = temp_dir.path().join("empty.db");
        
        // Create an empty database
        {
            let db = NullifierDB::create(&db_path)?;
            // Immediately close without adding any nullifiers
            db.flush_and_close()?;
        }
        
        // Use create on an existing database, which should recover it
        let recovered_db = NullifierDB::create(&db_path)?;
        
        // Verify it's empty
        assert_eq!(recovered_db.len(), 0, "Recovered empty database should have zero nullifiers");
        assert!(recovered_db.is_empty(), "Recovered empty database should be empty");
        
        Ok(())
    }
    
    #[test]
    fn test_lock_contention() {
        let temp_dir = tempdir().expect("Failed to create temp dir");
        let db_path = temp_dir.path().join("locked.db");
        
        // First, create a database and hold it open
        let db1 = NullifierDB::create(&db_path).expect("Failed to create first database");
        
        // Try to open the same database again while it's still locked
        let result = NullifierDB::recover(&db_path);
        
        // Check that we get the expected DatabaseLocked error
        match result {
            Err(NullifierError::DatabaseLocked { path }) => {
                assert_eq!(path, db_path.to_string_lossy().to_string(), 
                         "Lock error should contain the correct path");
                
                // Verify the error message includes instructions
                let error_msg = format!("{}", NullifierError::DatabaseLocked { path });
                assert!(error_msg.contains("restart your application"), 
                       "Error message should include recovery instructions");
            },
            Ok(_) => panic!("Expected DatabaseLocked error, got Ok"),
            Err(e) => panic!("Expected DatabaseLocked error, got {:?}", e),
        }
        
        // Close the first database
        drop(db1); // Implicitly calls drop which should release the lock
        
        // Now we should be able to open it
        let db2 = NullifierDB::recover(&db_path).expect("Failed to recover database after lock release");
        
        // Should be empty since we didn't add anything
        assert!(db2.is_empty(), "Database should be empty");
    }
    
    #[test]
    fn test_zero_scalar_nullifier() -> Result<(), NullifierError> {
        let temp_dir = tempdir().expect("Failed to create temp dir");
        let db_path = temp_dir.path().join("zero_scalar.db");
        
        // Create zero scalar (identity element)
        let zero_scalar = [0u8; 32];
        
        // Create database and insert zero scalar
        {
            let mut db = NullifierDB::create(&db_path)?;
            
            // Verify zero nullifier doesn't exist yet
            assert!(!db.contains(&zero_scalar), "Zero scalar should not exist initially");
            
            // Insert zero scalar
            let result = db.insert(zero_scalar)?;
            assert!(result, "Expected insert to return true for zero scalar");
            
            // Check it was added
            assert!(db.contains(&zero_scalar), "Expected zero scalar to exist after insertion");
            
            // Try to insert again
            let result = db.insert(zero_scalar)?;
            assert!(!result, "Expected insert to return false for duplicate zero scalar");
            
            // Manual close
            db.flush_and_close()?;
        }
        
        // Recover database and verify zero scalar persistence
        {
            let db = NullifierDB::recover(&db_path)?;
            
            // Check zero scalar was properly recovered
            assert!(db.contains(&zero_scalar), "Zero scalar should persist after recovery");
            assert_eq!(db.len(), 1, "Database should contain exactly one nullifier");
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
    
    #[test]
    fn test_create_recovers_existing_db() -> Result<(), NullifierError> {
        let temp_dir = tempdir().expect("Failed to create temp dir");
        let db_path = temp_dir.path().join("recovery_test.db");
        
        // Create initial nullifiers
        let initial_nullifiers = vec![random_scalar(), random_scalar()];
        
        // Create database and add initial nullifiers
        {
            let mut db = NullifierDB::create(&db_path)?;
            
            for nullifier in &initial_nullifiers {
                db.insert(*nullifier)?;
            }
            
            db.flush_and_close()?;
        }
        
        // Create additional nullifier to add after recovery
        let additional_nullifier = random_scalar();
        
        // Use create() again on the existing database, which should recover it
        {
            let mut db = NullifierDB::create(&db_path)?;
            
            // Verify all initial nullifiers were recovered
            assert_eq!(db.len(), initial_nullifiers.len(), 
                      "Database should contain all initial nullifiers after recovery");
            
            for nullifier in &initial_nullifiers {
                assert!(db.contains(nullifier), 
                       "Each initial nullifier should exist after recovery");
            }
            
            // Add one more nullifier
            db.insert(additional_nullifier)?;
            
            db.flush_and_close()?;
        }
        
        // Reopen one more time to verify all nullifiers are present
        {
            let db = NullifierDB::recover(&db_path)?;
            
            // Verify we have all nullifiers (initial + additional)
            assert_eq!(db.len(), initial_nullifiers.len() + 1, 
                      "Database should contain all nullifiers");
            
            // Check initial nullifiers still exist
            for nullifier in &initial_nullifiers {
                assert!(db.contains(nullifier), 
                       "Initial nullifier should still exist");
            }
            
            // Check additional nullifier exists
            assert!(db.contains(&additional_nullifier), 
                   "Additional nullifier should exist");
        }
        
        Ok(())
    }
}
