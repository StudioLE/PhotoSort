use chrono::{DateTime, NaiveDateTime, Utc};
use std::fs::metadata;
use std::path::Path;

/// This function retrieves the modification time from the file's metadata.
///
/// # Arguments
/// * `path` - A reference to a `Path` object.
///
/// # Returns
/// * `Some(NaiveDateTime)` - If the modification time could be retrieved from the file system metadata.
/// * `None` - If there is no modification time available.
///
/// # Errors
/// This function will return an error if:
/// * The file metadata could not be read.
/// * The modification time could not be converted to a valid datetime.
pub fn get_file_modified_time<P: AsRef<Path>>(path: P) -> anyhow::Result<Option<NaiveDateTime>> {
    let metadata = metadata(path.as_ref())?;
    let system_time = metadata.modified()?;
    let datetime = DateTime::<Utc>::from(system_time).naive_local();
    Ok(Some(datetime))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;
    use tempfile::TempDir;

    #[test]
    fn test_get_file_modified_time_returns_date() {
        // Arrange
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("test_file.txt");
        File::create(&file_path).unwrap();

        // Act
        let result = get_file_modified_time(&file_path);

        // Assert
        assert!(result.is_ok());
        let datetime = result.unwrap();
        assert!(datetime.is_some(), "Should return a datetime for existing file");
    }

    #[test]
    fn test_get_file_modified_time_nonexistent_file() {
        // Arrange
        let nonexistent_path = Path::new("/nonexistent/path/to/file.txt");

        // Act
        let result = get_file_modified_time(nonexistent_path);

        // Assert
        assert!(result.is_err(), "Should return error for nonexistent file");
    }
}
