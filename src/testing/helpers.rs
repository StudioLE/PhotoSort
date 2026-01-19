use std::env::temp_dir;
use std::fs;
use std::io::Result;
use std::path::PathBuf;
use std::thread::current as current_thread;

use chrono::{Local, NaiveDate, NaiveDateTime, NaiveTime};
use tempfile::TempDir;

const DISABLE_TEMP_CLEANUP: bool = false;

/// Creates a test directory structure with source and target directories.
///
/// Creates a nested directory structure: `{tmp}/photo_sort/{test_name}/{iso_datetime}_XXXXXX/`
/// Cleanup is disabled to preserve files for inspection after tests run.
pub fn setup_test_dirs() -> Result<(TempDir, PathBuf, PathBuf)> {
    let test_name = get_test_name();
    let datetime_str = Local::now().format("%Y-%m-%dT%H-%M-%S").to_string();
    let base_path = temp_dir().join("photo_sort").join(test_name);
    fs::create_dir_all(&base_path)?;

    let temp_dir = tempfile::Builder::new()
        .prefix(&format!("{datetime_str}_"))
        .disable_cleanup(DISABLE_TEMP_CLEANUP)
        .tempdir_in(&base_path)?;
    let source_dir = temp_dir.path().join("source");
    let target_dir = temp_dir.path().join("target");
    fs::create_dir_all(&source_dir)?;
    fs::create_dir_all(&target_dir)?;
    Ok((temp_dir, source_dir, target_dir))
}

/// Gets the current test name from the thread name, with colons replaced by underscores.
pub fn get_test_name() -> String {
    current_thread()
        .name()
        .expect("should be able to get test name")
        .replace(':', "_")
}

/// Helper to create NaiveDateTime
pub fn get_datetime(
    year: i32,
    month: u32,
    day: u32,
    hour: u32,
    min: u32,
    sec: u32,
) -> NaiveDateTime {
    let date = NaiveDate::from_ymd_opt(year, month, day).unwrap();
    let time = NaiveTime::from_hms_opt(hour, min, sec).unwrap();
    NaiveDateTime::new(date, time)
}
