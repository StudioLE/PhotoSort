use anyhow::{anyhow, Result};
use filetime::FileTime;
use log::{debug, error, warn};
use std::fmt::{Display, Formatter};
use std::fs;
use std::path::Path;
use std::str::FromStr;

/// `ActualAction` is an enumeration that defines the different types of actions that can be performed on a file.
///
/// # Variants
///
/// * `Move` - Represents the action of moving a file.
/// * `Copy` - Represents the action of copying a file.
/// * `Hardlink` - Represents the action of creating a hard link to a file.
/// * `RelativeSymlink` - Represents the action of creating a relative symbolic link to a file.
/// * `AbsoluteSymlink` - Represents the action of creating an absolute symbolic link to a file.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum ActualAction {
    Move,
    Copy,
    Hardlink,
    RelativeSymlink,
    AbsoluteSymlink,
}

impl Display for ActualAction {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            ActualAction::Move => write!(f, "Move"),
            ActualAction::Copy => write!(f, "Copy"),
            ActualAction::Hardlink => write!(f, "Hardlink"),
            ActualAction::RelativeSymlink => write!(f, "RelSymlink"),
            ActualAction::AbsoluteSymlink => write!(f, "AbsSymlink"),
        }
    }
}

/// `ActionMode` defines the mode of operation of the tool
///
/// # Variants
/// * `Execute` - The provided action will be executed
/// * `DryRun` - The provided action will be printed but not executed
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum ActionMode {
    Execute(ActualAction),
    DryRun(ActualAction),
}

/// `FromStr` trait implementation for `ActualAction`.
///
/// This allows a string to be parsed into the `ActualAction` enum.
///
/// # Arguments
///
/// * `s` - A string slice that should be parsed into an `ActualAction`.
///
/// # Returns
///
/// * `Result<Self, Self::Err>` - Returns `Ok(ActualAction)` if the string could be parsed into an `ActionMode`, `Err(anyhow::Error)` otherwise.
impl FromStr for ActualAction {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> anyhow::Result<Self> {
        match s.to_lowercase().as_str() {
            "move" => Ok(ActualAction::Move),
            "copy" => Ok(ActualAction::Copy),
            "hardlink" | "hard" => Ok(ActualAction::Hardlink),
            "relative_symlink" | "relsym" => Ok(ActualAction::RelativeSymlink),
            "absolute_symlink" | "abssym" => Ok(ActualAction::AbsoluteSymlink),
            _ => Err(anyhow::anyhow!("Invalid action mode")),
        }
    }
}

/// Performs the specified action on the source file and target file.
///
/// # Arguments
///
/// * `source` - A `PathBuf` reference to the source file.
/// * `target` - A `PathBuf` reference to the target file.
/// * `action` - An `ActionMode` reference specifying the action to be performed.
/// * `mkdir` - Mkdir subfolders on the way, in dry-run mode no subfolders are created.
///
/// # Returns
///
/// * `std::io::Result<()>` - An IO Result indicating the success or failure of the operation.
///
/// # Actions
///
/// * `ActionMode::DryRun` - Prints the operation that would be performed without actually performing it.
/// * `ActionMode::Execute` - Performs the specified action on the source file and target file.
///    * `ActualAction::Move` - Moves the source file to the target location.
///    * `ActualAction::Copy` - Copies the source file to the target location.
///    * `ActualAction::Hardlink` - Creates a hard link at the target location pointing to the source file.
///    * `ActualAction::RelativeSymlink` - Creates a relative symbolic link at the target location pointing to the source file.
///    * `ActualAction::AbsoluteSymlink` - Creates an absolute symbolic link at the target location pointing to the source file.
///
/// # Errors
///
/// This function will return an error if:
///
/// * The target file already exists.
/// * An error occurred during the file operation.
pub fn file_action<P: AsRef<Path>, Q: AsRef<Path>>(
    source: P,
    target: Q,
    action: &ActionMode,
    mkdir: bool,
) -> Result<()> {
    let source = source.as_ref();
    let target = target.as_ref();

    error_file_exists(target)
        .map_err(|e| anyhow!("Target file already exists: {target:?} - {e:?}"))?;

    // check if parent folder exists
    if let Some(parent) = target.parent() {
        if !parent.exists() {
            if !mkdir {
                return Err(anyhow!(
                    "Target subfolder does not exist. Use --mkdir to create it: {parent:?}"
                ));
            }

            if matches!(action, ActionMode::DryRun(_)) {
                error!("[Mkdir] {}", parent.display());
            } else {
                fs::create_dir_all(parent).map_err(|e| {
                    anyhow!("Failed to create target subfolder: {parent:?} - {e:?}")
                })?;
            }
        }
    }

    let result = match action {
        ActionMode::Execute(ActualAction::Move) => move_file(source, target),
        ActionMode::Execute(ActualAction::Copy) => copy_file(source, target),
        ActionMode::Execute(ActualAction::Hardlink) => hardlink_file(source, target),
        ActionMode::Execute(ActualAction::RelativeSymlink) => relative_symlink_file(source, target),
        ActionMode::Execute(ActualAction::AbsoluteSymlink) => absolute_symlink_file(source, target),
        ActionMode::DryRun(action) => {
            dry_run(source, target, *action);
            Ok(())
        }
    };

    match result {
        Ok(()) => Ok(()),
        Err(e) => Err(anyhow!("Failed to perform action: {e:?}")),
    }
}

fn dry_run<A: AsRef<Path>, B: AsRef<Path>>(source: A, target: B, action: ActualAction) {
    error!(
        "[{}] {} -> {}",
        action,
        source.as_ref().display(),
        target.as_ref().display()
    );
}

fn error_file_exists(target: &Path) -> std::io::Result<()> {
    if target.exists() {
        Err(std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            "Target file already exists",
        ))
    } else {
        Ok(())
    }
}

fn copy_file<A: AsRef<Path>, B: AsRef<Path>>(source: A, target: B) -> std::io::Result<()> {
    let source = source.as_ref();
    let target = target.as_ref();

    debug!("Copying {} -> {}", source.display(), target.display());

    let metadata = fs::metadata(source)?;
    let result = fs::copy(source, target)?;

    if metadata.len() != result {
        let _ = fs::remove_file(target);
        return Err(std::io::Error::other("File copy failed"));
    }

    let mtime = FileTime::from_last_modification_time(&metadata);
    let atime = FileTime::from_last_access_time(&metadata);

    filetime::set_file_times(target, atime, mtime)?;

    Ok(())
}

fn move_file<A: AsRef<Path>, B: AsRef<Path>>(source: A, target: B) -> std::io::Result<()> {
    let source = source.as_ref();
    let target = target.as_ref();

    debug!("Moving {} -> {}", source.display(), target.display());

    let result = fs::rename(source, target);
    if let Err(err) = result {
        warn!(
            "Renaming file failed, falling back to cut/paste: {:?} for file {} -> {}",
            err,
            source.display(),
            target.display()
        );
        copy_file(source, target)?;
        fs::remove_file(source)
    } else {
        Ok(())
    }
}

fn hardlink_file<A: AsRef<Path>, B: AsRef<Path>>(source: A, target: B) -> std::io::Result<()> {
    let source = source.as_ref();
    let target = target.as_ref();

    debug!(
        "Creating hardlink {} -> {}",
        source.display(),
        target.display()
    );

    let result = fs::hard_link(source, target);
    if let Err(err) = result {
        error!(
            "Creating hardlink failed, falling back to copy: {:?} for file {} -> {}",
            err,
            source.display(),
            target.display()
        );
        copy_file(source, target)
    } else {
        Ok(())
    }
}

fn relative_symlink_file<A: AsRef<Path>, B: AsRef<Path>>(
    source: A,
    target: B,
) -> std::io::Result<()> {
    let source = source.as_ref();
    let target = target.as_ref();

    debug!(
        "Creating symlink {} -> {}",
        source.display(),
        target.display()
    );

    symlink::symlink_file(source, target)?;

    Ok(())
}

fn absolute_symlink_file<A: AsRef<Path>, B: AsRef<Path>>(
    source: A,
    target: B,
) -> std::io::Result<()> {
    let source = source.as_ref();
    let target = target.as_ref();

    debug!(
        "Creating symlink {} -> {}",
        source.display(),
        target.display()
    );
    let source = fs::canonicalize(source)?;

    relative_symlink_file(&source, target)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::*;
    use crate::{
        analysis::exif2date::ExifDateType, analysis::filename2date::NaiveFileNameParser,
        analysis::name_formatters::*, AnalysisType, Analyzer, AnalyzerSettings,
    };
    use std::path::PathBuf;

    /// Helper to create a standard analyzer for action tests
    fn create_action_test_analyzer(
        source_dirs: Vec<PathBuf>,
        target_dir: PathBuf,
        action_mode: ActionMode,
    ) -> Analyzer {
        let settings = AnalyzerSettings {
            analysis_type: AnalysisType::OnlyExif,
            exif_date_type: ExifDateType::Creation,
            source_dirs,
            target_dir,
            recursive_source: true,
            file_format: "{date?%Y}/{date?%m}/{type}{_:date}{-:name}{-:dup}.{ext?lower}"
                .to_string(),
            nodate_file_format: "nodate/{type}{-:name}{-:dup}.{ext?lower}".to_string(),
            unknown_file_format: None,
            bracketed_file_format: None,
            date_format: "%Y%m%d-%H%M%S".to_string(),
            extensions: vec!["jpg".to_string(), "jpeg".to_string()],
            #[cfg(feature = "video")]
            video_extensions: vec![],
            action_type: action_mode,
            mkdir: true,
        };

        let mut analyzer = Analyzer::new(settings).expect("Failed to create analyzer");
        analyzer.add_transformer(NaiveFileNameParser::default());
        analyzer.add_formatter(FormatDate::default());
        analyzer.add_formatter(FormatName::default());
        analyzer.add_formatter(FormatDuplicate::default());
        analyzer.add_formatter(FormatExtension::default());
        analyzer.add_formatter(FormatFileType::default());
        analyzer.add_formatter(FormatOriginalName::default());
        analyzer.add_formatter(FormatOriginalFileName::default());

        analyzer
    }

    #[test]
    fn test_copy_action() {
        // Arrange
        let (_temp_dir, source_dir, target_dir) = setup_test_dirs().unwrap();
        let datetime = get_datetime(2024, 5, 1, 9, 0, 0);
        let source_file = TestImageBuilder::new()
            .jpeg()
            .with_exif_datetime(datetime)
            .with_directory(&source_dir)
            .with_filename("to_copy.jpg")
            .build()
            .unwrap();
        let analyzer = create_action_test_analyzer(
            vec![source_dir],
            target_dir.clone(),
            ActionMode::Execute(ActualAction::Copy),
        );

        // Act
        analyzer.run_file(&source_file, &None).unwrap();

        // Assert
        assert!(
            source_file.exists(),
            "Source file should still exist after copy"
        );
        assert!(target_dir
            .join("2024/05/IMG_20240501-090000-to_copy.jpg")
            .exists());
    }

    #[test]
    fn test_move_action() {
        // Arrange
        let (_temp_dir, source_dir, target_dir) = setup_test_dirs().unwrap();
        let datetime = get_datetime(2024, 5, 1, 9, 0, 0);
        let source_file = TestImageBuilder::new()
            .jpeg()
            .with_exif_datetime(datetime)
            .with_directory(&source_dir)
            .with_filename("to_move.jpg")
            .build()
            .unwrap();
        let analyzer = create_action_test_analyzer(
            vec![source_dir],
            target_dir.clone(),
            ActionMode::Execute(ActualAction::Move),
        );

        // Act
        analyzer.run_file(&source_file, &None).unwrap();

        // Assert
        assert!(
            !source_file.exists(),
            "Source file should not exist after move"
        );
        assert!(target_dir
            .join("2024/05/IMG_20240501-090000-to_move.jpg")
            .exists());
    }

    #[test]
    fn test_hardlink_action() {
        // Arrange
        let (_temp_dir, source_dir, target_dir) = setup_test_dirs().unwrap();
        let datetime = get_datetime(2024, 5, 1, 9, 0, 0);
        let source_file = TestImageBuilder::new()
            .jpeg()
            .with_exif_datetime(datetime)
            .with_directory(&source_dir)
            .with_filename("to_hardlink.jpg")
            .build()
            .unwrap();
        let analyzer = create_action_test_analyzer(
            vec![source_dir],
            target_dir.clone(),
            ActionMode::Execute(ActualAction::Hardlink),
        );

        // Act
        analyzer.run_file(&source_file, &None).unwrap();

        // Assert
        let target_file = target_dir.join("2024/05/IMG_20240501-090000-to_hardlink.jpg");
        assert!(
            source_file.exists(),
            "Source file should still exist after hardlink"
        );
        assert!(target_file.exists(), "Target file should exist");
        let source_meta = fs::metadata(&source_file).unwrap();
        let target_meta = fs::metadata(&target_file).unwrap();
        assert_eq!(source_meta.len(), target_meta.len());
    }

    #[test]
    fn test_symlink_action() {
        // Arrange
        let (_temp_dir, source_dir, target_dir) = setup_test_dirs().unwrap();
        let datetime = get_datetime(2024, 5, 1, 9, 0, 0);
        let source_file = TestImageBuilder::new()
            .jpeg()
            .with_exif_datetime(datetime)
            .with_directory(&source_dir)
            .with_filename("to_symlink.jpg")
            .build()
            .unwrap();
        let analyzer = create_action_test_analyzer(
            vec![source_dir],
            target_dir.clone(),
            ActionMode::Execute(ActualAction::AbsoluteSymlink),
        );

        // Act
        analyzer.run_file(&source_file, &None).unwrap();

        // Assert
        let target_file = target_dir.join("2024/05/IMG_20240501-090000-to_symlink.jpg");
        assert!(source_file.exists(), "Source file should still exist");
        assert!(
            target_file.exists() || target_file.is_symlink(),
            "Target should exist or be a symlink"
        );
        #[cfg(unix)]
        {
            let meta = fs::symlink_metadata(&target_file).unwrap();
            assert!(meta.is_symlink(), "Target should be a symlink");
        }
    }

    #[test]
    fn test_dry_run_mode() {
        // Arrange
        let (_temp_dir, source_dir, target_dir) = setup_test_dirs().unwrap();
        let datetime = get_datetime(2024, 5, 1, 9, 0, 0);
        let source_file = TestImageBuilder::new()
            .jpeg()
            .with_exif_datetime(datetime)
            .with_directory(&source_dir)
            .with_filename("dry_run_test.jpg")
            .build()
            .unwrap();
        let analyzer = create_action_test_analyzer(
            vec![source_dir],
            target_dir.clone(),
            ActionMode::DryRun(ActualAction::Copy),
        );

        // Act
        analyzer.run_file(&source_file, &None).unwrap();

        // Assert
        assert!(source_file.exists());
        assert!(!target_dir
            .join("2024/05/IMG_20240501-090000-dry_run_test.jpg")
            .exists());
    }

    // ============================================================================
    // Unit tests for low-level file operations
    // ============================================================================

    #[test]
    fn test_copy_file_preserves_content() {
        // Arrange
        let (_temp_dir, source_dir, target_dir) = setup_test_dirs().unwrap();
        let source_file = source_dir.join("test.txt");
        let target_file = target_dir.join("test_copy.txt");
        fs::write(&source_file, b"test content").unwrap();

        // Act
        copy_file(&source_file, &target_file).unwrap();

        // Assert
        assert!(target_file.exists());
        assert_eq!(fs::read(&target_file).unwrap(), b"test content");
    }

    #[test]
    fn test_move_file_removes_source() {
        // Arrange
        let (_temp_dir, source_dir, target_dir) = setup_test_dirs().unwrap();
        let source_file = source_dir.join("test.txt");
        let target_file = target_dir.join("test_moved.txt");
        fs::write(&source_file, b"test content").unwrap();

        // Act
        move_file(&source_file, &target_file).unwrap();

        // Assert
        assert!(!source_file.exists());
        assert!(target_file.exists());
        assert_eq!(fs::read(&target_file).unwrap(), b"test content");
    }

    #[test]
    fn test_file_action_fails_if_target_exists() {
        // Arrange
        let (_temp_dir, source_dir, target_dir) = setup_test_dirs().unwrap();
        let source_file = source_dir.join("source.txt");
        let target_file = target_dir.join("target.txt");
        fs::write(&source_file, b"source content").unwrap();
        fs::write(&target_file, b"existing content").unwrap();

        // Act
        let result = file_action(
            &source_file,
            &target_file,
            &ActionMode::Execute(ActualAction::Copy),
            false,
        );

        // Assert
        assert!(result.is_err());
    }

    #[test]
    fn test_actual_action_from_str() {
        assert_eq!(ActualAction::from_str("move").unwrap(), ActualAction::Move);
        assert_eq!(ActualAction::from_str("copy").unwrap(), ActualAction::Copy);
        assert_eq!(
            ActualAction::from_str("hardlink").unwrap(),
            ActualAction::Hardlink
        );
        assert_eq!(
            ActualAction::from_str("hard").unwrap(),
            ActualAction::Hardlink
        );
        assert_eq!(
            ActualAction::from_str("relative_symlink").unwrap(),
            ActualAction::RelativeSymlink
        );
        assert_eq!(
            ActualAction::from_str("relsym").unwrap(),
            ActualAction::RelativeSymlink
        );
        assert_eq!(
            ActualAction::from_str("absolute_symlink").unwrap(),
            ActualAction::AbsoluteSymlink
        );
        assert_eq!(
            ActualAction::from_str("abssym").unwrap(),
            ActualAction::AbsoluteSymlink
        );
        assert!(ActualAction::from_str("invalid").is_err());
    }

    #[test]
    fn test_actual_action_display() {
        assert_eq!(format!("{}", ActualAction::Move), "Move");
        assert_eq!(format!("{}", ActualAction::Copy), "Copy");
        assert_eq!(format!("{}", ActualAction::Hardlink), "Hardlink");
        assert_eq!(format!("{}", ActualAction::RelativeSymlink), "RelSymlink");
        assert_eq!(format!("{}", ActualAction::AbsoluteSymlink), "AbsSymlink");
    }
}
