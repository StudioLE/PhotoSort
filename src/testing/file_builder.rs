use std::fs::File;
use std::io::{Result, Write};
use std::path::{Path, PathBuf};

/// Type of placeholder file to create.
#[derive(Debug, Clone, Copy, Default)]
pub enum PlaceholderType {
    #[default]
    Raw,
    #[cfg(feature = "video")]
    Video,
}

/// Builder for creating placeholder test files (RAW, video).
///
/// # Example
///
/// ```ignore
/// TestFileBuilder::new()
///     .raw()
///     .with_directory(&source_dir)
///     .with_filename("DSC0001.cr2")
///     .build()?;
/// ```
#[derive(Debug, Clone, Default)]
pub struct TestFileBuilder {
    file_type: PlaceholderType,
    directory: Option<PathBuf>,
    filename: Option<String>,
    content: Option<Vec<u8>>,
}

impl TestFileBuilder {
    /// Creates a new `TestFileBuilder` with default settings (RAW file).
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the file type to RAW.
    pub fn raw(mut self) -> Self {
        self.file_type = PlaceholderType::Raw;
        self
    }

    /// Sets the file type to video (requires `video` feature).
    #[cfg(feature = "video")]
    pub fn video(mut self) -> Self {
        self.file_type = PlaceholderType::Video;
        self
    }

    /// Sets the output directory.
    pub fn with_directory(mut self, dir: &Path) -> Self {
        self.directory = Some(dir.to_path_buf());
        self
    }

    /// Sets the output filename.
    pub fn with_filename(mut self, name: &str) -> Self {
        self.filename = Some(name.to_string());
        self
    }

    /// Sets custom file content.
    pub fn with_content(mut self, content: &[u8]) -> Self {
        self.content = Some(content.to_vec());
        self
    }

    /// Builds the file to directory + filename.
    ///
    /// # Panics
    ///
    /// Panics if `directory` or `filename` is not set.
    pub fn build(self) -> Result<PathBuf> {
        let dir = self.directory.expect("directory must be set");
        let filename = self.filename.expect("filename must be set");
        let path = dir.join(&filename);
        Self::write_file(&path, self.file_type, self.content)?;
        Ok(path)
    }

    /// Builds the file to an explicit path.
    pub fn build_to(self, path: &Path) -> Result<()> {
        Self::write_file(path, self.file_type, self.content)
    }

    fn write_file(path: &Path, file_type: PlaceholderType, content: Option<Vec<u8>>) -> Result<()> {
        let default_content: &[u8] = match file_type {
            PlaceholderType::Raw => b"FAKE_RAW_FILE_FOR_TESTING",
            #[cfg(feature = "video")]
            PlaceholderType::Video => b"FAKE_VIDEO_FILE_FOR_TESTING",
        };

        let content = content.as_deref().unwrap_or(default_content);

        let mut file = File::create(path)?;
        file.write_all(content)?;
        Ok(())
    }
}
