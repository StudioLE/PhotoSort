//! Builder pattern implementations for creating test files.
//!
//! Provides `TestImageBuilder` for creating JPEG/PNG images with optional EXIF data,
//! and `TestFileBuilder` for creating placeholder RAW/video files.

use std::io::Result;
use std::path::{Path, PathBuf};

use chrono::NaiveDateTime;

/// Image format for test images.
#[derive(Debug, Clone, Copy, Default)]
pub enum ImageFormat {
    #[default]
    Jpeg,
    Png,
}

/// Builder for creating test image files (JPEG, PNG).
///
/// # Example
///
/// ```ignore
/// TestImageBuilder::new()
///     .jpeg()
///     .dimensions(100, 100)
///     .with_directory(&source_dir)
///     .with_filename("photo.jpg")
///     .with_exif_datetime(datetime)
///     .build()?;
/// ```
#[derive(Debug, Clone)]
pub struct TestImageBuilder {
    format: ImageFormat,
    width: u32,
    height: u32,
    directory: Option<PathBuf>,
    filename: Option<String>,
    exif_datetime: Option<NaiveDateTime>,
}

impl Default for TestImageBuilder {
    fn default() -> Self {
        Self {
            format: ImageFormat::Jpeg,
            width: 10,
            height: 10,
            directory: None,
            filename: None,
            exif_datetime: None,
        }
    }
}

impl TestImageBuilder {
    /// Creates a new `TestImageBuilder` with default settings (10x10 JPEG).
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the image format to JPEG.
    pub fn jpeg(mut self) -> Self {
        self.format = ImageFormat::Jpeg;
        self
    }

    /// Sets the image format to PNG.
    pub fn png(mut self) -> Self {
        self.format = ImageFormat::Png;
        self
    }

    /// Sets the image dimensions.
    pub fn with_dimensions(mut self, width: u32, height: u32) -> Self {
        self.width = width;
        self.height = height;
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

    /// Sets the EXIF DateTimeOriginal metadata (JPEG only).
    pub fn with_exif_datetime(mut self, dt: NaiveDateTime) -> Self {
        self.exif_datetime = Some(dt);
        self
    }

    /// Builds the image file to directory + filename.
    ///
    /// # Panics
    ///
    /// Panics if `directory` or `filename` is not set.
    pub fn get_path(&self) -> PathBuf {
        let dir = self.directory.clone().expect("directory must be set");
        let filename = self.filename.clone().expect("filename must be set");
        dir.join(&filename)
    }

    /// Builds the image file to directory + filename.
    ///
    /// # Panics
    ///
    /// Panics if `directory` or `filename` is not set.
    pub fn build(self) -> Result<PathBuf> {
        let path = self.get_path();
        Self::write_image(
            &path,
            self.format,
            self.width,
            self.height,
            self.exif_datetime,
        )?;
        Ok(path)
    }

    fn write_image(
        path: &Path,
        format: ImageFormat,
        width: u32,
        height: u32,
        exif_datetime: Option<NaiveDateTime>,
    ) -> Result<()> {
        use image::{ImageBuffer, Rgb};

        // Create a simple gradient image
        let img: ImageBuffer<Rgb<u8>, Vec<u8>> = ImageBuffer::from_fn(width, height, |x, y| {
            Rgb([(x * 25) as u8, (y * 25) as u8, 128])
        });

        img.save(path)
            .map_err(|e| std::io::Error::other(format!("Failed to save image: {e}")))?;

        // Add EXIF if requested (JPEG only)
        if let Some(dt) = exif_datetime {
            if matches!(format, ImageFormat::Jpeg) {
                use little_exif::exif_tag::ExifTag;
                use little_exif::metadata::Metadata;

                let exif_datetime = dt.format("%Y:%m:%d %H:%M:%S").to_string();
                let mut metadata = Metadata::new();
                metadata.set_tag(ExifTag::DateTimeOriginal(exif_datetime));
                metadata
                    .write_to_file(path)
                    .map_err(|e| std::io::Error::other(format!("Failed to write EXIF: {e}")))?;
            }
        }

        Ok(())
    }
}
