#![doc = include_str!("../README.md")]
#![allow(clippy::unnecessary_debug_formatting)]

use crate::analysis::exif2date::ExifDateType;
use crate::analysis::name_formatters::{BracketInfo, FileType, NameFormatterInvocationInfo};
use action::ActionMode;
use anyhow::{anyhow, Result};
use chrono::NaiveDateTime;
use log::{debug, error, info, trace, warn};
use std::cmp::Ordering;
use std::ffi::OsStr;
use std::fs;
use std::fs::{DirEntry, File};
use std::io::{Read, Seek};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::LazyLock;

pub mod action;
pub mod analysis;
pub mod name;

/// `AnalysisType` is an enumeration that defines the different types of analysis that can be performed on a file.
///
/// # Variants
///
/// * `OnlyExif` - Represents the action of analyzing a file based only on its Exif data.
/// * `OnlyName` - Represents the action of analyzing a file based only on its name.
/// * `ExifThenName` - Represents the action of analyzing a file based first on its Exif data, then on its name if the Exif data is not sufficient.
/// * `NameThenExif` - Represents the action of analyzing a file based first on its name, then on its Exif data if the name is not sufficient.
/// * `ExifThenNameThenFs` - Like `ExifThenName`, but falls back to the file's filesystem date if neither Exif nor name analysis yields a date.
/// * `NameThenExifThenFs` - Like `NameThenExif`, but falls back to the file's filesystem date if neither name nor Exif analysis yields a date.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum AnalysisType {
    OnlyExif,
    OnlyName,
    ExifThenName,
    NameThenExif,
    ExifThenNameThenFs,
    NameThenExifThenFs,
}
/// Implementation of the `FromStr` trait for `AnalysisType`.
///
/// This allows a string to be parsed into the `AnalysisType` enum.
///
/// # Arguments
///
/// * `s` - A string slice that should be parsed into an `AnalysisType`.
///
/// # Returns
///
/// * `Result<Self, Self::Err>` - Returns `Ok(AnalysisType)` if the string could be parsed into an `AnalysisType`, `Err(anyhow::Error)` otherwise.
impl FromStr for AnalysisType {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self> {
        match s.to_lowercase().as_str() {
            "only_exif" | "exif" => Ok(AnalysisType::OnlyExif),
            "only_name" | "name" => Ok(AnalysisType::OnlyName),
            "exif_then_name" | "exif_name" => Ok(AnalysisType::ExifThenName),
            "name_then_exif" | "name_exif" => Ok(AnalysisType::NameThenExif),
            "exif_then_name_then_fs" | "exif_name_fs" => Ok(AnalysisType::ExifThenNameThenFs),
            "name_then_exif_then_fs" | "name_exif_fs" => Ok(AnalysisType::NameThenExifThenFs),
            _ => Err(anyhow::anyhow!("Invalid analysis type")),
        }
    }
}

/// `AnalyzerSettings` is a struct that holds the settings for an `Analyzer`.
///
/// # Fields
/// * `analysis_type` - An `AnalysisType` that specifies the type of analysis to perform on a file.
/// * `exif_date_type` - Which EXIF date to use when analyzing photos. See [`ExifDateType`] for details.
/// * `source_dirs` - A vector of `Path` references that represent the source directories to analyze.
/// * `target_dir` - A `Path` reference that represents the target directory for the analysis results.
/// * `recursive_source` - A boolean that indicates whether to analyze source directories recursively.
/// * `file_format` - A string that represents the target format of the files to analyze.
/// * `nodate_file_format` - A string that represent the target format of files with no date.
/// * `unknown_file_format` - An optional string that represents the target format of files not matching the list of extensions
/// * `date_format` - A string that represents the format of the dates in the files to analyze.
/// * `extensions` - A vector of strings that represent the file extensions to consider during analysis.
/// * `action_type` - An `ActionMode` that specifies the type of action to perform on a file after analysis.
/// * `mkdir` - A boolean that indicates whether to create the target directory if it does not exist.
#[derive(Debug, Clone)]
pub struct AnalyzerSettings {
    pub analysis_type: AnalysisType,
    pub exif_date_type: ExifDateType,
    pub source_dirs: Vec<PathBuf>,
    pub target_dir: PathBuf,
    pub recursive_source: bool,
    pub file_format: String,
    pub nodate_file_format: String,
    pub unknown_file_format: Option<String>,
    pub bracketed_file_format: Option<String>,
    pub date_format: String,
    pub extensions: Vec<String>,
    #[cfg(feature = "video")]
    pub video_extensions: Vec<String>,
    pub action_type: ActionMode,
    pub mkdir: bool,
}

static RE_DETECT_NAME_FORMAT_COMMAND: LazyLock<regex::Regex> = LazyLock::new(|| {
    regex::Regex::new(
        r"\{([^}]*)}", // finds { ... } blocks
    )
    .expect("Failed to compile regex")
});

static RE_COMMAND_SPLIT: LazyLock<regex::Regex> = LazyLock::new(|| {
    regex::Regex::new(
        r"^(([^:]*):)?(.*)$", // splits command into modifiers:command
    )
    .expect("Failed to compile regex")
});

/// `Analyzer` is a struct that represents an analyzer for files.
///
/// # Fields
///
/// * `name_transformers` - A list of `NameTransformer` objects that are used to transform the names of files during analysis.
/// * `name_formatters` - A list of `NameFormatter` objects that are used to generate the new names of files after analysis.
/// * `settings` - An `AnalyzerSettings` object that holds the settings for the `Analyzer`.
pub struct Analyzer {
    name_transformers:
        Vec<Box<dyn analysis::filename2date::FileNameToDateTransformer + Send + Sync>>,
    name_formatters: Vec<Box<dyn analysis::name_formatters::NameFormatter + Send + Sync>>,
    pub settings: AnalyzerSettings,
}

/// Implementation of methods for the `Analyzer` struct.
///
/// # Methods
///
/// * [`new`](#method.new) - Creates a new `Analyzer` with the given settings.
/// * [`add_transformer`](#method.add_transformer) - Adds a name transformer to the `Analyzer`.
/// * [`analyze_name`](#method.analyze_name) - Analyzes the name of a file.
/// * [`analyze_exif`](#method.analyze_exif) - Analyzes the Exif data of a file.
/// * [`analyze`](#method.analyze) - Analyzes a file based on the `Analyzer`'s settings.
/// * [`compose_file_name`](#method.compose_file_name) - Composes a file name based on the given date, name, and duplicate counter.
/// * [`do_file_action`](#method.do_file_action) - Performs the file action specified in the `Analyzer`'s settings on a file.
/// * [`is_valid_extension`](#method.is_valid_extension) - Checks if a file has a valid extension.
/// * [`rename_files_in_folder`](#method.rename_files_in_folder) - Renames files in a folder based on the `Analyzer`'s settings.
/// * [`run`](#method.run) - Runs the `Analyzer`, renaming files in the source directories based on the `Analyzer`'s settings.
impl Analyzer {
    /// Creates a new `Analyzer` with the given settings.
    ///
    /// # Arguments
    ///
    /// * `settings` - An `AnalyzerSettings` object that holds the settings for the `Analyzer`.
    ///
    /// # Returns
    ///
    /// * `Result<Analyzer>` - Returns `Ok(Analyzer)` if the `Analyzer` could be created successfully, `Err(anyhow::Error)` otherwise.
    ///
    /// # Errors
    ///
    /// * If the target directory does not exist.
    /// * If a source directory does not exist.
    /// * If an error occurs while getting the standard name transformers.
    pub fn new(settings: AnalyzerSettings) -> Result<Analyzer> {
        let analyzer = Analyzer {
            name_transformers: Vec::default(),
            name_formatters: Vec::default(),
            settings,
        };

        if !analyzer.settings.target_dir.exists() {
            return Err(anyhow!("Target directory does not exist"));
        }
        for source in &analyzer.settings.source_dirs {
            if !source.exists() {
                return Err(anyhow!("Source directory {source:?} does not exist"));
            }
        }

        Ok(analyzer)
    }

    /// Adds a name transformer to the `Analyzer`.
    ///
    /// # Arguments
    /// * `transformer` - A `NameTransformer` object that is used to transform the names of files during analysis.
    pub fn add_transformer<
        T: 'static + analysis::filename2date::FileNameToDateTransformer + Send + Sync,
    >(
        &mut self,
        transformer: T,
    ) {
        self.name_transformers.push(Box::new(transformer));
    }

    /// Adds a name formatter to the `Analyzer`.
    ///
    /// # Arguments
    /// * `formatter` - A `NameFormatter` object that is used to generate the new names of files after analysis.
    pub fn add_formatter<T: 'static + analysis::name_formatters::NameFormatter + Send + Sync>(
        &mut self,
        formatter: T,
    ) {
        self.name_formatters.push(Box::new(formatter));
    }

    fn analyze_name(&self, name: &str) -> Result<(Option<NaiveDateTime>, String)> {
        let result = analysis::get_name_time(name, &self.name_transformers)?;
        match result {
            Some((time, name)) => Ok((Some(time), name)),
            None => Ok((None, name.to_string())),
        }
    }

    fn analyze_photo_exif<S: Read + Seek>(
        file: S,
        date_type: ExifDateType,
    ) -> Result<Option<NaiveDateTime>> {
        let exif_time = analysis::exif2date::get_exif_time(file, date_type)?;
        Ok(exif_time)
    }

    #[cfg(feature = "video")]
    fn analyze_video_metadata<P: AsRef<Path>>(path: P) -> Result<Option<NaiveDateTime>> {
        let video_time = analysis::video2date::get_video_time(path)?;
        Ok(video_time)
    }

    fn analyze_fs<P: AsRef<Path>>(path: P) -> Result<Option<NaiveDateTime>> {
        let fs_time = analysis::fs2date::get_file_modified_time(path)?;
        Ok(fs_time)
    }

    fn analyze_exif<A: AsRef<Path>>(&self, path: A) -> Result<Option<NaiveDateTime>> {
        let path = path.as_ref();

        #[cfg(feature = "video")]
        let video = self.is_valid_video_extension(path.extension())?;
        let photo = self.is_valid_photo_extension(path.extension())?;

        #[cfg(feature = "video")]
        {
            if video && photo {
                return Err(anyhow::anyhow!("File has both photo and video extensions. Do not include the same extension in both settings"));
            }
        }

        if photo {
            let file = File::open(path)?;
            return Analyzer::analyze_photo_exif(&file, self.settings.exif_date_type);
        }
        #[cfg(feature = "video")]
        if video {
            return Analyzer::analyze_video_metadata(path);
        }

        Err(anyhow::anyhow!("File extension is not valid"))
    }

    /// Analyzes a file for a date based on the `Analyzer`'s settings.
    ///
    /// # Arguments
    /// * `path` - A `PathBuf` that represents the path of the file to analyze.
    ///
    /// # Returns
    /// * `Result<(Option<NaiveDateTime>, String)>` - Returns a tuple containing an `Option<NaiveDateTime>` and a `String`.
    ///   The `Option<NaiveDateTime>` represents the date and time extracted from the file, if any.
    ///   The `String` represents the transformed name of the file.
    ///
    /// # Errors
    /// This function will return an error if:
    /// * The file name cannot be retrieved or is invalid.
    /// * The file cannot be opened.
    /// * An error occurs during the analysis of the file's Exif data or name.
    pub fn analyze<A: AsRef<Path>>(&self, path: A) -> Result<(Option<NaiveDateTime>, String)> {
        let path = path.as_ref();

        let name = path
            .file_name()
            .ok_or(anyhow::anyhow!("No file name"))?
            .to_str()
            .ok_or(anyhow::anyhow!("Invalid file name"))?;

        let valid_extension = self
            .is_valid_extension(path.extension())
            .unwrap_or_else(|err| {
                warn!("Error checking file extension: {err}");
                false
            });
        if !valid_extension {
            warn!("Skipping file with invalid extension: {}", path.display());
            return Err(anyhow::anyhow!("Invalid file extension"));
        }

        let result = match self.settings.analysis_type {
            AnalysisType::OnlyExif => {
                let exif_result = self
                    .analyze_exif(path)
                    .map_err(|e| anyhow!("Error analyzing Exif data: {e}"))?;
                let name_result = self.analyze_name(name);

                match name_result {
                    Ok((_, name)) => (exif_result, name),
                    Err(_err) => (exif_result, name.to_string()),
                }
            }
            AnalysisType::OnlyName => self.analyze_name(name)?,
            AnalysisType::ExifThenName | AnalysisType::ExifThenNameThenFs => {
                let exif_result = self.analyze_exif(path);
                let exif_result = match exif_result {
                    Err(e) => {
                        warn!("Error analyzing Exif data: {} for {}", e, path.display());
                        info!("Falling back to name analysis");
                        None
                    }
                    Ok(date) => date,
                };
                let name_result = self.analyze_name(name);

                match exif_result {
                    Some(date) => match name_result {
                        Ok((_, name)) => (Some(date), name),
                        Err(_err) => (Some(date), name.to_string()),
                    },
                    None => name_result?,
                }
            }
            AnalysisType::NameThenExif | AnalysisType::NameThenExifThenFs => {
                let name_result = self.analyze_name(name)?;
                if name_result.0.is_none() {
                    let exif_result = self.analyze_exif(path);
                    match exif_result {
                        Ok(date) => (date, name_result.1),
                        Err(e) => {
                            warn!("Error analyzing Exif data: {} for {}", e, path.display());
                            (None, name_result.1)
                        }
                    }
                } else {
                    name_result
                }
            }
        };

        let uses_fs_fallback = matches!(
            self.settings.analysis_type,
            AnalysisType::ExifThenNameThenFs | AnalysisType::NameThenExifThenFs
        );
        if result.0.is_none() && uses_fs_fallback {
            info!("Falling back to filesystem date for {}", path.display());
            match Self::analyze_fs(path) {
                Ok(date) => return Ok((date, result.1)),
                Err(e) => {
                    warn!(
                        "Error getting filesystem date: {} for {}",
                        e,
                        path.display()
                    );
                }
            }
        }
        Ok(result)
    }

    /// Replaces {name}, {date}, ... in a format with actual values
    fn replace_filepath_parts<'a, 'b>(
        &self,
        format_string: &'b str,
        info: &'a NameFormatterInvocationInfo,
    ) -> Result<String> {
        #[derive(Debug)]
        enum FormatString<'a> {
            Literal(String),
            Command(&'a str, String),
        }
        impl FormatString<'_> {
            fn formatted_string(self) -> String {
                match self {
                    FormatString::Literal(str) | FormatString::Command(_, str) => str,
                }
            }
        }

        let detect_commands = RE_DETECT_NAME_FORMAT_COMMAND.captures_iter(format_string);

        let mut final_string: Vec<FormatString<'b>> = Vec::new();

        let mut current_string_index = 0;
        for capture in detect_commands {
            let match_all = capture.get(0).expect("Capture group 0 should always exist");
            let start = match_all.start();
            let end = match_all.end();

            if start > current_string_index {
                final_string.push(FormatString::Literal(
                    format_string[current_string_index..start].to_string(),
                ));
            }

            // {prefix:cmd}
            // let full_match_string = match_all.as_str();
            // prefix:cmd
            let inner_command_string = capture
                .get(1)
                .expect("Capture group 2 should always exist")
                .as_str();

            let inner_command_capture = RE_COMMAND_SPLIT
                .captures(inner_command_string)
                .expect("Should always match");

            // prefix
            let command_modifier = inner_command_capture.get(2).map_or("", |x| x.as_str());
            // cmd
            let actual_command = inner_command_capture.get(3).map_or("", |x| x.as_str());

            let mut found_command = false;

            for formatter in &self.name_formatters {
                if let Some(matched) = formatter.argument_template().captures(actual_command) {
                    let mut command_substitution = match formatter.replacement_text(matched, info) {
                        Ok(replaced_text) => replaced_text,
                        Err(err) => {
                            return Err(anyhow!("Failed to format the file name with the given format string: {actual_command:?}. Got error: {{{err}}}"));
                        }
                    };

                    if !command_substitution.is_empty() && !command_modifier.is_empty() {
                        // prefix_substitution
                        command_substitution = format!("{command_modifier}{command_substitution}");
                    }
                    found_command = true;
                    final_string.push(FormatString::Command(
                        inner_command_string,
                        command_substitution,
                    ));
                    break;
                }
            }

            if !found_command {
                return Err(anyhow!("Failed to format file name with the given format string. There exists no formatter for the format command: {{{actual_command}}}"));
            }

            current_string_index = end;
        }
        if format_string.len() > current_string_index {
            final_string.push(FormatString::Literal(
                format_string[current_string_index..].to_string(),
            ));
        }

        trace!("Parsed format string {format_string:?} to");
        for part in &final_string {
            match part {
                FormatString::Literal(str) => trace!(" - Literal: {str:?}"),
                FormatString::Command(cmd, str) => trace!(" - Command: {cmd:?}\t{str:?}"),
            }
        }

        Ok(final_string
            .into_iter()
            .map(FormatString::formatted_string)
            .collect::<String>())
    }

    /// Performs the file action specified in the `Analyzer`'s settings on a file.
    ///
    /// # Arguments
    ///
    /// * `path` - A `PathBuf` that represents the path of the file to perform the action on.
    /// * `bracket_info` - The information regarding file bracketing. Can be extracted with the `get_bracketing_info` method.
    ///
    /// # Returns
    ///
    /// * `Result<()>` - Returns `Ok(())` if the file action could be performed successfully, `Err(anyhow::Error)` otherwise.
    ///
    /// # Errors
    ///
    /// This function will return an error if:
    /// * The analysis of the file fails.
    /// * An IO error occurs while analyzing the date
    /// * An IO error occurs while doing the file action
    #[allow(clippy::too_many_lines)]
    pub fn run_file<P: AsRef<Path>>(
        &self,
        path: P,
        bracket_info: &Option<BracketInfo>,
    ) -> Result<()> {
        let path = path.as_ref();
        let valid_ext = self.is_valid_extension(path.extension());
        let is_unknown_file = match valid_ext {
            Ok(false) => {
                if self.settings.unknown_file_format.is_none() {
                    info!(
                        "Skipping file because extension is not in the list: {}",
                        path.display()
                    );
                    return Ok(());
                }
                debug!("Processing unknown file: {}", path.display());
                true
            }
            Ok(true) => {
                debug!("Processing file: {}", path.display());
                false
            }
            Err(err) => {
                warn!("Error checking file extension: {err}");
                return Ok(());
            }
        };

        let (date, cleaned_name) = if is_unknown_file {
            (
                None,
                path.with_extension("")
                    .file_name()
                    .ok_or(anyhow::anyhow!("No file name"))?
                    .to_str()
                    .ok_or(anyhow::anyhow!("Invalid file name"))?
                    .to_string(),
            )
        } else {
            let (date, cleaned_name) = self.analyze(path).map_err(|err| {
                error!("Error extracting date: {err}");
                err
            })?;
            let cleaned_name = name::clean_image_name(cleaned_name.as_str());

            debug!("Analysis results: Date: {date:?}, Cleaned name: {cleaned_name:?}",);

            if date.is_none() {
                warn!("No date was derived for file {}.", path.display());
            }

            (date, cleaned_name)
        };

        let date_string = match date {
            None => "NODATE".to_string(),
            Some(date) => date.format(&self.settings.date_format).to_string(),
        };

        let mut ftype = FileType::None;
        if self.is_valid_photo_extension(path.extension())? {
            ftype = FileType::Image;
        }
        #[cfg(feature = "video")]
        if self.is_valid_video_extension(path.extension())? {
            ftype = FileType::Video;
        }

        let mut file_name_info = NameFormatterInvocationInfo {
            date: &date,
            date_string: &date_string,
            date_default_format: &self.settings.date_format,
            file_type: &ftype,
            cleaned_name: &cleaned_name,
            duplicate_counter: None,
            extension: path
                .extension()
                .map_or(String::new(), |ext| ext.to_string_lossy().to_string()),
            bracket_info: bracket_info.as_ref(),
            original_name: path
                .with_extension("")
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .to_string(),
            original_filename: path
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .to_string(),
        };

        let new_file_path = |file_name_info: &NameFormatterInvocationInfo| -> Result<PathBuf> {
            let format_string = if is_unknown_file {
                self.settings
                    .unknown_file_format
                    .as_ref()
                    .ok_or(anyhow!("No unknown format string specified"))?
                    .as_str()
            } else if let (Some(bracket_info), Some(_)) =
                (&self.settings.bracketed_file_format, &bracket_info)
            {
                bracket_info.as_str()
            } else if date.is_some() {
                self.settings.file_format.as_str()
            } else {
                self.settings.nodate_file_format.as_str()
            };

            let path_split: Vec<_> = format_string
                .split('/')
                .map(|component| self.replace_filepath_parts(component, file_name_info))
                .collect();
            for entry in &path_split {
                if let Err(err) = entry {
                    return Err(anyhow!("Failed to format filename: {err}"));
                }
            }
            let path_split = path_split.into_iter().map(Result::unwrap);

            let mut target_path = self.settings.target_dir.clone();
            for path_component in path_split {
                let component = path_component.replace(['/', '\\'], "");
                if component != ".." {
                    target_path.push(component);
                }
            }
            Ok(target_path)
        };

        let mut new_path = new_file_path(&file_name_info)?;
        let mut dup_counter = 0;

        while new_path.exists() {
            debug!("Target file already exists: {}", new_path.display());
            dup_counter += 1;
            file_name_info.duplicate_counter = Some(dup_counter);
            new_path = new_file_path(&file_name_info)?;
        }

        if dup_counter > 0 {
            info!("De-duplicated target file: {}", new_path.display());
        }

        action::file_action(
            path,
            &new_path,
            &self.settings.action_type,
            self.settings.mkdir,
        )?;
        Ok(())
    }

    fn is_valid_photo_extension(&self, ext: Option<&OsStr>) -> Result<bool> {
        match ext {
            None => Ok(false),
            Some(ext) => {
                let ext = ext
                    .to_str()
                    .ok_or(anyhow::anyhow!("Invalid file extension"))?
                    .to_lowercase();
                Ok(self
                    .settings
                    .extensions
                    .iter()
                    .any(|valid_ext| ext == valid_ext.as_str()))
            }
        }
    }

    #[cfg(feature = "video")]
    fn is_valid_video_extension(&self, ext: Option<&OsStr>) -> Result<bool> {
        match ext {
            None => Ok(false),
            Some(ext) => {
                let ext = ext
                    .to_str()
                    .ok_or(anyhow::anyhow!("Invalid file extension"))?
                    .to_lowercase();
                Ok(self
                    .settings
                    .video_extensions
                    .iter()
                    .any(|valid_ext| ext == valid_ext.as_str()))
            }
        }
    }

    fn is_valid_extension(&self, ext: Option<&OsStr>) -> Result<bool> {
        let valid_photo = self.is_valid_photo_extension(ext)?;
        #[cfg(feature = "video")]
        let valid_video = self.is_valid_video_extension(ext)?;
        #[cfg(not(feature = "video"))]
        let valid_video = false;
        Ok(valid_photo || valid_video)
    }
}

mod exifutils;

#[cfg(test)]
pub mod testing;

pub struct BracketEXIFInformation {
    pub index: u32,
}

/// Finds all files in a source directory and its subdirectories.
///
/// # Arguments
/// * `directory` - The directory to search for files.
/// * `recursive` - A boolean that indicates whether to search subdirectories.
/// * `result` - A mutable reference to a vector of `PathBuf` objects that will hold the results.
///
/// # Errors
/// This function will return an error if:
/// * The directory cannot be read or other IO errors occur.
pub fn find_files_in_source(
    directory: PathBuf,
    recursive: bool,
    result: &mut Vec<PathBuf>,
) -> Result<()> {
    let mut entries = fs::read_dir(directory)?.collect::<Vec<std::io::Result<DirEntry>>>();
    entries.sort_by(|a, b| match (a, b) {
        (Ok(a), Ok(b)) => a.path().cmp(&b.path()),
        (Err(_), Ok(_)) => Ordering::Less,
        (Ok(_), Err(_)) => Ordering::Greater,
        (Err(_), Err(_)) => Ordering::Equal,
    });
    for entry in entries {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            if recursive {
                debug!("Processing subfolder: {}", path.display());
                find_files_in_source(path, recursive, result)?;
            }
        } else {
            trace!("Found file: {}", path.display());
            result.push(path);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::action::{ActionMode, ActualAction};
    use crate::analysis::exif2date::ExifDateType;
    use crate::analysis::filename2date::NaiveFileNameParser;
    use crate::analysis::name_formatters::{
        FormatDate, FormatDuplicate, FormatExtension, FormatFileType, FormatName,
        FormatOriginalFileName, FormatOriginalName,
    };
    use crate::testing::*;
    use chrono::Datelike;
    use std::fs;
    use std::path::PathBuf;

    /// Creates default analyzer settings for testing
    fn default_test_settings(source_dirs: Vec<PathBuf>, target_dir: PathBuf) -> AnalyzerSettings {
        AnalyzerSettings {
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
            extensions: vec![
                "jpg".to_string(),
                "jpeg".to_string(),
                "png".to_string(),
                "cr2".to_string(),
                "cr3".to_string(),
                "nef".to_string(),
                "arw".to_string(),
                "raf".to_string(),
                "orf".to_string(),
                "rw2".to_string(),
                "dng".to_string(),
                "xmp".to_string(),
            ],
            #[cfg(feature = "video")]
            video_extensions: vec![
                "mp4".to_string(),
                "mov".to_string(),
                "avi".to_string(),
                "mkv".to_string(),
                "webm".to_string(),
            ],
            action_type: ActionMode::Execute(ActualAction::Copy),
            mkdir: true,
        }
    }

    /// Creates a standard analyzer with common settings for testing
    fn create_analyzer(
        source_dirs: Vec<PathBuf>,
        target_dir: PathBuf,
        analysis_type: AnalysisType,
        action_mode: ActionMode,
    ) -> Analyzer {
        let mut settings = default_test_settings(source_dirs, target_dir);
        settings.analysis_type = analysis_type;
        settings.action_type = action_mode;

        let mut analyzer = Analyzer::new(settings).expect("Failed to create analyzer");

        // Add standard transformers and formatters
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

    // ============================================================================
    // EXIF-based sorting tests
    // ============================================================================

    #[test]
    fn test_sort_jpeg_with_exif_date() {
        // Arrange
        let (_temp_dir, source_dir, target_dir) = setup_test_dirs().unwrap();
        let datetime = get_datetime(2024, 6, 15, 14, 30, 45);
        let source_file = TestImageBuilder::new()
            .jpeg()
            .with_exif_datetime(datetime)
            .with_directory(&source_dir)
            .with_filename("photo.jpg")
            .build()
            .unwrap();
        let analyzer = create_analyzer(
            vec![source_dir],
            target_dir.clone(),
            AnalysisType::OnlyExif,
            ActionMode::Execute(ActualAction::Copy),
        );

        // Act
        analyzer.run_file(&source_file, &None).unwrap();

        // Assert
        let expected_path = target_dir.join("2024/06/IMG_20240615-143045-photo.jpg");
        assert!(
            expected_path.exists(),
            "Expected file at: {}",
            expected_path.display()
        );
    }

    #[test]
    fn test_sort_multiple_jpegs_with_different_exif_dates() {
        // Arrange
        let (_temp_dir, source_dir, target_dir) = setup_test_dirs().unwrap();
        let dates = [
            (get_datetime(2023, 1, 15, 10, 0, 0), "photo1.jpg"),
            (get_datetime(2023, 6, 20, 15, 30, 0), "photo2.jpg"),
            (get_datetime(2024, 12, 25, 18, 0, 0), "photo3.jpg"),
        ];
        for (datetime, filename) in &dates {
            TestImageBuilder::new()
                .jpeg()
                .with_exif_datetime(*datetime)
                .with_directory(&source_dir)
                .with_filename(filename)
                .build()
                .unwrap();
        }
        let analyzer = create_analyzer(
            vec![source_dir.clone()],
            target_dir.clone(),
            AnalysisType::OnlyExif,
            ActionMode::Execute(ActualAction::Copy),
        );

        // Act
        let mut files = Vec::new();
        find_files_in_source(source_dir, false, &mut files).unwrap();
        for file in files {
            analyzer.run_file(&file, &None).unwrap();
        }

        // Assert
        assert!(target_dir
            .join("2023/01/IMG_20230115-100000-photo1.jpg")
            .exists());
        assert!(target_dir
            .join("2023/06/IMG_20230620-153000-photo2.jpg")
            .exists());
        assert!(target_dir
            .join("2024/12/IMG_20241225-180000-photo3.jpg")
            .exists());
    }

    #[test]
    fn test_exif_date_types() {
        // Arrange
        let (_temp_dir, source_dir, target_dir) = setup_test_dirs().unwrap();
        let datetime = get_datetime(2024, 3, 10, 12, 0, 0);
        let source_file = TestImageBuilder::new()
            .jpeg()
            .with_exif_datetime(datetime)
            .with_directory(&source_dir)
            .with_filename("test_creation.jpg")
            .build()
            .unwrap();
        let settings = AnalyzerSettings {
            analysis_type: AnalysisType::OnlyExif,
            exif_date_type: ExifDateType::Creation,
            source_dirs: vec![source_dir],
            target_dir: target_dir.clone(),
            recursive_source: false,
            file_format: "{date}.{ext?lower}".to_string(),
            nodate_file_format: "nodate/{name}.{ext?lower}".to_string(),
            unknown_file_format: None,
            bracketed_file_format: None,
            date_format: "%Y%m%d".to_string(),
            extensions: vec!["jpg".to_string()],
            #[cfg(feature = "video")]
            video_extensions: vec![],
            action_type: ActionMode::Execute(ActualAction::Copy),
            mkdir: true,
        };
        let mut analyzer = Analyzer::new(settings).unwrap();
        analyzer.add_transformer(NaiveFileNameParser::default());
        analyzer.add_formatter(FormatDate::default());
        analyzer.add_formatter(FormatName::default());
        analyzer.add_formatter(FormatDuplicate::default());
        analyzer.add_formatter(FormatExtension::default());

        // Act
        analyzer.run_file(&source_file, &None).unwrap();

        // Assert
        assert!(target_dir.join("20240310.jpg").exists());
    }

    // ============================================================================
    // Filename-based sorting tests
    // ============================================================================

    #[test]
    fn test_sort_by_filename_date() {
        // Arrange
        let (_temp_dir, source_dir, target_dir) = setup_test_dirs().unwrap();
        let source_file = TestImageBuilder::new()
            .jpeg()
            .with_directory(&source_dir)
            .with_filename("20240815_143022_vacation.jpg")
            .build()
            .unwrap();
        let analyzer = create_analyzer(
            vec![source_dir],
            target_dir.clone(),
            AnalysisType::OnlyName,
            ActionMode::Execute(ActualAction::Copy),
        );

        // Act
        analyzer.run_file(&source_file, &None).unwrap();

        // Assert
        let expected_path = target_dir.join("2024/08/IMG_20240815-143022-vacation.jpg");
        assert!(
            expected_path.exists(),
            "Expected file at: {}",
            expected_path.display()
        );
    }

    #[test]
    fn test_filename_date_formats() {
        // Arrange
        let (_temp_dir, source_dir, target_dir) = setup_test_dirs().unwrap();
        let filenames = [
            "2024-01-15-photo.jpg",
            "2024_02_20_trip.jpg",
            "20240315_sunset.jpg",
            "2024-04-10_12-30-45_event.jpg",
            "IMG_20240505_183000.jpg",
        ];
        for filename in &filenames {
            TestImageBuilder::new()
                .jpeg()
                .with_directory(&source_dir)
                .with_filename(filename)
                .build()
                .unwrap();
        }
        let analyzer = create_analyzer(
            vec![source_dir.clone()],
            target_dir.clone(),
            AnalysisType::OnlyName,
            ActionMode::Execute(ActualAction::Copy),
        );

        // Act
        let mut files = Vec::new();
        find_files_in_source(source_dir, false, &mut files).unwrap();
        for file in files {
            analyzer.run_file(&file, &None).unwrap();
        }

        // Assert
        assert!(target_dir.join("2024/01").exists());
        assert!(target_dir.join("2024/02").exists());
        assert!(target_dir.join("2024/03").exists());
        assert!(target_dir.join("2024/04").exists());
        assert!(target_dir.join("2024/05").exists());
    }

    #[test]
    fn test_raw_file_filename_sorting() {
        // Arrange
        let (_temp_dir, source_dir, target_dir) = setup_test_dirs().unwrap();
        let raw_files = [
            ("20240101_120000_DSC0001.cr2", "2024/01"),
            ("2024-02-15_landscape.nef", "2024/02"),
            ("20240320-091500.arw", "2024/03"),
            ("2024_04_25_portrait.dng", "2024/04"),
        ];
        for (filename, _) in &raw_files {
            TestFileBuilder::new()
                .raw()
                .with_directory(&source_dir)
                .with_filename(filename)
                .build()
                .unwrap();
        }
        let analyzer = create_analyzer(
            vec![source_dir.clone()],
            target_dir.clone(),
            AnalysisType::OnlyName,
            ActionMode::Execute(ActualAction::Copy),
        );

        // Act
        let mut files = Vec::new();
        find_files_in_source(source_dir, false, &mut files).unwrap();
        for file in files {
            analyzer.run_file(&file, &None).unwrap();
        }

        // Assert
        for (_, expected_dir) in &raw_files {
            let dir_path = target_dir.join(expected_dir);
            assert!(
                dir_path.exists(),
                "Expected directory: {}",
                dir_path.display()
            );
            assert!(
                fs::read_dir(&dir_path).unwrap().count() > 0,
                "Directory should not be empty: {}",
                dir_path.display()
            );
        }
    }

    #[test]
    fn test_additional_raw_formats() {
        // Arrange - test the newly added RAW formats: cr3, raf, orf, rw2
        let (_temp_dir, source_dir, target_dir) = setup_test_dirs().unwrap();
        let raw_files = [
            ("20240501_canon_r5.cr3", "2024/05"),
            ("20240602_fuji_xt5.raf", "2024/06"),
            ("20240703_olympus.orf", "2024/07"),
            ("20240804_panasonic.rw2", "2024/08"),
        ];
        for (filename, _) in &raw_files {
            TestFileBuilder::new()
                .raw()
                .with_directory(&source_dir)
                .with_filename(filename)
                .build()
                .unwrap();
        }
        let analyzer = create_analyzer(
            vec![source_dir.clone()],
            target_dir.clone(),
            AnalysisType::OnlyName,
            ActionMode::Execute(ActualAction::Copy),
        );

        // Act
        let mut files = Vec::new();
        find_files_in_source(source_dir, false, &mut files).unwrap();
        for file in files {
            analyzer.run_file(&file, &None).unwrap();
        }

        // Assert
        for (_, expected_dir) in &raw_files {
            let dir_path = target_dir.join(expected_dir);
            assert!(
                dir_path.exists(),
                "Expected directory: {}",
                dir_path.display()
            );
        }
    }

    #[test]
    fn test_xmp_sidecar_file_handling() {
        // Arrange - XMP sidecar files should be processed
        let (_temp_dir, source_dir, target_dir) = setup_test_dirs().unwrap();
        TestFileBuilder::new()
            .raw()
            .with_directory(&source_dir)
            .with_filename("20240915_photo.xmp")
            .with_content(b"<?xml version=\"1.0\"?><x:xmpmeta></x:xmpmeta>")
            .build()
            .unwrap();
        let analyzer = create_analyzer(
            vec![source_dir.clone()],
            target_dir.clone(),
            AnalysisType::OnlyName,
            ActionMode::Execute(ActualAction::Copy),
        );

        // Act
        let mut files = Vec::new();
        find_files_in_source(source_dir, false, &mut files).unwrap();
        for file in files {
            analyzer.run_file(&file, &None).unwrap();
        }

        // Assert
        let expected_dir = target_dir.join("2024/09");
        assert!(
            expected_dir.exists(),
            "XMP file should be sorted to {}",
            expected_dir.display()
        );
        let has_xmp = fs::read_dir(&expected_dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .any(|f| f.path().extension().is_some_and(|e| e == "xmp"));
        assert!(has_xmp, "Directory should contain the .xmp file");
    }

    // ============================================================================
    // Fallback behavior tests
    // ============================================================================

    #[test]
    fn test_exif_then_name_fallback() {
        // Arrange
        let (_temp_dir, source_dir, target_dir) = setup_test_dirs().unwrap();
        let exif_date = get_datetime(2024, 7, 4, 10, 0, 0);
        let with_exif = TestImageBuilder::new()
            .jpeg()
            .with_exif_datetime(exif_date)
            .with_directory(&source_dir)
            .with_filename("with_exif.jpg")
            .build()
            .unwrap();
        let without_exif = TestImageBuilder::new()
            .jpeg()
            .with_directory(&source_dir)
            .with_filename("20240815_no_exif.jpg")
            .build()
            .unwrap();
        let analyzer = create_analyzer(
            vec![source_dir],
            target_dir.clone(),
            AnalysisType::ExifThenName,
            ActionMode::Execute(ActualAction::Copy),
        );

        // Act
        analyzer.run_file(&with_exif, &None).unwrap();
        analyzer.run_file(&without_exif, &None).unwrap();

        // Assert
        assert!(target_dir.join("2024/07").exists()); // EXIF file in July
        assert!(target_dir.join("2024/08").exists()); // Filename-based file in August
    }

    #[test]
    fn test_name_then_exif_fallback() {
        // Arrange
        let (_temp_dir, source_dir, target_dir) = setup_test_dirs().unwrap();
        let exif_date = get_datetime(2024, 1, 1, 0, 0, 0);
        let both = TestImageBuilder::new()
            .jpeg()
            .with_exif_datetime(exif_date)
            .with_directory(&source_dir)
            .with_filename("20240615_has_both.jpg")
            .build()
            .unwrap();
        let exif_only_date = get_datetime(2024, 9, 1, 12, 0, 0);
        let exif_only = TestImageBuilder::new()
            .jpeg()
            .with_exif_datetime(exif_only_date)
            .with_directory(&source_dir)
            .with_filename("no_date_in_name.jpg")
            .build()
            .unwrap();
        let analyzer = create_analyzer(
            vec![source_dir],
            target_dir.clone(),
            AnalysisType::NameThenExif,
            ActionMode::Execute(ActualAction::Copy),
        );

        // Act
        analyzer.run_file(&both, &None).unwrap();
        analyzer.run_file(&exif_only, &None).unwrap();

        // Assert
        assert!(target_dir.join("2024/06").exists()); // Filename date (June)
        assert!(target_dir.join("2024/09").exists()); // EXIF date (September)
    }

    #[test]
    fn test_no_date_handling() {
        // Arrange
        let (_temp_dir, source_dir, target_dir) = setup_test_dirs().unwrap();
        let no_date_file = TestImageBuilder::new()
            .jpeg()
            .with_directory(&source_dir)
            .with_filename("random_photo.jpg")
            .build()
            .unwrap();
        let analyzer = create_analyzer(
            vec![source_dir],
            target_dir.clone(),
            AnalysisType::ExifThenName,
            ActionMode::Execute(ActualAction::Copy),
        );

        // Act
        analyzer.run_file(&no_date_file, &None).unwrap();

        // Assert
        let nodate_dir = target_dir.join("nodate");
        assert!(nodate_dir.exists(), "nodate directory should exist");
        assert!(
            fs::read_dir(&nodate_dir).unwrap().count() > 0,
            "nodate directory should contain the file"
        );
    }

    // ============================================================================
    // AnalysisType parsing tests
    // ============================================================================

    #[test]
    fn test_analysis_type_from_str_fs_fallback_modes() {
        // Test parsing of the new fs fallback analysis modes
        assert_eq!(
            AnalysisType::from_str("exif_then_name_then_fs").unwrap(),
            AnalysisType::ExifThenNameThenFs
        );
        assert_eq!(
            AnalysisType::from_str("exif_name_fs").unwrap(),
            AnalysisType::ExifThenNameThenFs
        );
        assert_eq!(
            AnalysisType::from_str("name_then_exif_then_fs").unwrap(),
            AnalysisType::NameThenExifThenFs
        );
        assert_eq!(
            AnalysisType::from_str("name_exif_fs").unwrap(),
            AnalysisType::NameThenExifThenFs
        );
        // Test case insensitivity
        assert_eq!(
            AnalysisType::from_str("EXIF_THEN_NAME_THEN_FS").unwrap(),
            AnalysisType::ExifThenNameThenFs
        );
    }

    // ============================================================================
    // Filesystem date fallback tests
    // ============================================================================

    #[test]
    fn test_exif_then_name_then_fs_uses_filesystem_date() {
        // Arrange - file with no EXIF and no date in filename should fall back to fs date
        let (_temp_dir, source_dir, target_dir) = setup_test_dirs().unwrap();
        let no_date_file = TestImageBuilder::new()
            .jpeg()
            .with_directory(&source_dir)
            .with_filename("random_photo.jpg")
            .build()
            .unwrap();
        let analyzer = create_analyzer(
            vec![source_dir],
            target_dir.clone(),
            AnalysisType::ExifThenNameThenFs,
            ActionMode::Execute(ActualAction::Copy),
        );

        // Act
        analyzer.run_file(&no_date_file, &None).unwrap();

        // Assert - file should NOT be in nodate folder since fs date is used
        let nodate_dir = target_dir.join("nodate");
        let nodate_has_files = nodate_dir.exists()
            && fs::read_dir(&nodate_dir)
                .map(|rd| rd.count() > 0)
                .unwrap_or(false);
        assert!(
            !nodate_has_files,
            "File should be sorted by filesystem date, not placed in nodate"
        );
    }

    #[test]
    fn test_name_then_exif_then_fs_uses_filesystem_date() {
        // Arrange - file with no date in filename and no EXIF should fall back to fs date
        // Use PNG since it doesn't have EXIF, avoiding the EXIF parsing error
        let (_temp_dir, source_dir, target_dir) = setup_test_dirs().unwrap();
        let no_date_file = TestImageBuilder::new()
            .png()
            .with_directory(&source_dir)
            .with_filename("screenshot.png")
            .build()
            .unwrap();
        let analyzer = create_analyzer(
            vec![source_dir],
            target_dir.clone(),
            AnalysisType::NameThenExifThenFs,
            ActionMode::Execute(ActualAction::Copy),
        );

        // Act
        analyzer.run_file(&no_date_file, &None).unwrap();

        // Assert - file should NOT be in nodate folder since fs date is used
        let nodate_dir = target_dir.join("nodate");
        let nodate_has_files = nodate_dir.exists()
            && fs::read_dir(&nodate_dir)
                .map(|rd| rd.count() > 0)
                .unwrap_or(false);
        assert!(
            !nodate_has_files,
            "File should be sorted by filesystem date, not placed in nodate"
        );
    }

    #[test]
    fn test_exif_then_name_then_fs_prefers_exif() {
        // Arrange - file with EXIF date should use EXIF, not fall back to fs
        let (_temp_dir, source_dir, target_dir) = setup_test_dirs().unwrap();
        let exif_date = get_datetime(2024, 3, 15, 10, 30, 0);
        let with_exif = TestImageBuilder::new()
            .jpeg()
            .with_exif_datetime(exif_date)
            .with_directory(&source_dir)
            .with_filename("photo.jpg")
            .build()
            .unwrap();
        let analyzer = create_analyzer(
            vec![source_dir],
            target_dir.clone(),
            AnalysisType::ExifThenNameThenFs,
            ActionMode::Execute(ActualAction::Copy),
        );

        // Act
        analyzer.run_file(&with_exif, &None).unwrap();

        // Assert - should be sorted by EXIF date (March 2024)
        assert!(
            target_dir.join("2024/03").exists(),
            "File should be sorted by EXIF date to 2024/03"
        );
    }

    #[test]
    fn test_name_then_exif_then_fs_prefers_name() {
        // Arrange - file with date in filename should use that, not fall back
        let (_temp_dir, source_dir, target_dir) = setup_test_dirs().unwrap();
        let source_file = TestImageBuilder::new()
            .jpeg()
            .with_directory(&source_dir)
            .with_filename("20241225_christmas.jpg")
            .build()
            .unwrap();
        let analyzer = create_analyzer(
            vec![source_dir],
            target_dir.clone(),
            AnalysisType::NameThenExifThenFs,
            ActionMode::Execute(ActualAction::Copy),
        );

        // Act
        analyzer.run_file(&source_file, &None).unwrap();

        // Assert - should be sorted by filename date (December 2024)
        assert!(
            target_dir.join("2024/12").exists(),
            "File should be sorted by filename date to 2024/12"
        );
    }

    // ============================================================================
    // Deduplication tests
    // ============================================================================

    #[test]
    fn test_duplicate_handling() {
        // Arrange
        let (_temp_dir, source_dir, target_dir) = setup_test_dirs().unwrap();
        let datetime = get_datetime(2024, 5, 1, 9, 0, 0);
        for i in 1..=3 {
            TestImageBuilder::new()
                .jpeg()
                .with_exif_datetime(datetime)
                .with_directory(&source_dir)
                .with_filename(&format!("photo{i}.jpg"))
                .build()
                .unwrap();
        }
        let analyzer = create_analyzer(
            vec![source_dir.clone()],
            target_dir.clone(),
            AnalysisType::OnlyExif,
            ActionMode::Execute(ActualAction::Copy),
        );

        // Act
        let mut files = Vec::new();
        find_files_in_source(source_dir, false, &mut files).unwrap();
        for file in files {
            analyzer.run_file(&file, &None).unwrap();
        }

        // Assert
        let target_month_dir = target_dir.join("2024/05");
        let file_count = fs::read_dir(&target_month_dir)
            .unwrap()
            .filter(|e| e.is_ok())
            .count();
        assert_eq!(
            file_count, 3,
            "All 3 files should be present with deduplication"
        );
    }

    // ============================================================================
    // Recursive directory tests
    // ============================================================================

    #[test]
    fn test_recursive_source_directory() {
        // Arrange
        let (_temp_dir, source_dir, target_dir) = setup_test_dirs().unwrap();
        let subdir1 = source_dir.join("vacation/2024");
        let subdir2 = source_dir.join("work/meetings");
        fs::create_dir_all(&subdir1).unwrap();
        fs::create_dir_all(&subdir2).unwrap();
        let date1 = get_datetime(2024, 7, 15, 10, 0, 0);
        let date2 = get_datetime(2024, 8, 20, 14, 0, 0);
        let date3 = get_datetime(2024, 9, 5, 9, 0, 0);
        TestImageBuilder::new()
            .jpeg()
            .with_exif_datetime(date1)
            .with_directory(&source_dir)
            .with_filename("root_photo.jpg")
            .build()
            .unwrap();
        TestImageBuilder::new()
            .jpeg()
            .with_exif_datetime(date2)
            .with_directory(&subdir1)
            .with_filename("vacation_photo.jpg")
            .build()
            .unwrap();
        TestImageBuilder::new()
            .jpeg()
            .with_exif_datetime(date3)
            .with_directory(&subdir2)
            .with_filename("meeting_photo.jpg")
            .build()
            .unwrap();
        let analyzer = create_analyzer(
            vec![source_dir.clone()],
            target_dir.clone(),
            AnalysisType::OnlyExif,
            ActionMode::Execute(ActualAction::Copy),
        );

        // Act
        let mut files = Vec::new();
        find_files_in_source(source_dir, true, &mut files).unwrap();
        assert_eq!(files.len(), 3, "Should find 3 files recursively");
        for file in files {
            analyzer.run_file(&file, &None).unwrap();
        }

        // Assert
        assert!(target_dir.join("2024/07").exists());
        assert!(target_dir.join("2024/08").exists());
        assert!(target_dir.join("2024/09").exists());
    }

    // ============================================================================
    // Format string tests
    // ============================================================================

    #[test]
    fn test_custom_format_string() {
        // Arrange
        let (_temp_dir, source_dir, target_dir) = setup_test_dirs().unwrap();
        let datetime = get_datetime(2024, 11, 22, 16, 45, 30);
        let source_file = TestImageBuilder::new()
            .jpeg()
            .with_exif_datetime(datetime)
            .with_directory(&source_dir)
            .with_filename("original_name.jpg")
            .build()
            .unwrap();
        let settings = AnalyzerSettings {
            analysis_type: AnalysisType::OnlyExif,
            exif_date_type: ExifDateType::Creation,
            source_dirs: vec![source_dir],
            target_dir: target_dir.clone(),
            recursive_source: false,
            file_format: "{date?%Y-%m-%d}/{original_filename}".to_string(),
            nodate_file_format: "unsorted/{original_filename}".to_string(),
            unknown_file_format: None,
            bracketed_file_format: None,
            date_format: "%Y%m%d-%H%M%S".to_string(),
            extensions: vec!["jpg".to_string()],
            #[cfg(feature = "video")]
            video_extensions: vec![],
            action_type: ActionMode::Execute(ActualAction::Copy),
            mkdir: true,
        };
        let mut analyzer = Analyzer::new(settings).unwrap();
        analyzer.add_transformer(NaiveFileNameParser::default());
        analyzer.add_formatter(FormatDate::default());
        analyzer.add_formatter(FormatName::default());
        analyzer.add_formatter(FormatDuplicate::default());
        analyzer.add_formatter(FormatExtension::default());
        analyzer.add_formatter(FormatOriginalName::default());
        analyzer.add_formatter(FormatOriginalFileName::default());

        // Act
        analyzer.run_file(&source_file, &None).unwrap();

        // Assert
        let expected_path = target_dir.join("2024-11-22/original_name.jpg");
        assert!(
            expected_path.exists(),
            "Expected file at: {}",
            expected_path.display()
        );
    }

    #[test]
    fn test_extension_case_handling() {
        // Arrange
        let (_temp_dir, source_dir, target_dir) = setup_test_dirs().unwrap();
        let datetime = get_datetime(2024, 1, 1, 12, 0, 0);
        let source_file = TestImageBuilder::new()
            .jpeg()
            .with_exif_datetime(datetime)
            .with_directory(&source_dir)
            .with_filename("photo.JPG")
            .build()
            .unwrap();
        let settings = AnalyzerSettings {
            analysis_type: AnalysisType::OnlyExif,
            exif_date_type: ExifDateType::Creation,
            source_dirs: vec![source_dir.clone()],
            target_dir: target_dir.clone(),
            recursive_source: false,
            file_format: "{date}.{ext?lower}".to_string(),
            nodate_file_format: "nodate/{name}.{ext?lower}".to_string(),
            unknown_file_format: None,
            bracketed_file_format: None,
            date_format: "%Y%m%d".to_string(),
            extensions: vec!["jpg".to_string(), "jpeg".to_string()],
            #[cfg(feature = "video")]
            video_extensions: vec![],
            action_type: ActionMode::Execute(ActualAction::Copy),
            mkdir: true,
        };
        let mut analyzer = Analyzer::new(settings).unwrap();
        analyzer.add_transformer(NaiveFileNameParser::default());
        analyzer.add_formatter(FormatDate::default());
        analyzer.add_formatter(FormatName::default());
        analyzer.add_formatter(FormatDuplicate::default());
        analyzer.add_formatter(FormatExtension::default());

        // Act
        analyzer.run_file(&source_file, &None).unwrap();

        // Assert
        assert!(target_dir.join("20240101.jpg").exists());
    }

    // ============================================================================
    // Multiple source directories tests
    // ============================================================================

    #[test]
    fn test_multiple_source_directories() {
        // Arrange
        let (_temp_dir, source_dir, target_dir) = setup_test_dirs().unwrap();
        let source1 = source_dir.join("camera1");
        let source2 = source_dir.join("camera2");
        fs::create_dir_all(&source1).unwrap();
        fs::create_dir_all(&source2).unwrap();
        let date1 = get_datetime(2024, 3, 15, 10, 0, 0);
        let date2 = get_datetime(2024, 4, 20, 14, 0, 0);
        TestImageBuilder::new()
            .jpeg()
            .with_exif_datetime(date1)
            .with_directory(&source1)
            .with_filename("cam1_photo.jpg")
            .build()
            .unwrap();
        TestImageBuilder::new()
            .jpeg()
            .with_exif_datetime(date2)
            .with_directory(&source2)
            .with_filename("cam2_photo.jpg")
            .build()
            .unwrap();
        let analyzer = create_analyzer(
            vec![source1.clone(), source2.clone()],
            target_dir.clone(),
            AnalysisType::OnlyExif,
            ActionMode::Execute(ActualAction::Copy),
        );

        // Act
        for source in [source1, source2] {
            let mut files = Vec::new();
            find_files_in_source(source, false, &mut files).unwrap();
            for file in files {
                analyzer.run_file(&file, &None).unwrap();
            }
        }

        // Assert
        assert!(target_dir.join("2024/03").exists());
        assert!(target_dir.join("2024/04").exists());
    }

    // ============================================================================
    // Edge case tests
    // ============================================================================

    #[test]
    fn test_file_with_spaces_in_name() {
        // Arrange
        let (_temp_dir, source_dir, target_dir) = setup_test_dirs().unwrap();
        let datetime = get_datetime(2024, 6, 1, 12, 0, 0);
        let source_file = TestImageBuilder::new()
            .jpeg()
            .with_exif_datetime(datetime)
            .with_directory(&source_dir)
            .with_filename("my vacation photo 2024.jpg")
            .build()
            .unwrap();
        let analyzer = create_analyzer(
            vec![source_dir],
            target_dir.clone(),
            AnalysisType::OnlyExif,
            ActionMode::Execute(ActualAction::Copy),
        );

        // Act
        analyzer.run_file(&source_file, &None).unwrap();

        // Assert
        assert!(target_dir.join("2024/06").exists());
        let dir_contents: Vec<_> = fs::read_dir(target_dir.join("2024/06"))
            .unwrap()
            .filter_map(|e| e.ok())
            .collect();
        assert_eq!(dir_contents.len(), 1);
    }

    #[test]
    fn test_file_with_special_characters() {
        // Arrange
        let (_temp_dir, source_dir, target_dir) = setup_test_dirs().unwrap();
        let datetime = get_datetime(2024, 6, 1, 12, 0, 0);
        let source_file = TestImageBuilder::new()
            .jpeg()
            .with_exif_datetime(datetime)
            .with_directory(&source_dir)
            .with_filename("photo_with-special.chars.jpg")
            .build()
            .unwrap();
        let analyzer = create_analyzer(
            vec![source_dir],
            target_dir.clone(),
            AnalysisType::OnlyExif,
            ActionMode::Execute(ActualAction::Copy),
        );

        // Act
        analyzer.run_file(&source_file, &None).unwrap();

        // Assert
        assert!(target_dir.join("2024/06").exists());
    }

    #[test]
    fn test_png_file_sorting() {
        // Arrange
        let (_temp_dir, source_dir, target_dir) = setup_test_dirs().unwrap();
        let source_file = TestImageBuilder::new()
            .png()
            .with_directory(&source_dir)
            .with_filename("20240401_screenshot.png")
            .build()
            .unwrap();
        let analyzer = create_analyzer(
            vec![source_dir],
            target_dir.clone(),
            AnalysisType::OnlyName,
            ActionMode::Execute(ActualAction::Copy),
        );

        // Act
        analyzer.run_file(&source_file, &None).unwrap();

        // Assert
        assert!(target_dir.join("2024/04").exists());
    }

    // ============================================================================
    // Analysis result tests
    // ============================================================================

    #[test]
    fn test_analyze_returns_correct_date_and_name() {
        let (_temp_dir, source_dir, target_dir) = setup_test_dirs().unwrap();

        let datetime = get_datetime(2024, 8, 15, 14, 30, 0);
        let source_file = TestImageBuilder::new()
            .jpeg()
            .with_exif_datetime(datetime)
            .with_directory(&source_dir)
            .with_filename("IMG_vacation_photo.jpg")
            .build()
            .unwrap();

        let analyzer = create_analyzer(
            vec![source_dir],
            target_dir,
            AnalysisType::OnlyExif,
            ActionMode::Execute(ActualAction::Copy),
        );

        let (date, name) = analyzer.analyze(&source_file).unwrap();

        assert!(date.is_some());
        let extracted_date = date.unwrap();
        assert_eq!(extracted_date.date().year(), 2024);
        assert_eq!(extracted_date.date().month(), 8);
        assert_eq!(extracted_date.date().day(), 15);

        // Name should be cleaned (IMG prefix removed, extension removed)
        assert!(name.contains("vacation") || name.contains("photo"));
    }

    #[test]
    fn test_analyze_filename_date_extraction() {
        let (_temp_dir, source_dir, target_dir) = setup_test_dirs().unwrap();

        let source_file = TestImageBuilder::new()
            .jpeg()
            .with_directory(&source_dir)
            .with_filename("20231225_christmas.jpg")
            .build()
            .unwrap();

        let analyzer = create_analyzer(
            vec![source_dir],
            target_dir,
            AnalysisType::OnlyName,
            ActionMode::Execute(ActualAction::Copy),
        );

        let (date, name) = analyzer.analyze(&source_file).unwrap();

        assert!(date.is_some());
        let extracted_date = date.unwrap();
        assert_eq!(extracted_date.date().year(), 2023);
        assert_eq!(extracted_date.date().month(), 12);
        assert_eq!(extracted_date.date().day(), 25);

        // Name should have the date part removed
        assert!(name.contains("christmas"));
        assert!(!name.contains("20231225"));
    }

    // ============================================================================
    // Video file tests (only when video feature is enabled)
    // ============================================================================

    #[cfg(feature = "video")]
    mod video_tests {
        use super::*;

        #[test]
        fn test_video_file_sorting_by_filename() {
            let (_temp_dir, source_dir, target_dir) = setup_test_dirs().unwrap();

            // Create fake video files with dates in filenames
            let video_files = [
                "20240101_120000_new_year.mp4",
                "2024-02-14_valentine.mov",
                "20240704_fireworks.avi",
            ];

            for filename in &video_files {
                TestFileBuilder::new()
                    .video()
                    .with_directory(&source_dir)
                    .with_filename(filename)
                    .build()
                    .unwrap();
            }

            let analyzer = create_analyzer(
                vec![source_dir.clone()],
                target_dir.clone(),
                AnalysisType::OnlyName,
                ActionMode::Execute(ActualAction::Copy),
            );

            let mut files = Vec::new();
            find_files_in_source(source_dir, false, &mut files).unwrap();
            for file in files {
                analyzer.run_file(&file, &None).unwrap();
            }

            // Verify video files are sorted correctly
            assert!(target_dir.join("2024/01").exists());
            assert!(target_dir.join("2024/02").exists());
            assert!(target_dir.join("2024/07").exists());
        }

        #[test]
        fn test_mkv_webm_video_sorting() {
            // Arrange - test the newly added video formats: mkv, webm
            let (_temp_dir, source_dir, target_dir) = setup_test_dirs().unwrap();
            let video_files = [
                ("20240810_screen_recording.mkv", "2024/08"),
                ("20240920_webinar.webm", "2024/09"),
            ];

            for (filename, _) in &video_files {
                TestFileBuilder::new()
                    .video()
                    .with_directory(&source_dir)
                    .with_filename(filename)
                    .build()
                    .unwrap();
            }

            let analyzer = create_analyzer(
                vec![source_dir.clone()],
                target_dir.clone(),
                AnalysisType::OnlyName,
                ActionMode::Execute(ActualAction::Copy),
            );

            // Act
            let mut files = Vec::new();
            find_files_in_source(source_dir, false, &mut files).unwrap();
            for file in files {
                analyzer.run_file(&file, &None).unwrap();
            }

            // Assert
            for (_, expected_dir) in &video_files {
                let dir_path = target_dir.join(expected_dir);
                assert!(
                    dir_path.exists(),
                    "Expected directory: {}",
                    dir_path.display()
                );
            }
        }
    }

    // ============================================================================
    // Error handling tests
    // ============================================================================

    #[test]
    fn test_invalid_source_directory() {
        let target_dir = tempfile::TempDir::new().unwrap();

        let settings = AnalyzerSettings {
            analysis_type: AnalysisType::OnlyExif,
            exif_date_type: ExifDateType::Creation,
            source_dirs: vec![PathBuf::from("/nonexistent/directory")],
            target_dir: target_dir.path().to_path_buf(),
            recursive_source: false,
            file_format: "{date}.{ext}".to_string(),
            nodate_file_format: "nodate/{name}.{ext}".to_string(),
            unknown_file_format: None,
            bracketed_file_format: None,
            date_format: "%Y%m%d".to_string(),
            extensions: vec!["jpg".to_string()],
            #[cfg(feature = "video")]
            video_extensions: vec![],
            action_type: ActionMode::Execute(ActualAction::Copy),
            mkdir: true,
        };

        let result = Analyzer::new(settings);
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_target_directory() {
        let source_dir = tempfile::TempDir::new().unwrap();

        let settings = AnalyzerSettings {
            analysis_type: AnalysisType::OnlyExif,
            exif_date_type: ExifDateType::Creation,
            source_dirs: vec![source_dir.path().to_path_buf()],
            target_dir: PathBuf::from("/nonexistent/target"),
            recursive_source: false,
            file_format: "{date}.{ext}".to_string(),
            nodate_file_format: "nodate/{name}.{ext}".to_string(),
            unknown_file_format: None,
            bracketed_file_format: None,
            date_format: "%Y%m%d".to_string(),
            extensions: vec!["jpg".to_string()],
            #[cfg(feature = "video")]
            video_extensions: vec![],
            action_type: ActionMode::Execute(ActualAction::Copy),
            mkdir: true,
        };

        let result = Analyzer::new(settings);
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_extension_handling() {
        let (_temp_dir, source_dir, target_dir) = setup_test_dirs().unwrap();

        // Create a file with an extension not in the list
        let source_file = source_dir.join("document.pdf");
        fs::write(&source_file, b"PDF content").unwrap();

        let analyzer = create_analyzer(
            vec![source_dir],
            target_dir.clone(),
            AnalysisType::OnlyExif,
            ActionMode::Execute(ActualAction::Copy),
        );

        // This should not create any files (extension not valid)
        let result = analyzer.run_file(&source_file, &None);
        assert!(result.is_ok()); // Should succeed but skip the file

        // Target should be empty (no files copied)
        let has_files = fs::read_dir(&target_dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .any(|e| e.path().is_file());
        assert!(
            !has_files,
            "No files should be copied for invalid extension"
        );
    }
}
