use std::error::Error;
use std::fmt;
use std::io;
use std::path::{Path, PathBuf};

use miette::Diagnostic;

/// An error while reading or parsing a named configuration file.
///
/// The parse variant retains the parser's [`miette::Diagnostic`] source and
/// filename, so converting a file-backed parse into a report does not lose
/// the snippet that made the error useful. The wrapper forwards the parser's
/// diagnostic fields rather than rendering the parser as a second cause.
#[derive(Debug)]
pub enum FileError<E> {
    /// The file could not be read.
    Read { path: PathBuf, source: io::Error },
    /// The file was read but its contents were invalid.
    Parse { path: PathBuf, source: E },
}

impl<E> FileError<E> {
    /// Return the path associated with the failure.
    pub fn path(&self) -> &Path {
        match self {
            Self::Read { path, .. } | Self::Parse { path, .. } => path,
        }
    }
}

impl<E: fmt::Display> fmt::Display for FileError<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Read { path, source } => write!(f, "{}: {source}", path.display()),
            Self::Parse { path, source } => write!(f, "{}: {source}", path.display()),
        }
    }
}

impl<E: Error + 'static> Error for FileError<E> {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        // The parser diagnostic is already forwarded by the `Diagnostic`
        // implementation below. Expose only its own cause so miette does
        // not render the same snippet twice.
        match self {
            Self::Read { source, .. } => source.source(),
            Self::Parse { source, .. } => source.source(),
        }
    }
}

impl<E: Diagnostic + 'static> Diagnostic for FileError<E> {
    fn code<'a>(&'a self) -> Option<Box<dyn fmt::Display + 'a>> {
        match self {
            Self::Read { .. } => Some(Box::new("cgconfig::read")),
            Self::Parse { source, .. } => source.code(),
        }
    }

    fn severity(&self) -> Option<miette::Severity> {
        match self {
            Self::Read { .. } => Some(miette::Severity::Error),
            Self::Parse { source, .. } => source.severity(),
        }
    }

    fn help<'a>(&'a self) -> Option<Box<dyn fmt::Display + 'a>> {
        match self {
            Self::Read { .. } => None,
            Self::Parse { source, .. } => source.help(),
        }
    }

    fn url<'a>(&'a self) -> Option<Box<dyn fmt::Display + 'a>> {
        match self {
            Self::Read { .. } => None,
            Self::Parse { source, .. } => source.url(),
        }
    }

    fn source_code(&self) -> Option<&dyn miette::SourceCode> {
        match self {
            Self::Read { .. } => None,
            Self::Parse { source, .. } => source.source_code(),
        }
    }

    fn labels(&self) -> Option<Box<dyn Iterator<Item = miette::LabeledSpan> + '_>> {
        match self {
            Self::Read { .. } => None,
            Self::Parse { source, .. } => source.labels(),
        }
    }

    fn related<'a>(&'a self) -> Option<Box<dyn Iterator<Item = &'a dyn Diagnostic> + 'a>> {
        match self {
            Self::Read { .. } => None,
            Self::Parse { source, .. } => source.related(),
        }
    }

    fn diagnostic_source(&self) -> Option<&dyn Diagnostic> {
        match self {
            Self::Read { .. } => None,
            Self::Parse { source, .. } => source.diagnostic_source(),
        }
    }
}
