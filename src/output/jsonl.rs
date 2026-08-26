use crate::models::result::ScanFinding;
use std::fs::File;
use std::io::{self, BufWriter, Write};
use std::path::Path;

/// JSON Lines writer that streams findings one-per-line to a file or stdout.
pub struct JsonlWriter {
    writer: Box<dyn Write + Send>,
}

impl JsonlWriter {
    /// Create a JSONL writer targeting a file path.
    pub fn to_file(path: &str) -> io::Result<Self> {
        let file = File::create(Path::new(path))?;
        Ok(Self {
            writer: Box::new(BufWriter::new(file)),
        })
    }

    /// Create a JSONL writer targeting stdout.
    pub fn to_stdout() -> Self {
        Self {
            writer: Box::new(BufWriter::new(io::stdout())),
        }
    }

    /// Write a single finding as a JSON line.
    pub fn write_finding(&mut self, finding: &ScanFinding) -> io::Result<()> {
        let json = serde_json::to_string(finding)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
        writeln!(self.writer, "{}", json)?;
        self.writer.flush()
    }

    /// Flush any buffered content.
    pub fn flush(&mut self) -> io::Result<()> {
        self.writer.flush()
    }
}
