//! Bounded, buffered line reading for the SMTP protocol.
//!
//! `tokio`'s `read_until` has no length limit, which would let a client with a
//! single unterminated line exhaust memory. This reader enforces an explicit
//! per-line cap and reports over-long lines instead of allocating without
//! bound, while still supporting pipelined commands (several commands
//! arriving in one TCP segment).

use tokio::io::{AsyncRead, AsyncReadExt};

/// Size of each read from the socket.
const CHUNK: usize = 16 * 1024;

#[derive(Debug, PartialEq, Eq)]
pub enum ReadLine {
    /// A complete line with its CRLF (or bare LF) removed.
    Line(Vec<u8>),
    /// The line exceeded the caller's limit; it has been drained from the
    /// stream so the session can report an error and carry on.
    TooLong,
    /// The peer closed the connection.
    Eof,
}

pub struct LineReader<R> {
    inner: R,
    buffer: Vec<u8>,
    position: usize,
}

impl<R: AsyncRead + Unpin> LineReader<R> {
    pub fn new(inner: R) -> Self {
        Self {
            inner,
            buffer: Vec::with_capacity(CHUNK),
            position: 0,
        }
    }

    /// Bytes already read but not yet consumed. Non-zero after pipelined
    /// commands, which is why a session must never discard the reader between
    /// commands.
    pub fn buffered(&self) -> usize {
        self.buffer.len() - self.position
    }

    /// Reads one line, up to `max_len` bytes excluding the terminator.
    pub async fn read_line(&mut self, max_len: usize) -> std::io::Result<ReadLine> {
        // Offset (relative to `position`) already scanned for a newline.
        let mut scanned = 0usize;

        loop {
            if let Some(index) = self.buffer[self.position + scanned..]
                .iter()
                .position(|&byte| byte == b'\n')
            {
                let newline = scanned + index;
                let mut end = newline;
                if end > 0 && self.buffer[self.position + end - 1] == b'\r' {
                    end -= 1;
                }
                let line = self.buffer[self.position..self.position + end].to_vec();
                self.position += newline + 1;
                self.compact_if_drained();

                return Ok(if line.len() > max_len {
                    ReadLine::TooLong
                } else {
                    ReadLine::Line(line)
                });
            }

            scanned = self.buffered();

            // No newline yet and already past the limit: stop buffering and
            // drain the rest of the line.
            if scanned > max_len.saturating_add(2) {
                self.discard_line().await?;
                return Ok(ReadLine::TooLong);
            }

            if self.fill().await? == 0 {
                if self.buffered() == 0 {
                    return Ok(ReadLine::Eof);
                }
                // Final line without a terminator.
                let line = self.buffer[self.position..].to_vec();
                self.position = self.buffer.len();
                self.compact_if_drained();
                return Ok(if line.len() > max_len {
                    ReadLine::TooLong
                } else {
                    ReadLine::Line(line)
                });
            }
        }
    }

    /// Reads exactly `count` bytes verbatim, draining anything the line reader
    /// has already buffered first.
    ///
    /// Needed for opaque payloads such as HTTP request bodies, where reading
    /// line-wise would lose the distinction between `\n` and `\r\n`.
    pub async fn read_exact_bytes(&mut self, count: usize) -> std::io::Result<Option<Vec<u8>>> {
        let mut out = Vec::with_capacity(count.min(64 * 1024));

        while out.len() < count {
            if self.buffered() == 0 && self.fill().await? == 0 {
                return Ok(None);
            }
            let take = (count - out.len()).min(self.buffered());
            let from = self.position;
            out.extend_from_slice(&self.buffer[from..from + take]);
            self.position += take;
            self.compact_if_drained();
        }

        Ok(Some(out))
    }

    /// Reads and throws away bytes until the end of the current line.
    async fn discard_line(&mut self) -> std::io::Result<()> {
        loop {
            if let Some(index) = self.buffer[self.position..]
                .iter()
                .position(|&byte| byte == b'\n')
            {
                self.position += index + 1;
                self.compact_if_drained();
                return Ok(());
            }
            self.position = self.buffer.len();
            self.compact_if_drained();
            if self.fill().await? == 0 {
                return Ok(());
            }
        }
    }

    /// Reads more bytes, compacting the buffer first so it does not grow
    /// without bound across a long session.
    async fn fill(&mut self) -> std::io::Result<usize> {
        if self.position > 0 {
            self.buffer.drain(..self.position);
            self.position = 0;
        }

        let start = self.buffer.len();
        self.buffer.resize(start + CHUNK, 0);
        let read = self.inner.read(&mut self.buffer[start..]).await;
        match read {
            Ok(count) => {
                self.buffer.truncate(start + count);
                Ok(count)
            }
            Err(error) => {
                self.buffer.truncate(start);
                Err(error)
            }
        }
    }

    fn compact_if_drained(&mut self) {
        if self.position == self.buffer.len() {
            self.buffer.clear();
            self.position = 0;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reader(data: &[u8]) -> LineReader<std::io::Cursor<Vec<u8>>> {
        LineReader::new(std::io::Cursor::new(data.to_vec()))
    }

    async fn collect(data: &[u8], max_len: usize) -> Vec<ReadLine> {
        let mut reader = reader(data);
        let mut out = Vec::new();
        loop {
            let line = reader.read_line(max_len).await.unwrap();
            let done = line == ReadLine::Eof;
            out.push(line);
            if done {
                break;
            }
        }
        out
    }

    #[tokio::test]
    async fn reads_crlf_lines() {
        let lines = collect(b"EHLO one\r\nMAIL FROM:<a@b.io>\r\n", 512).await;
        assert_eq!(
            lines,
            vec![
                ReadLine::Line(b"EHLO one".to_vec()),
                ReadLine::Line(b"MAIL FROM:<a@b.io>".to_vec()),
                ReadLine::Eof,
            ]
        );
    }

    #[tokio::test]
    async fn tolerates_bare_lf() {
        let lines = collect(b"NOOP\nQUIT\n", 512).await;
        assert_eq!(
            lines,
            vec![
                ReadLine::Line(b"NOOP".to_vec()),
                ReadLine::Line(b"QUIT".to_vec()),
                ReadLine::Eof,
            ]
        );
    }

    #[tokio::test]
    async fn preserves_empty_lines() {
        // The blank line between headers and body must survive intact.
        let lines = collect(b"Subject: x\r\n\r\nbody\r\n", 512).await;
        assert_eq!(
            lines,
            vec![
                ReadLine::Line(b"Subject: x".to_vec()),
                ReadLine::Line(Vec::new()),
                ReadLine::Line(b"body".to_vec()),
                ReadLine::Eof,
            ]
        );
    }

    #[tokio::test]
    async fn final_line_without_terminator_is_returned() {
        let lines = collect(b"QUIT", 512).await;
        assert_eq!(
            lines,
            vec![ReadLine::Line(b"QUIT".to_vec()), ReadLine::Eof]
        );
    }

    #[tokio::test]
    async fn over_long_lines_are_reported_and_skipped() {
        let long = "A".repeat(600);
        let data = format!("{long}\r\nNOOP\r\n");
        let lines = collect(data.as_bytes(), 512).await;
        assert_eq!(
            lines,
            vec![
                ReadLine::TooLong,
                ReadLine::Line(b"NOOP".to_vec()),
                ReadLine::Eof,
            ],
            "the session must be able to continue after an over-long line"
        );
    }

    #[tokio::test]
    async fn lines_spanning_multiple_reads_are_reassembled() {
        // Longer than the internal chunk, so it takes several socket reads.
        let payload = "B".repeat(CHUNK * 3 + 17);
        let data = format!("{payload}\r\nNOOP\r\n");
        let mut reader = reader(data.as_bytes());

        match reader.read_line(CHUNK * 4).await.unwrap() {
            ReadLine::Line(line) => assert_eq!(line.len(), payload.len()),
            other => panic!("expected a line, got {other:?}"),
        }
        assert_eq!(
            reader.read_line(512).await.unwrap(),
            ReadLine::Line(b"NOOP".to_vec())
        );
    }

    #[tokio::test]
    async fn pipelined_commands_are_all_available() {
        let mut reader = reader(b"MAIL FROM:<a@b.io>\r\nRCPT TO:<c@d.io>\r\nDATA\r\n");
        assert_eq!(
            reader.read_line(512).await.unwrap(),
            ReadLine::Line(b"MAIL FROM:<a@b.io>".to_vec())
        );
        assert!(reader.buffered() > 0, "pipelined bytes must be retained");
        assert_eq!(
            reader.read_line(512).await.unwrap(),
            ReadLine::Line(b"RCPT TO:<c@d.io>".to_vec())
        );
        assert_eq!(
            reader.read_line(512).await.unwrap(),
            ReadLine::Line(b"DATA".to_vec())
        );
    }

    #[tokio::test]
    async fn read_exact_bytes_preserves_crlf_and_leftovers() {
        let mut reader = reader(b"GET / HTTP/1.1\r\n{\"a\":1,\r\n\"b\":2}TRAILING");
        assert_eq!(
            reader.read_line(512).await.unwrap(),
            ReadLine::Line(b"GET / HTTP/1.1".to_vec())
        );

        let body = reader.read_exact_bytes(15).await.unwrap().unwrap();
        assert_eq!(
            body,
            b"{\"a\":1,\r\n\"b\":2}".to_vec(),
            "the CRLF inside the payload must be preserved byte for byte"
        );
        assert_eq!(
            reader.read_exact_bytes(8).await.unwrap().unwrap(),
            b"TRAILING".to_vec()
        );
    }

    #[tokio::test]
    async fn read_exact_bytes_reports_truncation() {
        let mut reader = reader(b"short");
        assert_eq!(reader.read_exact_bytes(100).await.unwrap(), None);
    }

    #[tokio::test]
    async fn read_exact_bytes_spans_multiple_reads() {
        let payload = vec![0xABu8; CHUNK * 2 + 5];
        let mut reader = reader(&payload);
        assert_eq!(
            reader.read_exact_bytes(payload.len()).await.unwrap().unwrap(),
            payload
        );
    }

    #[tokio::test]
    async fn binary_data_lines_survive_unchanged() {
        // Body lines may contain arbitrary bytes; nothing may be re-encoded.
        let mut data = b"X".to_vec();
        data.extend_from_slice(&[0x00, 0x80, 0xff, 0xc3, 0xa9]);
        let mut wire = data.clone();
        wire.extend_from_slice(b"\r\n");

        let mut reader = reader(&wire);
        assert_eq!(
            reader.read_line(512).await.unwrap(),
            ReadLine::Line(data)
        );
    }
}
