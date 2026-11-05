// Copyright 2026 Chaoyi Huang. All rights reserved.
//
// SPDX-License-Identifier: BUSL-1.1
//
// Use of this software is governed by the Business Source License
// included in the LICENSE file at the root of this repository.
//
// As of the Change Date specified in that file, in accordance with
// the Business Source License, use of this software will be governed
// by the Apache License, Version 2.0.
//
// Async helpers for the logging path: a byte pump that stops on shutdown.

use std::io;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::watch::Receiver;

// Pump buffer. Small is deliberate: the consumer is a log reader, so a
// pipe-sized chunk bounds forwarding latency without extra syscalls.
const PUMP_BUF_SIZE: usize = 8192;

/// Copy `src` into `dst` until `src` hits EOF or `shutdown` changes.
///
/// Returns the number of bytes transferred. `Interrupted` reads retry; any
/// other read error aborts the pump with that error, as does a write error.
/// Callers that must not fail on a dying log transport (e.g. the logger
/// task during process teardown) discard the result.
pub async fn pump_until_shutdown<R, W>(
    src: &mut R,
    dst: &mut W,
    shutdown: Receiver<bool>,
) -> io::Result<u64>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut moved: u64 = 0;
    let mut chunk = [0u8; PUMP_BUF_SIZE];
    let mut shutdown = shutdown;

    loop {
        tokio::select! {
            // Shutdown outranks in-flight I/O: once the warden is tearing
            // down, the log pump must not outlive the process.
            _ = shutdown.changed() => return Ok(moved),

            read = src.read(&mut chunk) => {
                match read {
                    Ok(0) => return Ok(moved),
                    Ok(n) => {
                        dst.write_all(&chunk[..n]).await?;
                        moved += n as u64;
                    }
                    Err(ref e) if e.kind() == io::ErrorKind::Interrupted => continue,
                    Err(e) => return Err(e),
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::pin::Pin;
    use std::task::{Context, Poll};
    use tokio::io::ReadBuf;
    use tokio::time::{timeout, Duration};

    /// Reader yielding `data` once, then pending forever — holds the pump
    /// mid-stream so only the shutdown branch can finish it.
    struct OnceThenHang {
        data: Vec<u8>,
        served: bool,
    }

    impl AsyncRead for OnceThenHang {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            if self.served {
                return Poll::Pending;
            }
            self.served = true;
            let n = buf.remaining().min(self.data.len());
            buf.put_slice(&self.data[..n]);
            Poll::Ready(Ok(()))
        }
    }

    /// Reader that always fails with a fixed kind — drives the error branch.
    struct FailingReader(io::ErrorKind);

    impl AsyncRead for FailingReader {
        fn poll_read(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Poll::Ready(Err(io::Error::new(self.0, "test read failure")))
        }
    }

    #[tokio::test]
    async fn pumps_to_eof_and_counts() {
        // Sender kept alive and never fired: the pump may only end at EOF.
        let (_tx, rx) = tokio::sync::watch::channel(false);
        let mut src = io::Cursor::new(b"hello pump".to_vec());
        let mut dst = Vec::new();
        let moved = timeout(
            Duration::from_secs(5),
            pump_until_shutdown(&mut src, &mut dst, rx),
        )
        .await
        .expect("EOF must end the pump")
        .unwrap();
        assert_eq!(moved, 10);
        assert_eq!(dst, b"hello pump");
    }

    #[tokio::test]
    async fn empty_source_is_zero_bytes() {
        let (_tx, rx) = tokio::sync::watch::channel(false);
        let mut src = io::Cursor::new(Vec::new());
        let mut dst = Vec::new();
        let moved = pump_until_shutdown(&mut src, &mut dst, rx).await.unwrap();
        assert_eq!(moved, 0);
        assert!(dst.is_empty());
    }

    #[tokio::test]
    async fn shutdown_stops_the_pump_without_hanging() {
        let (tx, rx) = tokio::sync::watch::channel(false);
        let mut src = OnceThenHang {
            data: b"partial".to_vec(),
            served: false,
        };
        let mut dst = Vec::new();
        tx.send(true).unwrap();
        let moved = timeout(
            Duration::from_secs(5),
            pump_until_shutdown(&mut src, &mut dst, rx),
        )
        .await
        .expect("shutdown must end the pump, not hang it")
        .unwrap();
        // Either branch may win one select round, so 0..=7 bytes may land —
        // the invariant under test is the timely exit plus a valid prefix.
        assert!(moved <= 7);
        assert_eq!(&dst[..], &b"partial"[..moved as usize]);
    }

    #[tokio::test]
    async fn read_error_propagates() {
        let (_tx, rx) = tokio::sync::watch::channel(false);
        let mut src = FailingReader(io::ErrorKind::BrokenPipe);
        let mut dst = Vec::new();
        let err = pump_until_shutdown(&mut src, &mut dst, rx)
            .await
            .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::BrokenPipe);
    }
}
