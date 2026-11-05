use chrono::{Datelike, Timelike, Utc};
use slog::*;
use slog_term::{Decorator, RecordDecorator};
use std::cell::RefCell;
use std::io::Write;
use std::sync::Mutex;
use std::{io, result};

#[macro_use]
extern crate lazy_static;

pub const LOG_CTRL_REOPEN: &str = "LogReopen";

lazy_static! {
    pub static ref START_TM: Mutex<std::time::Instant> = Mutex::new(std::time::Instant::now());
}

// {{{ Plain

pub struct RawPlainDecorator {
    name: String,
    current: u64,
    output: std::fs::File,
}

pub struct PlainDecorator {
    deco: RefCell<RawPlainDecorator>,
}

impl PlainDecorator {
    /// Create `PlainDecorator` instance
    pub fn new(name: String) -> Self {
        let now = Utc::now();
        let current = now.year() as u64 * 1_000_000
            + now.month() as u64 * 10_000
            + now.day() as u64 * 100
            + now.hour() as u64;
        let filename = name.clone();
        PlainDecorator {
            deco: RefCell::new(RawPlainDecorator {
                name: name,
                current: current,
                output: std::fs::File::options()
                    .create(true)
                    .append(true)
                    .open(std::path::Path::new(&filename.to_string()))
                    .unwrap(),
            }),
        }
    }
}

impl Decorator for PlainDecorator {
    fn with_record<F>(&self, _record: &Record, _logger_values: &OwnedKVList, f: F) -> io::Result<()>
    where
        F: FnOnce(&mut dyn RecordDecorator) -> io::Result<()>,
    {
        let mut deco = self.deco.borrow_mut();
        let mut deco = PlainRecordDecorator { deco: &mut *deco };
        f(&mut deco)
    }
}

/// Record decorator used by `PlainDecorator`
pub struct PlainRecordDecorator<'a> {
    deco: &'a mut RawPlainDecorator,
}

impl<'a> io::Write for PlainRecordDecorator<'a> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        {
            let now = Utc::now();
            let current = now.year() as u64 * 1_000_000
                + now.month() as u64 * 10_000
                + now.day() as u64 * 100
                + now.hour() as u64;
            if self.deco.current != current {
                self.deco.current = current;
                let filename = self.deco.name.clone();
                self.deco.output = std::fs::File::options()
                    .create(true)
                    .append(true)
                    .open(std::path::Path::new(&filename.to_string()))
                    .unwrap();
            }
        }
        self.deco.output.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.deco.output.flush()
    }
}

impl<'a> RecordDecorator for PlainRecordDecorator<'a> {
    fn reset(&mut self) -> io::Result<()> {
        Ok(())
    }
}

//// {{{ RawFormat

pub struct RawFormat<D>
where
    D: Decorator,
{
    decorator: D,
}

/// Streamer builder
pub struct RawFormatBuilder<D>
where
    D: Decorator,
{
    decorator: D,
}

impl<D> RawFormatBuilder<D>
where
    D: Decorator,
{
    /// Build the streamer
    pub fn build(self) -> RawFormat<D> {
        RawFormat {
            decorator: self.decorator,
        }
    }
}

impl<D> Drain for RawFormat<D>
where
    D: Decorator,
{
    type Ok = ();
    type Err = io::Error;

    fn log(&self, record: &Record, values: &OwnedKVList) -> result::Result<Self::Ok, Self::Err> {
        self.format_compact(record, values)
    }
}

impl<D> RawFormat<D>
where
    D: Decorator,
{
    /// New `RawFormatBuilder`
    #[allow(clippy::new_ret_no_self)]
    pub fn new(d: D) -> RawFormatBuilder<D> {
        RawFormatBuilder { decorator: d }
    }

    fn format_compact(&self, record: &Record, values: &OwnedKVList) -> io::Result<()> {
        self.decorator.with_record(record, values, |mut decorator| {
            decorator.start_msg()?;
            let mut count_rd = slog_term::CountingWriter::new(&mut decorator);
            write!(count_rd, "{}", record.msg())?;

            decorator.flush()?;

            Ok(())
        })
    }
}

pub fn create_logger(name: String) -> slog::Logger {
    let decorator = PlainDecorator::new(name);
    let drain = RawFormat::new(decorator).build().ignore_res();
    let drain = slog_async::Async::new(drain)
        .chan_size(8192)
        .thread_name("sandvmm-log".to_string())
        .overflow_strategy(slog_async::OverflowStrategy::Drop)
        .build()
        .ignore_res();
    let logger = slog::Logger::root(drain, o!());

    logger
}
