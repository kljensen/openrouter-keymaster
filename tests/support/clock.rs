//! A fake clock, so journal timestamps and retry timing are deterministic.

use std::sync::{Arc, Mutex};

use time::{Duration, OffsetDateTime};

/// Unix time of 2026-01-01T00:00:00Z, the default start of a test's timeline.
const DEFAULT_START: i64 = 1_767_225_600;

/// A clock that only moves when a test moves it.
///
/// Cloning shares the same timeline, so a fake clock handed to code under test
/// can still be advanced from the test body.
#[derive(Clone, Debug)]
pub struct FakeClock(Arc<Mutex<OffsetDateTime>>);

impl FakeClock {
    /// Starts the timeline at 2026-01-01T00:00:00Z.
    #[must_use]
    pub fn new() -> Self {
        Self::at_unix(DEFAULT_START)
    }

    /// Starts the timeline at a Unix timestamp in seconds.
    #[must_use]
    pub fn at_unix(seconds: i64) -> Self {
        let start = OffsetDateTime::from_unix_timestamp(seconds)
            .unwrap_or_else(|error| panic!("{seconds} is not a valid Unix timestamp: {error}"));
        Self::at(start)
    }

    /// Starts the timeline at an exact instant.
    #[must_use]
    pub fn at(now: OffsetDateTime) -> Self {
        Self(Arc::new(Mutex::new(now)))
    }

    /// The current instant.
    #[must_use]
    pub fn now(&self) -> OffsetDateTime {
        *self.lock()
    }

    /// Moves the timeline forward. A negative duration moves it back.
    pub fn advance(&self, by: Duration) {
        let mut now = self.lock();
        *now += by;
    }

    /// Jumps the timeline to an exact instant.
    pub fn set(&self, to: OffsetDateTime) {
        *self.lock() = to;
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, OffsetDateTime> {
        self.0.lock().expect("the fake clock is not poisoned")
    }
}

impl Default for FakeClock {
    fn default() -> Self {
        Self::new()
    }
}
