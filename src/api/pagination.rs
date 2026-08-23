//! Offset pagination, in one place, defensively.
//!
//! OpenRouter's list endpoints take an `offset` and return a page. That is the
//! whole contract, and it leaves several ways for a client to be wrong: reading
//! the same page forever because the offset never advances, dropping records
//! because a page overlapped the one before it, or trusting a `total_count`
//! that disagrees with the records actually sent.
//!
//! A partial snapshot is worse than no snapshot here. Planning compares what
//! exists remotely with what should exist, so a key missed by pagination looks
//! like a key that is not there — and the plan that follows would propose
//! creating a second one. Every invariant below exists to make a wrong snapshot
//! an error rather than a quiet omission.

use std::collections::BTreeSet;

use crate::client::ApiError;

/// How far pagination will go before it decides the server is not making
/// progress.
///
/// These are not tuning knobs for throughput; they are the point at which a
/// misbehaving server stops being Keymaster's problem.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PageLimits {
    /// Records asked for per page, where the endpoint accepts a limit.
    pub page_size: usize,
    /// Most pages one listing may read.
    pub max_pages: usize,
    /// Most records one listing may collect.
    pub max_items: usize,
}

impl Default for PageLimits {
    fn default() -> Self {
        Self {
            // OpenRouter's documented maximum for the endpoints that take one.
            page_size: 100,
            // Generous: 500 pages of 100 is far more than any organization has,
            // and still terminates in seconds rather than never.
            max_pages: 500,
            max_items: 50_000,
        }
    }
}

/// One page of records, and whatever the server claimed about the whole set.
pub(super) struct Page<T> {
    pub items: Vec<T>,
    /// The server's `total_count`, when it sent one. Used as a bound, never as
    /// a termination condition.
    pub total: Option<u64>,
}

/// Reads every page of one listing, or explains why it stopped.
///
/// `fetch` is given an offset and a page size and returns the records at that
/// offset, already converted to their domain form — so the endpoint keeps its
/// own parameters and this function stays the only place the invariants live.
///
/// `identity` names a record's immutable identity: a key hash, a guardrail
/// UUID, an assignment id. It is what deduplication and progress are measured
/// in, because it is the only part of a record that two pages cannot disagree
/// about.
pub(super) fn collect<T, I, F, N>(
    limits: PageLimits,
    resource: &str,
    identity: F,
    mut fetch: N,
) -> Result<Vec<T>, ApiError>
where
    I: Ord,
    F: Fn(&T) -> I,
    N: FnMut(usize, usize) -> Result<Page<T>, ApiError>,
{
    let mut collected: Vec<T> = Vec::new();
    let mut seen: BTreeSet<I> = BTreeSet::new();
    let mut offset = 0_usize;

    for page_number in 1..=limits.max_pages {
        let page = fetch(offset, limits.page_size)?;

        // An empty page is the end of the listing, and the only ordinary way
        // out of this loop.
        if page.items.is_empty() {
            return Ok(collected);
        }

        // Advance by what arrived, not by what was asked for: a server that
        // returns fewer records than the page size is still making progress,
        // and asking again from the same offset would loop.
        let returned = page.items.len();
        let before = collected.len();
        for item in page.items {
            if seen.insert(identity(&item)) {
                collected.push(item);
            }
        }

        // Overlapping pages are tolerated — the records are deduplicated — but
        // a page whose records are all repeats means the offset is being
        // ignored, and reading on would never terminate.
        if collected.len() == before {
            return Err(stalled(resource, offset, returned, page_number));
        }

        offset = offset.saturating_add(returned);
        let cap = item_cap(limits, page.total);
        if collected.len() > cap {
            return Err(too_many(resource, collected.len(), cap, page.total));
        }
    }

    Err(too_many_pages(resource, limits.max_pages))
}

/// How many records this listing may collect.
///
/// A documented `total_count` tightens the bound, which is what "use it without
/// trusting it" means in practice: an understated total does not truncate the
/// snapshot, because the allowance is twice the total plus a page, but a server
/// streaming records forever is stopped much sooner than the absolute cap.
fn item_cap(limits: PageLimits, total: Option<u64>) -> usize {
    let Some(total) = total.and_then(|total| usize::try_from(total).ok()) else {
        return limits.max_items;
    };
    limits
        .max_items
        .min(total.saturating_mul(2).saturating_add(limits.page_size))
}

fn stalled(resource: &str, offset: usize, returned: usize, page_number: usize) -> ApiError {
    ApiError::InvalidResponse {
        message: format!(
            "listing {resource} made no progress: page {page_number}, at offset {offset}, \
             returned {returned} record(s) and every one of them had an identity already seen. \
             The server appears to be ignoring the offset, so the snapshot would be incomplete."
        ),
    }
}

fn too_many(resource: &str, collected: usize, cap: usize, total: Option<u64>) -> ApiError {
    let claimed = total.map_or_else(
        || "and reported no total".to_owned(),
        |total| format!("while reporting a total of {total}"),
    );
    ApiError::InvalidResponse {
        message: format!(
            "listing {resource} returned {collected} distinct record(s) {claimed}, past the \
             {cap} this listing allows; the snapshot was abandoned rather than truncated"
        ),
    }
}

fn too_many_pages(resource: &str, max_pages: usize) -> ApiError {
    ApiError::InvalidResponse {
        message: format!(
            "listing {resource} read {max_pages} pages without reaching the end; the snapshot was \
             abandoned rather than truncated"
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Pages of integers, served in order, standing in for any listing.
    fn served(
        pages: Vec<Vec<i32>>,
        total: Option<u64>,
    ) -> impl FnMut(usize, usize) -> Result<Page<i32>, ApiError> {
        let mut next = 0;
        move |_offset, _page_size| {
            let items = pages.get(next).cloned().unwrap_or_default();
            next += 1;
            Ok(Page { items, total })
        }
    }

    fn read(pages: Vec<Vec<i32>>, total: Option<u64>) -> Result<Vec<i32>, ApiError> {
        collect(
            PageLimits::default(),
            "things",
            |item: &i32| *item,
            served(pages, total),
        )
    }

    #[test]
    fn overlapping_pages_are_deduplicated_and_still_progress() {
        let read = read(vec![vec![1, 2, 3], vec![3, 4], vec![]], None).expect("a full listing");
        assert_eq!(read, vec![1, 2, 3, 4]);
    }

    #[test]
    fn a_page_of_nothing_but_repeats_is_refused() {
        let failure = read(vec![vec![1, 2], vec![1, 2], vec![]], None)
            .expect_err("a stalled listing is not a snapshot");
        assert_eq!(failure.kind(), "invalid_response");
        assert!(failure.to_string().contains("no progress"), "{failure}");
    }

    #[test]
    fn an_understated_total_does_not_truncate_the_listing() {
        let read = read(vec![vec![1, 2], vec![3, 4], vec![]], Some(1)).expect("a full listing");
        assert_eq!(read, vec![1, 2, 3, 4]);
    }
}
