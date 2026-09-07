pub mod queue;
pub mod router;
pub mod tun;

use crate::ops::metrics::Metrics;
use queue::{DataMetrics, DropReason};

impl DataMetrics for Metrics {
    fn dropped(&self, reason: DropReason) {
        self.queue_drop(match reason {
            DropReason::QueueOldest => "queue_oldest",
            DropReason::QueueFull => "queue_full",
            DropReason::QueueTail => "queue_tail",
            DropReason::QueueExpired => "queue_expired",
            DropReason::SessionClosed => "session_closed",
            DropReason::InvalidTunPacket => "invalid_tun_packet",
            DropReason::NoSession => "no_session",
        });
    }

    fn adjust_queue_bytes(&self, lane: usize, delta: isize) {
        Metrics::adjust_queue_bytes(self, lane, delta as i64);
    }

    fn lane_collapsed(&self) {
        Metrics::lane_collapsed(self);
    }
}
