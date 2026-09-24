pub mod dial;
pub mod service;

use crate::ops::abuse::{AbuseGuard, Reservation, Surface};
use crate::state::usage;
use service::{
    AuthenticationLimiter, AuthenticationReservation, Identity, UsageHooks, UsageSession,
};
use std::net::IpAddr;

struct ProxyAuthenticationReservation<'a>(Option<Reservation<'a>>);

impl AuthenticationReservation for ProxyAuthenticationReservation<'_> {
    fn refund(mut self: Box<Self>) {
        self.0
            .take()
            .expect("proxy authentication reservation is present")
            .refund();
    }
}

impl AuthenticationLimiter for AbuseGuard {
    fn reserve(&self, client: IpAddr) -> Option<Box<dyn AuthenticationReservation + '_>> {
        AbuseGuard::reserve(self, Surface::Proxy, client).map(|reservation| {
            Box::new(ProxyAuthenticationReservation(Some(reservation)))
                as Box<dyn AuthenticationReservation + '_>
        })
    }
}

impl UsageHooks for usage::Store {
    fn begin(
        &self,
        identity: &Identity,
        kind: &'static str,
        target: &str,
    ) -> Box<dyn UsageSession> {
        Box::new(usage::Store::begin(
            self,
            "",
            identity.account_id.as_ref(),
            identity.device_id.as_ref(),
            kind,
            "",
            target,
        ))
    }
}

impl UsageSession for usage::Session {
    fn add_uploaded(&self, bytes: u64) {
        usage::Session::add_uploaded(self, bytes, 0);
    }

    fn add_downloaded(&self, bytes: u64) {
        usage::Session::add_downloaded(self, bytes, 0);
    }
}
