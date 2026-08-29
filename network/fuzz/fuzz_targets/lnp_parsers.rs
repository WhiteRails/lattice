#![no_main]

use libfuzzer_sys::fuzz_target;
use lattice_net_core::packet::PacketFragment;
use lattice_net_core::profile::{EnrollmentBundle, EnrollmentOffer};
use lattice_net_core::protocol::{decode_control, decode_enrollment};

fuzz_target!(|data: &[u8]| {
    let _ = PacketFragment::decode(data);
    let _ = decode_control(data);
    let _ = decode_enrollment(data);
    let _ = EnrollmentBundle::parse(data);
    let _ = EnrollmentOffer::parse(data);
});
