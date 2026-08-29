#![no_main]

use std::time::Instant;

use libfuzzer_sys::fuzz_target;
use lattice_net_core::packet::{PacketFragment, PacketReassembler};

fuzz_target!(|data: &[u8]| {
    let mut reassembler = PacketReassembler::default();
    for chunk in data.chunks(64) {
        if let Ok(fragment) = PacketFragment::decode(chunk) {
            let _ = reassembler.push(fragment, Instant::now());
        }
    }
});
