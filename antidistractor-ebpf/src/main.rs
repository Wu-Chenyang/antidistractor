#![cfg_attr(target_arch = "bpf", no_std)]
#![cfg_attr(target_arch = "bpf", no_main)]

use aya_ebpf::{
    macros::{classifier, map},
    maps::HashMap,
    programs::TcContext,
};

#[map]
static mut BLOCKLIST: HashMap<[u8; 256], u8> = HashMap::with_max_entries(1024, 0);

#[classifier]
pub fn antidistractor(ctx: TcContext) -> i32 {
    match try_antidistractor(ctx) {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

fn try_antidistractor(_ctx: TcContext) -> Result<i32, u32> {
    Ok(0) // TC_ACT_OK
}

#[cfg(target_arch = "bpf")]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[cfg(not(target_arch = "bpf"))]
fn main() {}
