#![no_std]

pub const MAX_DNS_NAME_LEN: usize = 256;

#[derive(Clone, Copy)]
#[repr(C)]
pub struct BlockEntry {
    pub name: [u8; MAX_DNS_NAME_LEN],
    pub len: usize,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for BlockEntry {}
