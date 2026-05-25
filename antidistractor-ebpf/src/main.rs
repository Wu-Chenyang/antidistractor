#![no_std]
#![no_main]
#![allow(static_mut_refs)]

use aya_ebpf::{
    bindings::{TC_ACT_OK, TC_ACT_SHOT},
    helpers::bpf_skb_load_bytes,
    macros::{classifier, map},
    maps::{HashMap, PerCpuArray},
    programs::TcContext,
};

const MAX_DNS_NAME_LEN: usize = 256;

#[map]
static mut BLOCKLIST: HashMap<[u8; MAX_DNS_NAME_LEN], u8> = HashMap::with_max_entries(1024, 0);

/// Per-CPU buffer for SNI name extraction (avoids BPF stack size limits).
#[repr(C)]
pub struct NameBuf {
    pub name: [u8; MAX_DNS_NAME_LEN],
}

#[map]
static mut NAME_BUF: PerCpuArray<NameBuf> = PerCpuArray::with_max_entries(1, 0);

#[classifier]
pub fn antidistractor(ctx: TcContext) -> i32 {
    match try_antidistractor(&ctx) {
        Ok(ret) => ret,
        Err(_) => TC_ACT_OK,
    }
}

/// Read a u8 from skb at the given offset using bpf_skb_load_bytes.
/// Works even when data is in skb fragments (GSO/GRO on egress path).
#[inline(always)]
fn skb_load_u8(ctx: &TcContext, off: usize) -> Result<u8, ()> {
    let mut buf = [0u8; 1];
    let ret = unsafe {
        bpf_skb_load_bytes(
            ctx.skb.skb as *const _,
            off as u32,
            buf.as_mut_ptr() as *mut _,
            1,
        )
    };
    if ret != 0 { return Err(()); }
    Ok(buf[0])
}

/// Read a big-endian u16 from skb at the given offset.
#[inline(always)]
fn skb_load_u16(ctx: &TcContext, off: usize) -> Result<u16, ()> {
    let mut buf = [0u8; 2];
    let ret = unsafe {
        bpf_skb_load_bytes(
            ctx.skb.skb as *const _,
            off as u32,
            buf.as_mut_ptr() as *mut _,
            2,
        )
    };
    if ret != 0 { return Err(()); }
    Ok(u16::from_be_bytes(buf))
}

fn try_antidistractor(ctx: &TcContext) -> Result<i32, ()> {
    // Read EtherType (at offset 12 in ethernet frame)
    let ether_type = skb_load_u16(ctx, 12)?;

    let mut offset: usize = 14; // past ethernet header
    let proto: u8;

    if ether_type == 0x0800 {
        // IPv4: read protocol and IHL
        let ver_ihl = skb_load_u8(ctx, offset)?;
        proto = skb_load_u8(ctx, offset + 9)?;
        let ihl = (ver_ihl & 0x0F) as usize * 4;
        if ihl < 20 || ihl > 60 { return Ok(TC_ACT_OK); }
        offset += ihl;
    } else if ether_type == 0x86DD {
        // IPv6: next header at offset+6
        proto = skb_load_u8(ctx, offset + 6)?;
        offset += 40;
    } else {
        return Ok(TC_ACT_OK);
    }

    // Only TCP
    if proto != 6 { return Ok(TC_ACT_OK); }

    // Read TCP destination port (offset+2 in TCP header)
    let dest_port = skb_load_u16(ctx, offset + 2)?;
    if dest_port != 443 { return Ok(TC_ACT_OK); }

    // TCP data offset (offset+12, upper 4 bits)
    let doff_byte = skb_load_u8(ctx, offset + 12)?;
    let doff = ((doff_byte & 0xF0) >> 4) as usize * 4;
    if doff < 20 || doff > 60 { return Ok(TC_ACT_OK); }
    offset += doff;

    // TLS Record: ContentType(1) + Version(2) + Length(2)
    let content_type = skb_load_u8(ctx, offset)?;
    if content_type != 22 { return Ok(TC_ACT_OK); } // 22 = Handshake
    offset += 5;

    // Handshake header: Type(1) + Length(3)
    let hs_type = skb_load_u8(ctx, offset)?;
    if hs_type != 1 { return Ok(TC_ACT_OK); } // 1 = ClientHello
    offset += 4;

    // ClientHello: Version(2) + Random(32)
    offset += 34;

    // Session ID Length(1) + Session ID
    let sid_len = skb_load_u8(ctx, offset)? as usize;
    if sid_len > 32 { return Ok(TC_ACT_OK); }
    offset += 1 + sid_len;

    // Cipher Suites Length(2) + Cipher Suites
    let cs_len = skb_load_u16(ctx, offset)? as usize;
    if cs_len > 512 { return Ok(TC_ACT_OK); }
    offset += 2 + cs_len;

    // Compression Methods Length(1) + Compression Methods
    let cp_len = skb_load_u8(ctx, offset)? as usize;
    if cp_len > 32 { return Ok(TC_ACT_OK); }
    offset += 1 + cp_len;

    // Extensions Length(2)
    let exts_len = skb_load_u16(ctx, offset)? as usize;
    offset += 2;

    // Iterate extensions to find SNI (type 0x0000)
    let mut cur_ext: usize = 0;
    for _ in 0..64u32 {
        if cur_ext + 4 > exts_len { break; }

        let etype = skb_load_u16(ctx, offset + cur_ext)?;
        let elen = skb_load_u16(ctx, offset + cur_ext + 2)? as usize;

        if etype == 0 {
            // SNI Extension
            let mut sni_off = offset + cur_ext + 4;
            // SNI List Length(2)
            sni_off += 2;

            // Name Type(1) - 0 = host_name
            let name_type = skb_load_u8(ctx, sni_off)?;
            if name_type == 0 {
                sni_off += 1;
                // Name Length(2)
                let name_len = skb_load_u16(ctx, sni_off)? as usize;
                sni_off += 2;

                if name_len > 0 && name_len < 128 {
                    // Use per-CPU map buffer to avoid BPF stack limits
                    let buf = unsafe {
                        let ptr = NAME_BUF.get_ptr_mut(0).ok_or(())?;
                        &mut *ptr
                    };

                    // Zero the entire buffer
                    buf.name = [0u8; MAX_DNS_NAME_LEN];

                    // Read name from skb. OR with 1 ensures the verifier sees
                    // the read length as always >= 1 (avoids zero-sized read error).
                    let read_len = (name_len as u32) | 1;

                    let ret = unsafe {
                        bpf_skb_load_bytes(
                            ctx.skb.skb as *const _,
                            sni_off as u32,
                            buf.name.as_mut_ptr() as *mut _,
                            read_len,
                        )
                    };
                    if ret != 0 { return Ok(TC_ACT_OK); }

                    if unsafe { BLOCKLIST.get(&buf.name).is_some() } {
                        return Ok(TC_ACT_SHOT);
                    }
                }
            }
            break;
        }
        cur_ext += 4 + elen;
        if cur_ext > 1024 { break; }
    }

    Ok(TC_ACT_OK)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! { loop {} }
