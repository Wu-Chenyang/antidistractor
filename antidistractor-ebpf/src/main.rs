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

/// Per-CPU buffer for suffix key construction during wildcard matching.
/// Stores ".label.label.tld\0..." for BLOCKLIST lookup.
#[map]
static mut SUFFIX_BUF: PerCpuArray<NameBuf> = PerCpuArray::with_max_entries(1, 0);

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
    // Detect whether the packet has an Ethernet header or starts directly at IP.
    // TUN/tap interfaces (link/none) have no Ethernet header — data starts at IP.
    // Regular interfaces (link/ether) have a 14-byte Ethernet header.
    //
    // We inspect the first byte of the packet:
    //   - IPv4 starts with 0x4? (version=4)
    //   - IPv6 starts with 0x6? (version=6)
    //   - Ethernet starts with a MAC byte (very unlikely to be 0x40-0x4F or 0x60-0x6F)
    let first_byte = skb_load_u8(ctx, 0)?;
    let ip_version = first_byte >> 4;

    let mut offset: usize;
    let proto: u8;

    if ip_version == 4 {
        // No Ethernet header — packet starts at IPv4
        offset = 0;
        let ver_ihl = first_byte;
        proto = skb_load_u8(ctx, offset + 9)?;
        let ihl = (ver_ihl & 0x0F) as usize * 4;
        if ihl < 20 || ihl > 60 { return Ok(TC_ACT_OK); }
        offset += ihl;
    } else if ip_version == 6 {
        // No Ethernet header — packet starts at IPv6
        offset = 0;
        proto = skb_load_u8(ctx, offset + 6)?;
        offset += 40;
    } else {
        // Likely has Ethernet header — read EtherType at offset 12
        let ether_type = skb_load_u16(ctx, 12)?;
        offset = 14; // past ethernet header

        if ether_type == 0x0800 {
            // IPv4
            let ver_ihl = skb_load_u8(ctx, offset)?;
            proto = skb_load_u8(ctx, offset + 9)?;
            let ihl = (ver_ihl & 0x0F) as usize * 4;
            if ihl < 20 || ihl > 60 { return Ok(TC_ACT_OK); }
            offset += ihl;
        } else if ether_type == 0x86DD {
            // IPv6
            proto = skb_load_u8(ctx, offset + 6)?;
            offset += 40;
        } else {
            return Ok(TC_ACT_OK);
        }
    }

    // Only TCP
    if proto != 6 { return Ok(TC_ACT_OK); }

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

                    // Step 1: exact match (existing behaviour).
                    if unsafe { BLOCKLIST.get(&buf.name).is_some() } {
                        return Ok(TC_ACT_SHOT);
                    }

                    // Step 2: suffix / wildcard match.
                    //
                    // Walk the SNI label by label from left to right.  For each '.'
                    // boundary, build a suffix key that starts with '.' and look it up
                    // in BLOCKLIST.  A stored key ".bilibili.com" therefore matches
                    // any SNI whose suffix equals ".bilibili.com" (i.e. every subdomain
                    // of bilibili.com).
                    //
                    // Example: SNI = "api.bilibili.com"
                    //   iteration 0 → suffix key ".bilibili.com"  → check BLOCKLIST
                    //   iteration 1 → suffix key ".com"           → check BLOCKLIST
                    //   iteration 2 → no more '.' → stop
                    //
                    // We use a second per-CPU map (SUFFIX_BUF) to hold the key so we
                    // never touch the BPF stack beyond a few bytes.  The loop bound (10)
                    // satisfies the verifier's termination requirement; real domain names
                    // have at most ~5 labels in practice.
                    let sbuf = unsafe {
                        let ptr = SUFFIX_BUF.get_ptr_mut(0).ok_or(())?;
                        &mut *ptr
                    };

                    // `dot_pos` tracks the byte index of the next '.' to process inside
                    // buf.name (which holds the raw SNI bytes, zero-padded to 256).
                    let mut dot_pos: usize = 0;

                    for _ in 0..10u32 {
                        // Find the next '.' starting from dot_pos.
                        // Bounded inner scan: SNI is at most 127 bytes (checked above).
                        let mut found = false;
                        for j in dot_pos..128usize {
                            // Safety: j < 128 < MAX_DNS_NAME_LEN (256).
                            // The verifier accepts this because j has a static upper bound.
                            if j >= MAX_DNS_NAME_LEN { break; }
                            if buf.name[j] == b'.' {
                                dot_pos = j;
                                found = true;
                                break;
                            }
                        }
                        if !found { break; }

                        // Build the suffix key in SUFFIX_BUF: copy from dot_pos to end,
                        // zero-fill the rest.  The key starts with '.' which distinguishes
                        // suffix keys from exact-domain keys in BLOCKLIST.
                        sbuf.name = [0u8; MAX_DNS_NAME_LEN];
                        // Copy bytes [dot_pos .. name_len] into sbuf.name[0..].
                        // We need a bounded copy; name_len < 128.
                        let suffix_len = if name_len > dot_pos { name_len - dot_pos } else { 0 };
                        if suffix_len == 0 || suffix_len >= MAX_DNS_NAME_LEN { break; }
                        for k in 0..128usize {
                            if k >= suffix_len { break; }
                            let src = dot_pos + k;
                            if src >= MAX_DNS_NAME_LEN || k >= MAX_DNS_NAME_LEN { break; }
                            sbuf.name[k] = buf.name[src];
                        }

                        if unsafe { BLOCKLIST.get(&sbuf.name).is_some() } {
                            return Ok(TC_ACT_SHOT);
                        }

                        // Advance past the current '.' so the next iteration finds the
                        // next label boundary.
                        dot_pos += 1;
                        if dot_pos >= name_len { break; }
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
