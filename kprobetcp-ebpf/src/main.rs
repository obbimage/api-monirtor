#![no_std]
#![no_main]

#[allow(
    clippy::all,
    dead_code,
    improper_ctypes_definitions,
    non_camel_case_types,
    non_snake_case,
    non_upper_case_globals,
    unnecessary_transmutes,
    unsafe_op_in_unsafe_fn,
)]
#[rustfmt::skip]
mod vmlinux;
use crate::vmlinux::{msghdr, sk_buff, sock, sock_common};

use aya_ebpf::{bpf_printk, helpers::{
    bpf_get_current_pid_tgid,
    bpf_probe_read_kernel,
    bpf_probe_read_kernel_buf,
    bpf_probe_read_user_buf,
}, macros::{kprobe, map, uprobe, uretprobe}, maps::{HashMap, PerCpuArray, RingBuf}, programs::{ProbeContext, RetProbeContext}, EbpfContext};

use aya_log_ebpf::info;
use kprobetcp_common::{HttpEvent, HttpMethod};

#[derive(Clone, Copy)]
pub struct SslReadArgs {
    pub buf: u64,
}

// ── Maps ──────────────────────────────────────────────────────────────────────
#[map]
static SSL_READ_ARGS: HashMap<u64, SslReadArgs> = HashMap::with_max_entries(4096, 0);

#[map]
static BUF: PerCpuArray<[u8; 512]> = PerCpuArray::with_max_entries(1, 0);

#[map]
static RING_BUF_REQ: RingBuf = RingBuf::with_byte_size(1024 * 256, 0);

#[map]
static RING_BUF_RES: RingBuf = RingBuf::with_byte_size(1024 * 256, 0);

#[map]
static RECV_IOV: HashMap<u64, u64> = HashMap::with_max_entries(1024, 0);

const AF_INET: u16 = 2;
const AF_INET6: u16 = 10;

// ─────────────────────────────────────────────────────────────────────────────
// SSL_write — HTTPS request
// ─────────────────────────────────────────────────────────────────────────────
#[uprobe]
pub fn ssl_write(ctx: ProbeContext) -> u32 {
    match try_ssl_write(ctx) {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

fn try_ssl_write(ctx: ProbeContext) -> Result<u32, i64> {
    let buf_ptr: *const u8 = ctx.arg(1).ok_or(1i64)?;
    let len: i32 = ctx.arg(2).ok_or(1i64)?;

    if buf_ptr.is_null() || len <= 0 {
        return Ok(0);
    }

    const MAX_DATA: usize = 496;
    let read_len = (len as usize).min(MAX_DATA);

    if read_len < 5 || read_len > MAX_DATA {
        return Ok(0);
    }

    let buf = unsafe {
        let ptr = BUF.get_ptr_mut(0).ok_or(1i64)?;
        &mut *ptr
    };

    unsafe {
        bpf_probe_read_user_buf(buf_ptr, &mut buf[..read_len])?;
    }
    //


    if let Some(mut entry) = RING_BUF_REQ.reserve::<HttpEvent>(0) {
        let event = unsafe { &mut *entry.as_mut_ptr() };
        event.is_request = 1;
        event.dport      = 443;
        event.sport      = 0;
        event.saddr      = 0;
        event.daddr      = 0;
        event.timestamp  = unsafe { aya_ebpf::helpers::bpf_ktime_get_ns() };
        event._pad       = [0u8; 3];
        event.method = if &buf[..4] == b"GET " {
            HttpMethod::GET as u8
        } else if &buf[..5] == b"POST " {
            HttpMethod::POST as u8
        } else if &buf[..4] == b"PUT " {
            HttpMethod::PUT as u8
        } else if &buf[..7] == b"DELETE " {
            HttpMethod::DELETE as u8
        } else {
            HttpMethod::UNKNOWN as u8
        };

        unsafe {
            core::ptr::copy_nonoverlapping(
                buf.as_ptr(),
                event.data.as_mut_ptr(),
                read_len,
            );
            // Zero phần còn lại
            core::ptr::write_bytes(
                event.data.as_mut_ptr().add(read_len),
                0,
                MAX_DATA - read_len,
            );
        }
        entry.submit(0);
    }

    Ok(0)
}

// ─────────────────────────────────────────────────────────────────────────────
// SSL_read entry — lưu buf pointer
// Key = bpf_get_current_pid_tgid() để đảm bảo khớp với uretprobe
// ─────────────────────────────────────────────────────────────────────────────
#[uprobe]
pub fn ssl_read_entry(ctx: ProbeContext) -> u32 {
    let buf_ptr: u64 = match ctx.arg(1) {
        Some(v) => v,
        None => return 0,
    };

    if buf_ptr == 0 {
        return 0;
    }

    // Dùng bpf_get_current_pid_tgid() — cùng helper với uretprobe
    let key: u64 = unsafe { bpf_get_current_pid_tgid() };

    let args = SslReadArgs { buf: buf_ptr };
    SSL_READ_ARGS.insert(&key, &args, 0).ok();

    0
}

// ─────────────────────────────────────────────────────────────────────────────
// SSL_read return — đọc response plaintext
// ─────────────────────────────────────────────────────────────────────────────
#[uretprobe]
pub fn ssl_read(ctx: RetProbeContext) -> u32 {
    match try_ssl_read_ret(ctx) {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

fn try_ssl_read_ret(ctx: RetProbeContext) -> Result<u32, i64> {
    let ret_val: i32 = ctx.ret::<i32>();
    if ret_val <= 0 {
        return Ok(0);
    }

    // Cùng key với entry
    let key: u64 = unsafe { bpf_get_current_pid_tgid() };

    let args = unsafe {
        match SSL_READ_ARGS.get(&key) {
            Some(a) => *a,
            None => {
                // info!(&ctx, "ssl_read_ret: no entry for key={}", key);
                return Ok(0);
            }
        }
    };
    SSL_READ_ARGS.remove(&key).ok();

    let buf_ptr = args.buf as *const u8;
    if buf_ptr.is_null() {
        return Ok(0);
    }

    const MAX_DATA: usize = 496;
    let read_len = (ret_val as usize).min(MAX_DATA);

    if read_len == 0 || read_len > MAX_DATA {
        return Ok(0);
    }

    let buf = unsafe {
        let ptr = BUF.get_ptr_mut(0).ok_or(1i64)?;
        &mut *ptr
    };

    unsafe {
        bpf_probe_read_user_buf(buf_ptr, &mut buf[..read_len])?;
    }
    // info!(&ctx,"test3");

    // Debug: log 5 bytes đầu
    // info!(&ctx, "ssl_read_ret: len={} first_bytes={} {} {} {} {}",
    //     read_len,
    //     buf[0], buf[1], buf[2], buf[3], buf[4]
    // );

    // if &buf[..5] != b"HTTP/" {
    //     return Ok(0);
    // }
    // info!(&ctx,"test3");

    // info!(&ctx, "ssl_read_ret: HTTP response captured len={}", read_len);

    if let Some(mut entry) = RING_BUF_RES.reserve::<HttpEvent>(0) {
        let event = unsafe { &mut *entry.as_mut_ptr() };
        event.is_request = 0;
        event.method     = HttpMethod::UNKNOWN as u8;
        event.sport      = 443;
        event.dport      = 0;
        event.saddr      = 0;
        event.daddr      = 0;
        event.timestamp  = unsafe { aya_ebpf::helpers::bpf_ktime_get_ns() };
        event._pad       = [0u8; 3];

        let mut i = 0usize;
        while i < MAX_DATA {
            event.data[i] = if i < read_len { buf[i] } else { 0 };
            i += 1;
        }
        entry.submit(0);
    }

    Ok(0)
}

// ─────────────────────────────────────────────────────────────────────────────
// skb_copy_datagram_iter — HTTP response (port 80)
// ─────────────────────────────────────────────────────────────────────────────
#[kprobe]
pub fn kprobe_skb_copy_datagram_iter(ctx: ProbeContext) -> u32 {
    match try_skb_copy_datagram_iter(ctx) {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

fn try_skb_copy_datagram_iter(ctx: ProbeContext) -> Result<u32, i64> {
    let skb: *const sk_buff = ctx.arg(0).ok_or(1i64)?;
    let len: u32 = ctx.arg(3).ok_or(1i64)?;

    if skb.is_null() {
        return Ok(0);
    }

    let sk: *const sock = unsafe {
        bpf_probe_read_kernel(&(*skb).sk as *const *mut sock)? as *const sock
    };

    if sk.is_null() {
        return Ok(0);
    }

    let sk_common = unsafe {
        bpf_probe_read_kernel(&(*sk).__sk_common as *const sock_common)?
    };

    if sk_common.skc_family != AF_INET {
        return Ok(0);
    }

    let src_addr = u32::from_be(unsafe {
        sk_common.__bindgen_anon_1.__bindgen_anon_1.skc_rcv_saddr
    });
    let dest_addr = u32::from_be(unsafe {
        sk_common.__bindgen_anon_1.__bindgen_anon_1.skc_daddr
    });
    let src_port = u16::from_be(unsafe {
        sk_common.__bindgen_anon_3.__bindgen_anon_1.skc_num
    });
    let dest_port = u16::from_be(unsafe {
        sk_common.__bindgen_anon_3.__bindgen_anon_1.skc_dport
    });

    let data_ptr: *const u8 = unsafe {
        bpf_probe_read_kernel(&(*skb).data as *const *mut u8)? as *const u8
    };

    if data_ptr.is_null() {
        return Ok(0);
    }

    const MAX_DATA: usize = 496;
    let read_len = (len as usize).min(MAX_DATA);

    if read_len < 5 || read_len > MAX_DATA {
        return Ok(0);
    }

    let buf = unsafe {
        let ptr = BUF.get_ptr_mut(0).ok_or(1i64)?;
        &mut *ptr
    };

    unsafe {
        bpf_probe_read_kernel_buf(data_ptr, &mut buf[..read_len])?;
    }

    if &buf[..5] != b"HTTP/" {
        return Ok(0);
    }

    // if let Some(mut entry) = RING_BUF_RES.reserve::<HttpEvent>(0) {
    //     let event = unsafe { &mut *entry.as_mut_ptr() };
    //     event.method     = HttpMethod::UNKNOWN as u8;
    //     event.saddr      = src_addr;
    //     event.daddr      = dest_addr;
    //     event.sport      = src_port;
    //     event.dport      = dest_port;
    //     event.is_request = 0;
    //     event._pad       = [0u8; 3];
    //     event.timestamp  = unsafe { aya_ebpf::helpers::bpf_ktime_get_ns() };
    //
    //     let mut i = 0usize;
    //     while i < MAX_DATA {
    //         event.data[i] = if i < read_len { buf[i] } else { 0 };
    //         i += 1;
    //     }
    //     entry.submit(0);
    // }

    Ok(0)
}

// ─────────────────────────────────────────────────────────────────────────────
// tcp_sendmsg — HTTP request (port 80)
// ─────────────────────────────────────────────────────────────────────────────
#[kprobe]
pub fn tcp_sendmsg(ctx: ProbeContext) -> u32 {
    match try_tcp_sendmsg(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret.try_into().unwrap_or(1),
    }
}

fn try_tcp_sendmsg(ctx: ProbeContext) -> Result<u32, i64> {
    let sock: *const sock = ctx.arg(0).ok_or(1i64)?;
    let msg: *const msghdr = ctx.arg(1).ok_or(1i64)?;
    let size: usize = ctx.arg(2).ok_or(1i64)?;

    let sk_common = unsafe {
        bpf_probe_read_kernel(&(*sock).__sk_common as *const sock_common)?
    };

    if sk_common.skc_family != AF_INET {
        return Ok(0);
    }

    let src_addr = u32::from_be(unsafe {
        sk_common.__bindgen_anon_1.__bindgen_anon_1.skc_rcv_saddr
    });
    let dest_addr = u32::from_be(unsafe {
        sk_common.__bindgen_anon_1.__bindgen_anon_1.skc_daddr
    });
    let src_port = u16::from_be(unsafe {
        sk_common.__bindgen_anon_3.__bindgen_anon_1.skc_num
    });
    let dest_port = u16::from_be(unsafe {
        sk_common.__bindgen_anon_3.__bindgen_anon_1.skc_dport
    });

    let msg_iter = unsafe { bpf_probe_read_kernel(&(*msg).msg_iter)? };
    let iovec = unsafe { msg_iter.__bindgen_anon_1.__ubuf_iovec };

    const MAX_DATA: usize = 496;
    let read_len = size.min(MAX_DATA);

    if read_len < 4 {
        return Ok(0);
    }

    let buf = unsafe {
        let ptr = BUF.get_ptr_mut(0).ok_or(1i64)?;
        &mut *ptr
    };

    unsafe {
        bpf_probe_read_user_buf(iovec.iov_base as *const u8, &mut buf[..read_len])?;
    }

    let method = match buf[0] {
        b'G' => HttpMethod::GET as u8,
        b'P' => {
            if read_len >= 4 && buf[1] == b'O' {
                HttpMethod::POST as u8
            } else {
                HttpMethod::PUT as u8
            }
        }
        b'D' => HttpMethod::DELETE as u8,
        _ => return Ok(0),
    };

    if let Some(mut entry) = RING_BUF_REQ.reserve::<HttpEvent>(0) {
        let event = unsafe { &mut *entry.as_mut_ptr() };
        event.method     = method;
        event.saddr      = src_addr;
        event.daddr      = dest_addr;
        event.sport      = src_port;
        event.dport      = dest_port;
        event.is_request = 1;
        event._pad       = [0u8; 3];
        event.timestamp  = unsafe { aya_ebpf::helpers::bpf_ktime_get_ns() };

        let mut i = 0usize;
        while i < MAX_DATA {
            event.data[i] = if i < read_len { buf[i] } else { 0 };
            i += 1;
        }
        entry.submit(0);
    }

    Ok(0)
}

// ─────────────────────────────────────────────────────────────────────────────
// kprobetcp — tcp_connect
// ─────────────────────────────────────────────────────────────────────────────
#[kprobe]
pub fn kprobetcp(ctx: ProbeContext) -> u32 {
    match try_kprobetcp(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret.try_into().unwrap_or(1),
    }
}

fn try_kprobetcp(ctx: ProbeContext) -> Result<u32, i64> {
    let sock: *mut sock = ctx.arg(0).ok_or(1i64)?;
    let sk_common = unsafe {
        bpf_probe_read_kernel(&(*sock).__sk_common as *const sock_common)?
    };
    match sk_common.skc_family {
        AF_INET => Ok(0),
        AF_INET6 => {
            let src_addr = sk_common.skc_v6_rcv_saddr;
            let dest_addr = sk_common.skc_v6_daddr;
            info!(
                &ctx,
                "AF_INET6 src addr: {:i}, dest addr: {:i}",
                unsafe { src_addr.in6_u.u6_addr8 },
                unsafe { dest_addr.in6_u.u6_addr8 }
            );
            Ok(0)
        }
        _ => Ok(0),
    }
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}