mod db;

use aya::maps::RingBuf;
use aya::programs::{KProbe, UProbe};
use aya_log::EbpfLogger;
use clap::Parser;
use hpack::Decoder;
use httparse::Status;
use kprobetcp_common::{Event, HttpMethod};
use log::{info, warn};
use std::collections::HashSet;
use std::convert::{TryFrom, TryInto};
use std::mem;
use std::os::unix::fs::MetadataExt;
use tokio::io::unix::AsyncFd;
use tokio::signal;
use db::create_client;
use crate::db::init_db;

// ── Method byte scheme ────────────────────────────────────────────────────────
// 0x01..=0x05  HTTP/1.1 methods (GET/POST/PUT/DELETE/PATCH)
// 0xE0         HTTP/2 DATA frame
// 0xE1         HTTP/2 HEADERS frame
// 0xE4         HTTP/2 SETTINGS frame  (bỏ qua)
// 0xF0         HTTP/2 client preface  (bỏ qua)
// 0xFF         unknown / raw TLS
const METHOD_H2_PREFACE:    u8 = 0xF0;
const METHOD_H2_FRAME_BASE: u8 = 0xE0;
const METHOD_H2_FRAME_MAX:  u8 = 0xE9;

// HTTP/2 frame types
const H2_FRAME_DATA:        u8 = 0x00;
const H2_FRAME_HEADERS:     u8 = 0x01;
const H2_FRAME_PRIORITY:    u8 = 0x02;
const H2_FRAME_RST_STREAM:  u8 = 0x03;
const H2_FRAME_SETTINGS:    u8 = 0x04;
const H2_FRAME_PUSH_PROMISE:u8 = 0x05;
const H2_FRAME_PING:        u8 = 0x06;
const H2_FRAME_GOAWAY:      u8 = 0x07;
const H2_FRAME_WINDOW_UPDATE:u8= 0x08;
const H2_FRAME_CONTINUATION:u8 = 0x09;

// ── CLI ───────────────────────────────────────────────────────────────────────
#[derive(Debug, Parser)]
struct Opt {
    /// Chỉ monitor PID này (None = tất cả)
    #[clap(short, long)]
    pid: Option<u32>,

    /// In raw hex dump cho mỗi event
    #[clap(long)]
    debug: bool,

    /// Chỉ in HTTP/2 events
    #[clap(long)]
    h2_only: bool,
}

// ── SSL lib discovery ─────────────────────────────────────────────────────────
fn find_ssl_libs() -> HashSet<String> {
    let mut libs        = HashSet::new();
    let mut seen_inodes = HashSet::new();

    let mut try_add = |path: &str| {
        let p = std::path::Path::new(path);
        if !p.exists() { return; }
        if let Ok(meta) = std::fs::metadata(p) {
            if seen_inodes.insert(meta.ino()) {
                let canonical = std::fs::canonicalize(p)
                    .map(|cp| cp.to_string_lossy().to_string())
                    .unwrap_or_else(|_| path.to_string());
                libs.insert(canonical);
            }
        }
    };

    if let Ok(out) = std::process::Command::new("ldconfig").arg("-p").output() {
        let stdout = String::from_utf8_lossy(&out.stdout);
        for line in stdout.lines() {
            let is_ssl = line.contains("libssl.so")
                || line.contains("libgnutls.so")
                || line.contains("libmbedtls.so");
            if is_ssl {
                if let Some(path) = line.split("=>").nth(1) {
                    try_add(path.trim());
                }
            }
        }
    }

    for path in &[
        "/lib/x86_64-linux-gnu/libssl.so.3",
        "/usr/lib/x86_64-linux-gnu/libssl.so.3",
        "/lib/x86_64-linux-gnu/libssl.so.1.1",
        "/usr/lib/x86_64-linux-gnu/libssl.so.1.1",
        "/lib/x86_64-linux-gnu/libgnutls.so.30",
        "/usr/lib/x86_64-linux-gnu/libgnutls.so.30",
    ] {
        try_add(path);
    }
    libs
}

// ── UProbe helpers ────────────────────────────────────────────────────────────
fn load_uprobe(bpf: &mut aya::Ebpf, name: &str) -> bool {
    match bpf.program_mut(name) {
        None => { println!("  ! '{}' not in eBPF binary — skipping", name); false }
        Some(prog) => match TryInto::<&mut UProbe>::try_into(prog) {
            Err(e) => { warn!("'{}' is not a UProbe: {}", name, e); false }
            Ok(p) => match p.load() {
                Ok(_)  => { println!("  ✓ loaded '{}'", name); true }
                Err(e) => { warn!("'{}' load failed: {}", name, e); false }
            },
        },
    }
}

fn attach_uprobe(
    bpf: &mut aya::Ebpf,
    prog_name: &str,
    fn_name: &str,
    lib_path: &str,
    pid: Option<u32>,
    label: &str,
) {
    match bpf.program_mut(prog_name) {
        None => println!("  ! '{}' not found", prog_name),
        Some(prog) => match TryInto::<&mut UProbe>::try_into(prog) {
            Err(e) => println!("  ! '{}' cast failed: {}", prog_name, e),
            Ok(p) => match p.attach(fn_name, lib_path, pid) {
                Ok(_)  => println!("  ✓ {} {} @ {}", label, fn_name, lib_path),
                Err(e) => println!("  ✗ {} {} @ {}: {:?}", label, fn_name, lib_path, e),
            },
        },
    }
}

// ── Method helpers ────────────────────────────────────────────────────────────
fn is_h1_method(method: u8) -> bool {
    matches!(
        HttpMethod::try_from(method),
        Ok(HttpMethod::GET | HttpMethod::POST | HttpMethod::PUT
            | HttpMethod::DELETE | HttpMethod::PATCH)
    )
}

fn is_h2_frame_event(method: u8) -> bool {
    method >= METHOD_H2_FRAME_BASE && method <= METHOD_H2_FRAME_MAX
}

fn h2_frame_type_name(t: u8) -> &'static str {
    match t {
        H2_FRAME_DATA         => "DATA",
        H2_FRAME_HEADERS      => "HEADERS",
        H2_FRAME_PRIORITY     => "PRIORITY",
        H2_FRAME_RST_STREAM   => "RST_STREAM",
        H2_FRAME_SETTINGS     => "SETTINGS",
        H2_FRAME_PUSH_PROMISE => "PUSH_PROMISE",
        H2_FRAME_PING         => "PING",
        H2_FRAME_GOAWAY       => "GOAWAY",
        H2_FRAME_WINDOW_UPDATE=> "WINDOW_UPDATE",
        H2_FRAME_CONTINUATION => "CONTINUATION",
        _                     => "UNKNOWN",
    }
}

// ── IPv4 helpers ──────────────────────────────────────────────────────────────
fn fmt_ipv4(addr: u32) -> String {
    format!("{}.{}.{}.{}",
            (addr >> 24) & 0xff,
            (addr >> 16) & 0xff,
            (addr >>  8) & 0xff,
            addr        & 0xff,
    )
}

// ── Data length: trim trailing NULLs ─────────────────────────────────────────
fn effective_len(data: &[u8]) -> usize {
    data.iter().rposition(|&b| b != 0).map_or(0, |i| i + 1)
}

// ── Hex dump ──────────────────────────────────────────────────────────────────
fn hex_dump(data: &[u8], max_bytes: usize) {
    let n = data.len().min(max_bytes);
    for chunk in data[..n].chunks(16) {
        print!("    ");
        for b in chunk { print!("{:02x} ", b); }
        // padding
        for _ in 0..(16 - chunk.len()) { print!("   "); }
        print!(" |");
        for &b in chunk {
            print!("{}", if b.is_ascii_graphic() || b == b' ' { b as char } else { '.' });
        }
        println!("|");
    }
    if data.len() > max_bytes {
        println!("    ... ({} more bytes)", data.len() - max_bytes);
    }
}

// ── HTTP/2 frame parser ───────────────────────────────────────────────────────
struct H2Frame<'a> {
    length:     u32,
    frame_type: u8,
    flags:      u8,
    stream_id:  u32,
    payload:    &'a [u8],
}

fn parse_h2_frame(data: &[u8]) -> Option<H2Frame<'_>> {
    if data.len() < 9 { return None; }
    let length     = ((data[0] as u32) << 16) | ((data[1] as u32) << 8) | (data[2] as u32);
    let frame_type = data[3];
    let flags      = data[4];
    let stream_id  = ((data[5] as u32 & 0x7f) << 24)
        | ((data[6] as u32) << 16)
        | ((data[7] as u32) << 8)
        |  (data[8] as u32);
    let end     = (9 + length as usize).min(data.len());
    let payload = &data[9..end];
    Some(H2Frame { length, frame_type, flags, stream_id, payload })
}

// ── HTTP/2 event handler ──────────────────────────────────────────────────────
fn handle_h2_event(event: &Event, source: &str, debug: bool) {
    let len = effective_len(&event.data);
    if len == 0 { return; }

    // Preface: "PRI * HTTP/2.0\r\nSM\r\n\r\n"
    if event.method == METHOD_H2_PREFACE {
        println!("[{}][H2] ── CLIENT PREFACE ──────────────────────────────", source);
        return;
    }

    // Binary frame (method = 0xE0 | frame_type)
    if is_h2_frame_event(event.method) {
        let frame_type = event.method & 0x0F;

        // Bỏ qua control frames không có payload hữu ích
        match frame_type {
            H2_FRAME_SETTINGS | H2_FRAME_PING | H2_FRAME_WINDOW_UPDATE
            | H2_FRAME_PRIORITY | H2_FRAME_RST_STREAM | H2_FRAME_GOAWAY => {
                if debug {
                    println!("[{}][H2] {} (control frame, skipped)", source, h2_frame_type_name(frame_type));
                }
                return;
            }
            _ => {}
        }

        let Some(frame) = parse_h2_frame(&event.data[..len]) else { return };

        match frame.frame_type {
            H2_FRAME_HEADERS | H2_FRAME_PUSH_PROMISE | H2_FRAME_CONTINUATION => {
                let end_headers = (frame.flags & 0x04) != 0;
                let end_stream  = (frame.flags & 0x01) != 0;

                // Nếu có PADDED flag (0x08), bỏ qua pad_length byte đầu
                let hpack_payload = if (frame.flags & 0x08) != 0 && !frame.payload.is_empty() {
                    let pad_len = frame.payload[0] as usize;
                    let end = frame.payload.len().saturating_sub(pad_len);
                    &frame.payload[1..end]
                } else {
                    frame.payload
                };

                // Nếu có PRIORITY flag (0x20), bỏ qua 5 bytes đầu (exclusive + weight)
                let hpack_payload = if frame.frame_type == H2_FRAME_HEADERS
                    && (frame.flags & 0x20) != 0
                    && hpack_payload.len() > 5
                {
                    &hpack_payload[5..]
                } else {
                    hpack_payload
                };

                println!(
                    "[{}][H2] ── REQUEST HEADERS ─ stream={} [end_headers={} end_stream={}]",
                    source, frame.stream_id, end_headers, end_stream
                );

                // Decode HPACK
                let mut decoder = Decoder::new();
                match decoder.decode(hpack_payload) {
                    Ok(headers) => {
                        let mut method    = String::new();
                        let mut path      = String::new();
                        let mut authority = String::new();
                        let mut scheme    = String::new();
                        let mut others    = vec![];

                        for (k, v) in &headers {
                            let key = String::from_utf8_lossy(k);
                            let val = String::from_utf8_lossy(v);
                            match key.as_ref() {
                                ":method"    => method    = val.to_string(),
                                ":path"      => path      = val.to_string(),
                                ":authority" => authority = val.to_string(),
                                ":scheme"    => scheme    = val.to_string(),
                                _            => others.push((key.to_string(), val.to_string())),
                            }
                        }

                        println!("  {} {}://{}{}", method, scheme, authority, path);
                        for (k, v) in &others {
                            println!("  {}::: {}", k, v);
                        }
                    }
                    Err(e) => {
                        // HPACK decode fail — có thể do thiếu context (stateful table)
                        // In hex để debug
                        println!("  [HPACK decode error: {:?} — payload {}B]", e, hpack_payload.len());
                        if debug {
                            hex_dump(hpack_payload, 64);
                        }
                    }
                }
            }

            H2_FRAME_DATA => {
                let end_stream = (frame.flags & 0x01) != 0;

                // Bỏ qua PADDED bytes nếu có
                let payload = if (frame.flags & 0x08) != 0 && !frame.payload.is_empty() {
                    let pad_len = frame.payload[0] as usize;
                    let end = frame.payload.len().saturating_sub(pad_len);
                    &frame.payload[1..end]
                } else {
                    frame.payload
                };

                // Trim null bytes cuối
                let payload_len = payload.iter().rposition(|&b| b != 0).map_or(0, |i| i + 1);
                let payload = &payload[..payload_len];

                if payload.is_empty() {
                    if debug {
                        println!("[{}][H2] DATA stream={} (empty, end_stream={})",
                                 source, frame.stream_id, end_stream);
                    }
                    return;
                }

                println!(
                    "[{}][H2] ── REQUEST BODY ─ stream={} [end_stream={}] {}B",
                    source, frame.stream_id, end_stream, payload.len()
                );

                match std::str::from_utf8(payload) {
                    Ok(text) => {
                        let preview = if text.len() > 1024 {
                            format!("{}...(truncated {}/{}B)", &text[..1024], 1024, text.len())
                        } else {
                            text.to_string()
                        };
                        println!("  {}", preview);
                    }
                    Err(_) => {
                        println!("  [binary {}B]", payload.len());
                        hex_dump(payload, 64);
                    }
                }
            }

            _ => {
                if debug {
                    println!(
                        "[{}][H2] {} frame stream={} len={}B",
                        source, h2_frame_type_name(frame.frame_type),
                        frame.stream_id, frame.length
                    );
                }
            }
        }

        return;
    }

    // Fallback: plaintext đã được encode bởi nghttp2_submit_request (method=0x21 cũ)
    // Giữ lại nếu bạn re-enable capture_h2_request
    let text = String::from_utf8_lossy(&event.data[..len]);
    let mut method = "";
    let mut path   = "";
    let mut host   = "";
    for line in text.lines() {
        if let Some((k, v)) = line.split_once(": ") {
            match k {
                ":method"    => method = v,
                ":path"      => path   = v,
                ":authority" => host   = v,
                _ => {}
            }
        }
    }
    println!("[{}][H2] ── REQUEST ───────────────────────────────────────", source);
    println!("  {} {} {}", method, host, path);
    if debug {
        println!("  headers:\n{}", text.trim_end());
    }
}

// ── HTTP/1.1 request handler ──────────────────────────────────────────────────
fn handle_h1_request(event: &Event, source: &str, debug: bool) {
    let len = effective_len(&event.data);
    if len == 0 { return; }

    let mut headers = [httparse::EMPTY_HEADER; 64];
    let mut req     = httparse::Request::new(&mut headers);

    match req.parse(&event.data[..len]) {
        Ok(Status::Complete(_)) | Ok(Status::Partial) => {
            let method = req.method.unwrap_or("?");
            let path   = req.path.unwrap_or("?");

            let mut host         = String::new();
            let mut content_type = String::new();
            let mut user_agent   = String::new();
            let mut content_len  = String::new();

            for h in req.headers.iter() {
                let val = std::str::from_utf8(h.value).unwrap_or("").to_string();
                match h.name.to_lowercase().as_str() {
                    "host"           => host         = val,
                    "content-type"   => content_type = val,
                    "user-agent"     => user_agent   = val,
                    "content-length" => content_len  = val,
                    _ => {}
                }
            }

            // Địa chỉ IP nếu có
            let addr_info = if event.src_addr != 0 && event.des_ddr != 0 {
                format!(" [{}:{} → {}:{}]",
                        fmt_ipv4(event.src_addr), event.src_port,
                        fmt_ipv4(event.des_ddr), event.des_port)
            } else {
                String::new()
            };

            println!("[{}][H1] ── REQUEST ───────────────────────────────────────", source);
            println!("  {} {} http://{}{}{}", method, path, host, path, addr_info);
            if !content_type.is_empty() {
                println!("  content-type: {}", content_type);
            }
            if !user_agent.is_empty() {
                println!("  user-agent:   {}", user_agent);
            }

            // Body
            if let Some(pos) = event.data[..len].windows(4).position(|w| w == b"\r\n\r\n") {
                let raw  = &event.data[pos + 4..len];
                let blen = effective_len(raw);
                if blen > 0 {
                    println!("  content-length: {}", content_len);
                    match std::str::from_utf8(&raw[..blen]) {
                        Ok(text) => {
                            let preview = if text.len() > 512 {
                                format!("{}...(truncated)", &text[..512])
                            } else {
                                text.to_string()
                            };
                            println!("  body: {}", preview);
                        }
                        Err(_) => {
                            println!("  body: [binary {}B]", blen);
                            if debug { hex_dump(&raw[..blen], 32); }
                        }
                    }
                }
            }

            if debug {
                println!("  [raw]");
                hex_dump(&event.data[..len], 128);
            }
        }
        Err(e) => {
            if debug {
                println!("[{}][H1] parse error: {:?}", source, e);
                hex_dump(&event.data[..len.min(32)], 32);
            }
        }
        Ok(Status::Partial) => {
            // đã xử lý ở trên
        }
    }
}

// ── HTTP response handler (HTTP/1.1 và HTTP/2 cleartext) ─────────────────────
fn handle_response(event: &Event, source: &str, debug: bool) {
    let data = &event.data;
    let len  = effective_len(data);
    if len < 5 { return; }

    // HTTP/2 response frame qua ssl_read
    if &data[..4] == b"HTTP" && data[4] == b'/' && len > 6 && data[5] == b'2' {
        // HTTP/2 cleartext response — rất hiếm, thường là binary
        // Thử parse như HTTP/1.1 trước
    }

    // Tìm "HTTP/" trong buffer (có thể có prefix rác)
    let start = data[..len].windows(5)
        .position(|w| w == b"HTTP/")
        .unwrap_or(0);
    let payload = &data[start..len];

    let mut headers = [httparse::EMPTY_HEADER; 64];
    let mut res     = httparse::Response::new(&mut headers);

    match res.parse(payload) {
        Ok(Status::Complete(_)) | Ok(Status::Partial) => {
            let code    = res.code.unwrap_or(0);
            let reason  = res.reason.unwrap_or("");
            let version = res.version.unwrap_or(0);

            let mut content_type   = String::new();
            let mut content_length = String::new();
            let mut server         = String::new();
            let mut transfer_enc   = String::new();

            for h in res.headers.iter() {
                let val = std::str::from_utf8(h.value).unwrap_or("").to_string();
                match h.name.to_lowercase().as_str() {
                    "content-type"      => content_type   = val,
                    "content-length"    => content_length = val,
                    "server"            => server         = val,
                    "transfer-encoding" => transfer_enc   = val,
                    _ => {}
                }
            }

            println!("[{}][H{}] ── RESPONSE ─────────────────────────────────────",
                     source, version);
            println!("  {} {} {}", code, reason, if !server.is_empty() {
                format!("(server: {})", server) } else { String::new() });

            if !content_type.is_empty() {
                println!("  content-type: {}", content_type);
            }
            if !content_length.is_empty() {
                println!("  content-length: {}", content_length);
            }
            if !transfer_enc.is_empty() {
                println!("  transfer-encoding: {}", transfer_enc);
            }

            // Body
            if let Some(pos) = payload.windows(4).position(|w| w == b"\r\n\r\n") {
                let raw  = &payload[pos + 4..];
                let blen = effective_len(raw);
                if blen > 0 {
                    match std::str::from_utf8(&raw[..blen]) {
                        Ok(text) => {
                            let t = text.trim_matches('\0');
                            if !t.is_empty() {
                                let preview = if t.len() > 512 {
                                    format!("{}...(truncated {} chars)", &t[..512], t.len())
                                } else {
                                    t.to_string()
                                };
                                println!("  body: {}", preview);
                            }
                        }
                        Err(_) => {
                            println!("  body: [binary {}B]", blen);
                            if debug { hex_dump(&raw[..blen.min(64)], 64); }
                        }
                    }
                }
            }

            if debug {
                println!("  [raw]");
                hex_dump(payload, 128);
            }
        }
        Err(e) => {
            // Có thể là HTTP/2 binary — thử parse frame
            if len >= 9 {
                if let Some(frame) = parse_h2_frame(&data[..len]) {
                    println!(
                        "[{}][H2] ── RESPONSE FRAME ─ {} stream={} payload={}B",
                        source, h2_frame_type_name(frame.frame_type),
                        frame.stream_id, frame.payload.len()
                    );
                    if frame.frame_type == H2_FRAME_DATA && !frame.payload.is_empty() {
                        match std::str::from_utf8(frame.payload) {
                            Ok(text) => {
                                let t = text.trim_matches('\0');
                                if !t.is_empty() {
                                    println!("  body: {}", &t[..t.len().min(512)]);
                                }
                            }
                            Err(_) => {
                                println!("  [binary payload]");
                                if debug { hex_dump(frame.payload, 64); }
                            }
                        }
                    }
                    return;
                }
            }
            if debug {
                println!("[{}] response parse error: {:?}", source, e);
                hex_dump(&data[..len.min(32)], 32);
            }
        }
        _ => {}
    }
}

// ── Main ──────────────────────────────────────────────────────────────────────
#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {

    let client = create_client();
    let result: u8 = client
        .query("SELECT 1")
        .fetch_one()
        .await?;

    init_db(&client).await.expect("TODO: panic message");

    println!("Connected: {}", result);

    let opt = Opt::parse();
    env_logger::init();

    let mut bpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/kprobetcp"
    )))?;

    // Logger
    match EbpfLogger::init(&mut bpf) {
        Err(e) => warn!("eBPF logger init failed: {e}"),
        Ok(logger) => {
            let mut logger = AsyncFd::with_interest(logger, tokio::io::Interest::READABLE)?;
            tokio::task::spawn(async move {
                loop {
                    let mut g = logger.readable_mut().await.unwrap();
                    g.get_inner_mut().flush();
                    g.clear_ready();
                }
            });
        }
    }

    // ── KProbe ────────────────────────────────────────────────────────────────
    println!("Loading kprobes...");
    {
        let p: &mut KProbe = bpf.program_mut("kprobetcp").unwrap().try_into()?;
        p.load()?;
        p.attach("tcp_connect", 0)?;
        println!("  ✓ kprobe tcp_connect");
    }
    {
        let p: &mut KProbe = bpf.program_mut("tcp_sendmsg").unwrap().try_into()?;
        p.load()?;
        p.attach("tcp_sendmsg", 0)?;
        println!("  ✓ kprobe tcp_sendmsg");
    }
    {
        let p: &mut KProbe = bpf.program_mut("kprobe_skb_copy_datagram_iter").unwrap().try_into()?;
        p.load()?;
        p.attach("skb_copy_datagram_iter", 0)?;
        println!("  ✓ kprobe skb_copy_datagram_iter");
    }

    // ── UProbe: load ──────────────────────────────────────────────────────────
    println!("Loading uprobes...");
    load_uprobe(&mut bpf, "ssl_write");
    load_uprobe(&mut bpf, "ssl_read_entry");
    load_uprobe(&mut bpf, "ssl_read");

    // ── Attach SSL libs ───────────────────────────────────────────────────────
    let pid      = opt.pid;
    let ssl_libs = find_ssl_libs();

    if ssl_libs.is_empty() {
        warn!("No SSL libs found — HTTPS monitoring disabled");
    } else {
        println!("Found {} SSL lib(s):", ssl_libs.len());
        for lib in &ssl_libs {
            if !lib.contains("libssl") { continue; }
            println!("  -> {}", lib);
            attach_uprobe(&mut bpf, "ssl_write",      "SSL_write", lib, pid, "uprobe   ");
            attach_uprobe(&mut bpf, "ssl_read_entry", "SSL_read",  lib, pid, "uprobe   ");
            attach_uprobe(&mut bpf, "ssl_read",       "SSL_read",  lib, pid, "uretprobe");
        }
    }

    // ── Verify uprobes ────────────────────────────────────────────────────────
    if let Ok(events) = std::fs::read_to_string("/sys/kernel/debug/tracing/uprobe_events") {
        let count = events.lines().count();
        println!("uprobe_events registered: {} entries", count);
        if count == 0 {
            println!("  WARNING: no uprobes — check permissions or kernel support");
        }
    }

    println!();
    println!("╔══════════════════════════════════════════════════════╗");
    println!("║          HTTP/HTTPS monitor — listening...           ║");
    println!("║  HTTP  : tcp_sendmsg + skb_copy_datagram_iter        ║");
    println!("║  HTTPS : SSL_write / SSL_read  (H1 + H2)             ║");
    if let Some(p) = pid { println!("║  PID   : {:<44}║", p); }
    if opt.debug  { println!("║  Mode  : DEBUG (hex dumps enabled)                  ║"); }
    println!("╚══════════════════════════════════════════════════════╝");
    println!();

    // ── Ring buffers ──────────────────────────────────────────────────────────
    let req_buf = RingBuf::try_from(
        bpf.map("RING_BUF_REQ")
            .ok_or_else(|| anyhow::anyhow!("RING_BUF_REQ not found"))?,
    )?;
    let mut req_fd = AsyncFd::new(req_buf)?;

    let res_buf = RingBuf::try_from(
        bpf.map("RING_BUF_RES")
            .ok_or_else(|| anyhow::anyhow!("RING_BUF_RES not found"))?,
    )?;
    let mut res_fd = AsyncFd::new(res_buf)?;

    let debug   = opt.debug;
    let h2_only = opt.h2_only;

    loop {
        tokio::select! {
            _ = signal::ctrl_c() => {
                println!("\nExiting...");
                break;
            }

            // ── REQUEST ring ──────────────────────────────────────────────────
            guard = req_fd.readable_mut() => {
                let mut guard = guard?;
                let rb = guard.get_inner_mut();

                while let Some(item) = rb.next() {
                    let data = &*item;
                    if data.len() < mem::size_of::<Event>() { continue; }

                    let event = unsafe {
                        std::ptr::read_unaligned(data.as_ptr() as *const Event)
                    };

                    let source = if event.des_port == 443 || event.src_port == 443 {
                        "HTTPS"
                    } else {
                        "HTTP"
                    };

                    // Phân loại và route
                    let method = event.method;

                    if method == METHOD_H2_PREFACE {
                        // HTTP/2 preface — bỏ qua, chỉ in ở debug
                        if debug {
                            println!("[{}][H2] CLIENT PREFACE", source);
                        }
                        continue;
                    }

                    if is_h2_frame_event(method) {
                        let frame_type = method & 0x0F;
                        // Chỉ skip control frames thực sự không có data hữu ích
                        // KHÔNG skip DATA (0x00) và HEADERS (0x01)
                        if !debug && matches!(frame_type,
                            H2_FRAME_SETTINGS | H2_FRAME_PING |
                            H2_FRAME_WINDOW_UPDATE | H2_FRAME_PRIORITY |
                            H2_FRAME_RST_STREAM | H2_FRAME_GOAWAY
                        ) {
                            continue;
                        }
                        handle_h2_event(&event, source, debug);
                        continue;
                    }

                    if is_h1_method(method) {
                        if !h2_only {
                            handle_h1_request(&event, source, debug);
                        }
                        continue;
                    }

                    // method = UNKNOWN nhưng có data → thử parse
                    let len = effective_len(&event.data);
                    if len >= 4 {
                        let d = &event.data;
                        if d[..4] == *b"GET " || d[..4] == *b"POST"
                            || d[..4] == *b"PUT " || d[..4] == *b"DELE"
                        {
                            // HTTP/1.1 text method
                            if !h2_only {
                                handle_h1_request(&event, source, debug);
                            }
                        } else if len >= 9 {
                            // Thử parse như HTTP/2 frame
                            handle_h2_event(&event, source, debug);
                        } else if debug {
                            println!("[{}] unrecognized request method=0x{:02x} len={}",
                                source, method, len);
                            hex_dump(&event.data[..len.min(16)], 16);
                        }
                    }
                }

                guard.clear_ready();
            }

            // ── RESPONSE ring ─────────────────────────────────────────────────
            guard = res_fd.readable_mut() => {
                let mut guard = guard?;
                let rb = guard.get_inner_mut();

                while let Some(item) = rb.next() {
                    let data = &*item;
                    if data.len() < mem::size_of::<Event>() { continue; }

                    let event = unsafe {
                        std::ptr::read_unaligned(data.as_ptr() as *const Event)
                    };

                    let source = if event.src_port == 443 || event.des_port == 443 {
                        "HTTPS"
                    } else {
                        "HTTP"
                    };

                    if !h2_only {
                        handle_response(&event, source, debug);
                    }
                }

                guard.clear_ready();
            }
        }
    }

    Ok(())
}