use aya::maps::RingBuf;
use aya::programs::{KProbe, UProbe};
use aya_log::EbpfLogger;
use clap::Parser;
use httparse::Status;
use kprobetcp_common::{HttpEvent, HttpMethod};
use log::{info, warn};
use std::collections::HashSet;
use std::convert::TryFrom;
use std::mem;
use std::os::unix::fs::MetadataExt;
use tokio::io::unix::AsyncFd;
use tokio::signal;

#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long)]
    pid: Option<u32>,
}

// ── Tìm SSL libs từ ldconfig, dedup theo inode ───────────────────────────────
fn find_ssl_libs() -> HashSet<String> {
    let mut libs: HashSet<String> = HashSet::new();
    let mut seen_inodes: HashSet<u64> = HashSet::new();

    let mut try_add = |path: &str| {
        let p = std::path::Path::new(path);
        if !p.exists() {
            return;
        }
        // metadata() tự follow symlink → lấy inode của file thực
        if let Ok(meta) = std::fs::metadata(p) {
            let inode = meta.ino();
            if seen_inodes.insert(inode) {
                // Resolve về canonical path để tránh symlink khác nhau
                let canonical = std::fs::canonicalize(p)
                    .map(|cp| cp.to_string_lossy().to_string())
                    .unwrap_or_else(|_| path.to_string());
                libs.insert(canonical);
            }
        }
    };

    // 1. ldconfig -p
    if let Ok(output) = std::process::Command::new("ldconfig").arg("-p").output() {
        let stdout = String::from_utf8_lossy(&output.stdout);
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

    // 2. Fallback hardcode — inode check sẽ lọc trùng với ldconfig
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

// ── Attach uprobe cho 1 lib ───────────────────────────────────────────────────
fn attach_one(
    prog: &mut UProbe,
    fn_name: &str,
    lib_path: &str,
    pid: Option<u32>,
    label: &str,
) {
    match prog.attach(fn_name, lib_path, pid) {
        Ok(_) => println!("  ✓ {} {} @ {}", label, fn_name, lib_path),
        Err(e) => println!("  ✗ {} {} @ {}: {:?}", label, fn_name, lib_path, e),
    }
}

// ── Parse HTTP response ───────────────────────────────────────────────────────
fn handle_response(data: &[u8], source: &str) {
    let len = data.iter().rposition(|&b| b != 0).map_or(0, |i| i + 1);
    if len < 5 {
        return;
    }
    print!("source: {}", source);

    let start = data[..len]
        .windows(5)
        .position(|w| w == b"HTTP/")
        .unwrap_or(0);

    let payload = &data[start..len];

    let mut headers = [httparse::EMPTY_HEADER; 64];
    let mut res = httparse::Response::new(&mut headers);

    match res.parse(payload) {
        Ok(Status::Complete(_)) | Ok(Status::Partial) => {
            let code = res.code.unwrap_or(0);
            let mut content_type = "";
            let mut content_length = "";

            for h in res.headers.iter() {
                match h.name.to_lowercase().as_str() {
                    "content-type" => content_type = std::str::from_utf8(h.value).unwrap_or(""),
                    "content-length" => {
                        content_length = std::str::from_utf8(h.value).unwrap_or("")
                    }
                    _ => {}
                }
            }

            let body = if let Some(pos) = payload.windows(4).position(|w| w == b"\r\n\r\n") {
                let raw_body = &payload[pos + 4..];
                let body_len = raw_body
                    .iter()
                    .rposition(|&b| b != 0)
                    .map_or(0, |i| i + 1);
                String::from_utf8_lossy(&raw_body[..body_len]).to_string()
            } else {
                String::new()
            };

            println!(
                "[{}] ← {} | content-type: {} | content-length: {}",
                source, code, content_type, content_length
            );

            if !body.is_empty() {
                let preview = if body.len() > 256 {
                    format!("{}...(truncated)", &body[..256])
                } else {
                    body
                };
                println!("  body: {}", preview);
            }
        }
        Err(e) => println!("[{}] parse error: {:?}", source, e),
        _ => {}
    }
}

// ── Parse HTTP request ────────────────────────────────────────────────────────
fn handle_request(event: &HttpEvent, source: &str) {
    let len = event
        .data
        .iter()
        .rposition(|&b| b != 0)
        .map_or(0, |i| i + 1);

    let mut headers = [httparse::EMPTY_HEADER; 64];
    let mut req = httparse::Request::new(&mut headers);

    if req.parse(&event.data[..len]).is_ok() {
        let method = req.method.unwrap_or("?");
        let path = req.path.unwrap_or("?");
        let mut host = "";
        for h in req.headers.iter() {
            if h.name.eq_ignore_ascii_case("Host") {
                host = std::str::from_utf8(h.value).unwrap_or("");
                break;
            }
        }
        println!("[{}] → {} {} {}", source, method, host, path);
    }
}

fn debug_event(event: &HttpEvent, source: &str) {
    println!("=== [{source}] ===");
    println!("  sport:      {}", event.sport);
    println!("  dport:      {}", event.dport);
    println!("  method:     {:?}", HttpMethod::try_from(event.method));
    println!("  is_request: {}", event.is_request);
    println!("  timestamp:  {}", event.timestamp);

    let len = event
        .data
        .iter()
        .position(|&b| b == 0)
        .unwrap_or(event.data.len());
    let body = String::from_utf8_lossy(&event.data[..len]);
    println!("raw item len = {}", event.data.len());
    println!("---data----\n{}", body);
    println!();
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let opt = Opt::parse();
    env_logger::init();

    let mut bpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/kprobetcp"
    )))?;

    match EbpfLogger::init(&mut bpf) {
        Err(e) => warn!("failed to initialize eBPF logger: {e}"),
        Ok(logger) => {
            let mut logger = AsyncFd::with_interest(logger, tokio::io::Interest::READABLE)?;
            tokio::task::spawn(async move {
                loop {
                    let mut guard = logger.readable_mut().await.unwrap();
                    guard.get_inner_mut().flush();
                    guard.clear_ready();
                }
            });
        }
    }

    // ── KProbe ────────────────────────────────────────────────────────────────
    let p: &mut KProbe = bpf.program_mut("kprobetcp").unwrap().try_into()?;
    p.load()?;
    p.attach("tcp_connect", 0)?;

    let p: &mut KProbe = bpf.program_mut("tcp_sendmsg").unwrap().try_into()?;
    p.load()?;
    p.attach("tcp_sendmsg", 0)?;

    let p: &mut KProbe = bpf
        .program_mut("kprobe_skb_copy_datagram_iter")
        .unwrap()
        .try_into()?;
    p.load()?;
    p.attach("skb_copy_datagram_iter", 0)?;

    // ── UProbe: load programs TRƯỚC, attach SAU ───────────────────────────────
    {
        let p: &mut UProbe = bpf.program_mut("ssl_write").unwrap().try_into()?;
        p.load()?;
    }
    {
        let p: &mut UProbe = bpf.program_mut("ssl_read_entry").unwrap().try_into()?;
        p.load()?;
    }
    {
        let p: &mut UProbe = bpf.program_mut("ssl_read").unwrap().try_into()?;
        p.load()?;
    }

    // ── Tìm SSL libs (dedup theo inode) ──────────────────────────────────────
    let ssl_libs = find_ssl_libs();
    let pid = opt.pid;

    if ssl_libs.is_empty() {
        warn!("No SSL libs found — HTTPS monitoring disabled");
    } else {
        println!("Found {} unique SSL lib(s):", ssl_libs.len());

        for lib in &ssl_libs {
            if !lib.contains("libssl") {
                continue; // bỏ qua gnutls vì chưa có program
            }
            println!("  → {}", lib);

            {
                let p: &mut UProbe = bpf.program_mut("ssl_write").unwrap().try_into()?;
                attach_one(p, "SSL_write", lib, pid, "uprobe   ");
            }
            {
                let p: &mut UProbe = bpf.program_mut("ssl_read_entry").unwrap().try_into()?;
                attach_one(p, "SSL_read", lib, pid, "uprobe   ");
            }
            {
                let p: &mut UProbe = bpf.program_mut("ssl_read").unwrap().try_into()?;
                attach_one(p, "SSL_read", lib, pid, "uretprobe");
            }
        }
    }

    // ── Verify uprobe đã register ─────────────────────────────────────────────
    if let Ok(events) =
        std::fs::read_to_string("/sys/kernel/debug/tracing/uprobe_events")
    {
        let count = events.lines().count();
        println!("uprobe_events registered: {} entries", count);
        if count == 0 {
            println!(
                "  WARNING: no uprobes registered — check permissions or kernel support"
            );
        }
    }

    println!("=================================================");
    println!(" HTTP/HTTPS monitor started");
    println!(" HTTP  : kprobe tcp_sendmsg + skb_copy_datagram_iter");
    println!(" HTTPS : uprobe SSL_write / SSL_read");
    println!("=================================================");

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

    loop {
        tokio::select! {
            _ = signal::ctrl_c() => {
                info!("Exiting...");
                break;
            }

            // REQUEST
            guard = req_fd.readable_mut() => {
                let mut guard = guard?;
                let rb = guard.get_inner_mut();
                while let Some(item) = rb.next() {
                    let data = &*item;
                    if data.len() < mem::size_of::<HttpEvent>() {
                        continue;
                    }
                    let event = unsafe {
                        std::ptr::read_unaligned(data.as_ptr() as *const HttpEvent)
                    };
                    let source = if event.dport == 443 || event.sport == 443 {
                        "HTTPS"
                    } else {
                        "HTTP"
                    };

                    debug_event(&event, source);

                    if let Ok(method) = HttpMethod::try_from(event.method) {
                        match method {
                            HttpMethod::GET
                            | HttpMethod::POST
                            | HttpMethod::DELETE
                            | HttpMethod::PUT
                            | HttpMethod::PATCH => handle_request(&event, source),
                            _ => {}
                        }
                    }
                }
                guard.clear_ready();
            }

            // RESPONSE
            guard = res_fd.readable_mut() => {
                let mut guard = guard?;
                let rb = guard.get_inner_mut();
                while let Some(item) = rb.next() {
                    let data = &*item;
                    if data.len() < mem::size_of::<HttpEvent>() {
                        continue;
                    }
                    let event = unsafe {
                        std::ptr::read_unaligned(data.as_ptr() as *const HttpEvent)
                    };
                    let source = if event.sport == 443 || event.dport == 443 {
                        "HTTPS"
                    } else {
                        "HTTP"
                    };
                    handle_response(&event.data, source);
                }
                guard.clear_ready();
            }
        }
    }

    Ok(())
}