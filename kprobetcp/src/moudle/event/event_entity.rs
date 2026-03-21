use clickhouse::Row;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, Row)]
pub struct EventEntity {
    pub timestamp: String,     // hoặc chrono::DateTime nếu muốn chuẩn hơn
    pub src_ip: String,
    pub src_port: u16,
    pub dst_ip: String,
    pub dst_port: u16,
    pub method: String,
    pub path: String,
    pub status: u16,
    pub protocol: String,
    pub user_agent: String,
    pub latency_ms: u32,
    pub bytes_in: u32,
    pub bytes_out: u32,
}