use std::error::Error;
use clickhouse::Client;

pub fn create_client() -> Client {
    Client::default()
        .with_url("http://localhost:8123")
        .with_user("admin")
        .with_password("admin123")
}
pub async fn init_db(client: &Client) -> Result<(), Box<dyn Error>> {
    // Tạo database
    client
        .query("CREATE DATABASE IF NOT EXISTS koko")
        .execute()
        .await?;

    // Tạo table
    client
        .query(
            "
            CREATE TABLE IF NOT EXISTS koko.events (
                timestamp   DateTime,
                src_ip      String,
                src_port    UInt16,
                dst_ip      String,
                dst_port    UInt16,
                method      LowCardinality(String),
                path        String,
                status      UInt16,
                protocol    LowCardinality(String),
                user_agent  String,
                latency_ms  UInt32,
                bytes_in    UInt32,
                bytes_out   UInt32
            )
            ENGINE = MergeTree()
            PARTITION BY toYYYYMM(timestamp)
            ORDER BY (timestamp, src_ip, dst_ip)
            ",
        )
        .execute()
        .await?;

    Ok(())
}