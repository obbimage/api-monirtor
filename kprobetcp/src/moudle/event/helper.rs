
pub async fn insert_event(client: &clickhouse::Client, event: &Event) -> Result<(), Box<dyn std::error::Error>> {
    let mut insert = client.insert("koko.events")?;

    insert.write(event).await?;
    insert.end().await?;

    Ok(())
}

pub async fn get_events(client: &clickhouse::Client) -> Result<Vec<Event>, Box<dyn std::error::Error>> {
    let result = client
        .query("SELECT * FROM koko.events LIMIT 10")
        .fetch_all::<Event>()
        .await?;

    Ok(result)
}