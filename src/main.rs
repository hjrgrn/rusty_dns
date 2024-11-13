use std::error::Error;

use dns::{
    configuration::get_settings,
    run,
    telemetry::{get_subscriber, init_subscriber},
};
use sqlx::{sqlite::SqliteConnectOptions, SqlitePool};
use tokio::net::UdpSocket;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let sub = get_subscriber("rusty_dns".into(), "info".into(), std::io::stdout);
    init_subscriber(sub);

    let settings = get_settings()?;

    // Inititalizing the database
    let db_option = SqliteConnectOptions::new()
        .filename(&settings.get_db_path())
        .create_if_missing(true);
    let db_pool = SqlitePool::connect_with(db_option).await?;
    // TODO: integrate configuration
    sqlx::migrate!().run(&db_pool).await?;

    let sock = UdpSocket::bind(&settings.get_local_server_full_domain()).await?;
    run(sock, settings, db_pool).await?;
    Ok(())
}
