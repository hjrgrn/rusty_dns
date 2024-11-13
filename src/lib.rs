use std::{io, sync::Arc};

use configuration::Settings;
use sqlx::SqlitePool;
use structs::buffer::BytePacketBuffer;
use tokio::net::UdpSocket;
use workers::query_handler;

pub mod configuration;
pub mod structs;
pub mod telemetry;
pub mod workers;

/// # `run`
///
/// Core Business.
pub async fn run(sock: UdpSocket, settings: Settings, db_pool: SqlitePool) -> io::Result<()> {
    let sock_ref = Arc::new(sock);
    loop {
        let mut req_buffer = BytePacketBuffer::new();
        let (_, src) = match sock_ref.recv_from(&mut req_buffer.buf).await {
            Ok(r) => r,
            Err(e) => {
                tracing::info!("Received a malformed packet: {}", e);
                continue;
            }
        };
        let s = sock_ref.clone();
        tokio::spawn(query_handler(
            s,
            req_buffer,
            src,
            settings.get_root_server_addr(),
            db_pool.clone(),
        ));
    }
}
