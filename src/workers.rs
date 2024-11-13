use std::{
    net::{Ipv4Addr, SocketAddr},
    sync::Arc,
};

use helpers::{cached_compose_response, compose_response, goofy_workaround};
use sqlx::SqlitePool;
use tokio::net::UdpSocket;

use crate::structs::{buffer::BytePacketBuffer, header::ResultCode, packet::Packet};

mod helpers;

/// # `query_handler`
///
/// Handles a single incoming query.
#[tracing::instrument(
    name = "Responding to a query",
    skip(sock, req_buffer, src),
    fields(
        address = %src
    )
)]
pub async fn query_handler(
    sock: Arc<UdpSocket>,
    mut req_buffer: BytePacketBuffer,
    src: SocketAddr,
    root_addr: Ipv4Addr,
    db_pool: SqlitePool,
) {
    let mut success = true;
    // Parse raw bytes into a structured object
    let mut request = match Packet::from_buffer(&mut req_buffer) {
        Ok(x) => x,
        Err(e) => {
            tracing::info!(
                "Unable to parse the packet received from {} becouse of: {}",
                src,
                e
            );
            // NOTE: we cannot await a future inside here, that's why goofy_workaround
            success = false;
            Packet::new()
        }
    };
    if !success {
        // TODO: rework goofy goofy_workaround
        goofy_workaround(sock, src, 0, ResultCode::FORMERR).await;
        return;
    }

    // packet inside of a block or even inside compose_response
    // NOTE: google's dns ignores the packets that have the header's response field
    // equal to true
    if request.header.response {
        return;
    }
    let mut response = if !request.header.recursion_desired {
        cached_compose_response(&mut request, &db_pool).await
    } else {
        compose_response(&mut request, root_addr, db_pool).await
    };

    let mut res_buffer = BytePacketBuffer::new();

    match response.write(&mut res_buffer) {
        Ok(_) => {}
        Err(e) => {
            tracing::info!("Unable to fullfil a query from {} becouse of: {}", src, e);
            success = false;
        }
    };
    if !success {
        goofy_workaround(sock, src, request.header.id, ResultCode::SERVFAIL).await;
        return;
    }

    let len = res_buffer.pos();
    // NOTE: expecially goofy workaround
    let data = [0];
    let data_ref = match res_buffer.get_range(0, len) {
        Ok(d) => d,
        Err(e) => {
            tracing::info!("Failed to respond to the query:\n{}", e);
            success = false;
            &data
        }
    };
    if !success {
        goofy_workaround(sock, src, request.header.id, ResultCode::SERVFAIL).await;
        return;
    }

    match sock.send_to(data_ref, src).await {
        Ok(_) => {}
        Err(e) => {
            success = false;
            tracing::info!("Failed to respond to the query:\n{}", e);
        }
    };
    if !success {
        goofy_workaround(sock, src, request.header.id, ResultCode::SERVFAIL).await;
    }
}
