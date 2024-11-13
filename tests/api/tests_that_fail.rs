use std::time::Duration;

use dns::structs::{buffer::BytePacketBuffer, header::ResultCode};
use tokio::{select, time::sleep};

use crate::helpers::{get_client_sock, get_query_packet, get_response_packet, spawn_app};

/// # `sending_a_non_properly_formatted_response_field`
///
/// Sends a packet that has response header's field turned
/// to true just gets ignored.
/// TODO: we should write multiple wrong packets here and send all of them
/// instead of creating a single function for every single case
#[tokio::test]
async fn sending_a_non_properly_formatted_response_field() {
    // arrangement
    let test_app = spawn_app().await.expect("Failed to spawn the app.");
    let client_sock = get_client_sock(&test_app.addr).await;

    // preparing packet
    // query parameters:
    let id = 999;
    let query_domain = "wiki.archlinux.org";
    // generate buffer
    let mut query_packet = get_query_packet(id, query_domain);
    // wrong header's field
    query_packet.header.response = true;
    // generate query buffer
    let mut query_buffer = BytePacketBuffer::new();
    query_packet
        .write(&mut query_buffer)
        .expect("Failed to generate the query buffer.");
    // send packet and obtaining nothing in response
    let responded = select! {
        _ = get_response_packet(client_sock, &query_buffer.buf) => {
            true
        }
        _ = sleep(Duration::from_secs(1)) => {
            false
        }
    };

    // asserts
    assert!(!responded);

    test_app.cancellation_token.cancel();
    let _ = test_app.handle.await;
}

/// # `recursion_desired_false`
///
/// In this test we don't have a valid cached record for the query and so a packet with
/// `ResultCode::SERVFAIL` should be returned.
#[tokio::test]
async fn recursion_desired_false_fails_if_no_cached_entry() {
    // arrangement
    let test_app = spawn_app().await.expect("Failed to spawn the app.");
    let client_sock = get_client_sock(&test_app.addr).await;

    // preparing packet
    // query parameters:
    let id = 999;
    let query_domain = "wiki.archlinux.org";
    // generate buffer
    let mut query_packet = get_query_packet(id, query_domain);
    // erroneous field
    query_packet.header.recursion_desired = false;
    // generate query buffer
    let mut query_buffer = BytePacketBuffer::new();
    query_packet
        .write(&mut query_buffer)
        .expect("Failed to generate the query buffer.");
    // send packet and obtaining the response
    let response_packet = get_response_packet(client_sock, &query_buffer.buf)
        .await
        .expect("Failed to get the response packet");

    // asserts
    // the id is the same of the one from the query
    assert_eq!(id, response_packet.header.id);
    // check if it is a response packet
    assert!(response_packet.header.response);
    // check if we have SERVFAIL error, default behaviour
    assert_eq!(response_packet.header.rescode, ResultCode::SERVFAIL);
    // check if we have no answers
    assert_eq!(response_packet.header.answers, 0);

    // Cleanup
    test_app.cancellation_token.cancel();
    let _ = test_app.handle.await;
}

/// # `send_unsctructured_too_short_packet`
///
/// Sends an unstructured packet that is too short, responds with `ResultCode::FORMERR`.
#[tokio::test]
async fn send_unsctructured_too_short_packet() {
    // arrangement
    let test_app = spawn_app().await.expect("Failed to spawn the app.");
    let client_sock = get_client_sock(&test_app.addr).await;

    // preparing packet
    let query_buffer = [0; 1];
    let response_packet = get_response_packet(client_sock, &query_buffer)
        .await
        .expect("Failed to generate the query buffer.");

    // assert
    assert_eq!(response_packet.header.rescode, ResultCode::FORMERR);

    // Cleanup
    test_app.cancellation_token.cancel();
    let _ = test_app.handle.await;
}

/// # `send_unsctructured_too_long_packet`
///
/// Sends an unstructured packet that is too long, responds with `ResultCode::FORMERR`.
#[tokio::test]
async fn send_unsctructured_too_long_packet() {
    // arrangement
    let test_app = spawn_app().await.expect("Failed to spawn the app.");
    let client_sock = get_client_sock(&test_app.addr).await;

    // preparing packet
    let query_buffer = [0; 600];
    let response_packet = get_response_packet(client_sock, &query_buffer)
        .await
        .expect("Failed to generate the query buffer.");

    // assert
    assert_eq!(response_packet.header.rescode, ResultCode::FORMERR);

    // Cleanup
    test_app.cancellation_token.cancel();
    let _ = test_app.handle.await;
}
