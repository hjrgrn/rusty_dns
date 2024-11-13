use core::panic;

use dns::structs::{buffer::BytePacketBuffer, header::ResultCode};

use crate::helpers::{get_client_sock, get_query_packet, get_response_packet, spawn_app};

#[tokio::test]
/// # `sending_a_properly_formatted_query`
///
/// Sending a properly formatted query returns a correct response.
async fn sending_a_properly_formatted_query() {
    // arrangement
    let test_app = spawn_app().await.expect("Failed to spawn the app.");
    let client_sock = get_client_sock(&test_app.addr).await;

    // preparing packet
    // query parameters:
    let id = 999;
    let query_domain = "wiki.archlinux.org";
    // generate buffer
    let mut query_packet = get_query_packet(id, query_domain);
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
    // check if we have no errors
    assert_eq!(response_packet.header.rescode, ResultCode::NOERROR);
    // check if we have an answer
    assert!(response_packet.header.answers > 0);
    // check the actual answer
    match response_packet.answers[0].clone() {
        dns::structs::questions_and_records::Record::A {
            domain,
            addr: _,
            ttl: _,
        } => {
            // domain of the answer is the same as the domain
            // of the response
            assert_eq!(domain, query_domain.to_owned());
        }
        _ => {
            panic!();
        }
    };

    // Graceful shutdown
    test_app.cancellation_token.cancel();
    let _ = test_app.handle.await;
}

/// # `recursion_desired_false_succeeds`
///
/// If the client passes the field "recursion desired" with the value false we are not allowed to
/// send a response unless said response has been previously cached, or we are an autoritative
/// server (we are not).
/// This tests ensures that the resource required is cached before asking for it.
#[tokio::test]
async fn recursion_desired_false_succeeds() {
    // arrangement
    let test_app = spawn_app().await.expect("Failed to spawn the app.");
    let client_sock = get_client_sock(&test_app.addr).await;

    // Send a packet in orderd to obtain the result and store it in the chace
    // query parameters:
    let id = 999;
    let query_domain = "wiki.archlinux.org";
    // generate buffer
    let mut query_packet = get_query_packet(id, query_domain);
    // generate query buffer
    let mut query_buffer = BytePacketBuffer::new();
    query_packet
        .write(&mut query_buffer)
        .expect("Failed to generate the query buffer.");
    // send packet and obtaining the response
    let response_packet = get_response_packet(client_sock, &query_buffer.buf)
        .await
        .expect("Failed to get the response packet");
    // Assert a correct response packet has returned
    assert_eq!(response_packet.header.rescode, ResultCode::NOERROR);

    // New client sock
    let client_sock = get_client_sock(&test_app.addr).await;
    // Prepare the packet with recursion_desired flag turned to false
    // erroneous field
    query_packet.header.recursion_desired = false;
    // generate query buffer
    let mut query_buffer = BytePacketBuffer::new();
    query_packet
        .write(&mut query_buffer)
        .expect("Failed to generate the query buffer.");
    // send packet and obtaining the response
    let cached_response_packet = get_response_packet(client_sock, &query_buffer.buf)
        .await
        .expect("Failed to get the response packet");
    // the id is the same of the one from the query
    assert_eq!(id, cached_response_packet.header.id);
    // check if it is a response packet
    assert!(cached_response_packet.header.response);
    // check if we have no errors
    assert_eq!(cached_response_packet.header.rescode, ResultCode::NOERROR);
    // check if we have an answer
    assert!(cached_response_packet.header.answers > 0);
    match response_packet.answers[0].clone() {
        dns::structs::questions_and_records::Record::A {
            domain,
            addr,
            ttl: _,
        } => {
            // domain of the answer is the same as the domain
            // of the response
            assert_eq!(domain, query_domain.to_owned());
            match cached_response_packet.answers[0].clone() {
                dns::structs::questions_and_records::Record::A {
                    domain: cached_domain,
                    addr: cached_addr,
                    ttl: _,
                } => {
                    assert_eq!(cached_domain, domain);
                    // cached address is the same address of the address received from the first
                    // response.
                    assert_eq!(cached_addr, addr);
                }
                _ => {
                    panic!();
                }
            }
        }
        _ => {
            panic!();
        }
    };

    // Graceful shutdown
    test_app.cancellation_token.cancel();
    let _ = test_app.handle.await;
}
