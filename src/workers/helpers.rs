use std::net::Ipv4Addr;
use std::str::FromStr;
use std::{net::SocketAddr, sync::Arc};

use sqlx::SqlitePool;
use tokio::net::UdpSocket;

use crate::structs::db_queries::CachedRecord;
use crate::structs::{
    auxiliaries::CResult,
    buffer::BytePacketBuffer,
    header::ResultCode,
    packet::Packet,
    questions_and_records::{QueryType, Question},
};

/// # `lookup`
///
/// Opens a new socket with the server provided and queris it
/// for the name provided, returns the packet if everything went well.
#[tracing::instrument(
    "Inquiring an extername name server",
    skip(qname, qtype, server),
    fields(
        domain_name = qname,
        server_ip = %server.0,
        server_port = server.1
    )
)]
pub async fn lookup(qname: &str, qtype: QueryType, server: (Ipv4Addr, u16)) -> CResult<Packet> {
    // Socket
    let socket = UdpSocket::bind("0.0.0.0:0").await?;

    // Preparing the query packet
    let mut packet = Packet::new();
    // TODO: generate a random value maybe
    packet.header.id = 999;
    packet.header.questions = 1;
    packet.header.recursion_desired = true;
    packet
        .questions
        .push(Question::new(qname.to_string(), qtype));
    let mut req_buffer = BytePacketBuffer::new();
    packet.write(&mut req_buffer)?;

    // Sends the query
    socket
        .send_to(&req_buffer.buf[0..req_buffer.pos()], server)
        .await?;

    // Receiving a response
    let mut res_buffer = BytePacketBuffer::new();
    socket.recv_from(&mut res_buffer.buf).await?;

    Packet::from_buffer(&mut res_buffer)
}

/// `goofy_workaround`
///
/// `query_handler`'s helper function, workaround to the fact
/// that `match` doesn't support awaiting a future inside of one of it's branches.
pub async fn goofy_workaround(sock: Arc<UdpSocket>, src: SocketAddr, id: u16, rescode: ResultCode) {
    let mut res_buffer = match BytePacketBuffer::new_error_packet(rescode, id) {
        Ok(b) => b,
        Err(_) => {
            return;
        }
    };
    let _ = sock.send_to(&mut res_buffer.buf, src).await;
}

/// # `handling_record`, `inquiring`'s helper function
///
/// This function parses a record extracted from the database and check if it is valid.
/// If its valid:
///     - if `inquiring` is searching for a name server it will updates the relative informations
///     - creates the response and returns it
/// else:
///     - deletes the record from the database, returns `None`
/// Handles tarcing.
/// TODO: testing
pub async fn handling_record(
    record: &CachedRecord,
    db_pool: &SqlitePool,
    search_for_qname: &mut bool,
    current_ns: &mut Ipv4Addr,
    currently_quering: &mut String,
    qname: &str,
    current_type: &mut QueryType,
    qtype: &QueryType,
) -> Option<Packet> {
    if record.is_valid() {
        // the stack accordingly
        // record is not expired
        tracing::info!("Found valid record for {} in the cache.", record.domain,);

        // sercing for a dns server, updates with the values found
        if !*search_for_qname {
            *current_ns = match Ipv4Addr::from_str(&record.domain) {
                Ok(ip) => ip,
                Err(e) => {
                    // IDEA: we may want to delete the malformed entry
                    tracing::error!("Incorrect data has been found in the cache database, it's necessary a debug, the server is still capable of responding to requests from the clients without the cache, but the cache is unreliable, wrong data may be served with this configuration, consider disabling the cache database with `-c` flag. Error:\n{}", e);
                    return None;
                }
            };
            *currently_quering = qname.to_string();
            *current_type = *qtype;
            *search_for_qname = true;
            return None;
        }

        let mut response = Packet::new();
        match response.add_cr_to_answers(&record) {
            Ok(_) => {
                return Some(response);
            }
            Err(e) => {
                // If this variant is found it means we have incorrect
                // data in our chache
                tracing::error!("Incorrect data has been found in the cache database, it's necessary a debug, the server is still capable of responding to requests from the clients without the cache, but the cache is unreliable, wrong data may be served with this configuration, consider disabling the cache database with `-c` flag. Error:\n{}", e);
                return None;
            }
        };
    } else {
        match record.delete_from_db(db_pool).await {
            Ok(_) => {
                tracing::info!(
                    "Deleted cached entry for \"{}\" from the database",
                    record.domain
                );
            }
            Err(e) => {
                tracing::error!("I was unable to cancel an entry from the database, the application needs to be shutdown, error:\n{}", e);
            }
        };
        return None;
    }
}

/// # `compose_response`
///
/// `query_handler`'s helper, composes a response packet give a specific request.
pub async fn compose_response(
    request: &mut Packet,
    root_addr: Ipv4Addr,
    db_pool: SqlitePool,
) -> Packet {
    // Composing the packet for the response
    let mut response = Packet::new();
    // Header
    response.header.id = request.header.id;
    response.header.recursion_desired = true;
    response.header.recursion_available = true;
    response.header.response = true;

    // Iterating over  the question section
    if let Some(question) = request.questions.pop() {
        tracing::info!("Received query: {:?}", question);

        // Performing a lookup for every question in the packet received
        if let Ok(result) =
            inquiring(&question.qname, question.qtype, root_addr.clone(), db_pool).await
        {
            response.questions.push(question.clone());
            response.header.rescode = result.header.rescode;

            for rec in result.answers {
                tracing::info!("Answer: {:?}", rec);
                response.answers.push(rec);
            }
            for rec in result.authorities {
                tracing::info!("Authority: {:?}", rec);
                response.authorities.push(rec);
            }
            for rec in result.resources {
                tracing::info!("Resouce: {:?}", rec);
                response.resources.push(rec);
            }
        } else {
            response.header.rescode = ResultCode::SERVFAIL;
        }
    } else {
        response.header.rescode = ResultCode::FORMERR;
    }

    response
}

/// # `inquiring`
///
/// Receives a query name and a type and performes an iterative lookup starting
/// from a root server.
#[tracing::instrument(
    name = "Starting the lookup process"
    skip(qtype, db_pool)
)]
pub async fn inquiring(
    qname: &str,
    qtype: QueryType,
    root_addr: Ipv4Addr,
    db_pool: SqlitePool,
) -> CResult<Packet> {
    // the current name server that we are using to inquire
    let mut current_ns = root_addr;
    // the name we are currently querying, the qname required or
    // a name server.
    let mut currently_quering = qname.to_string();
    // current type of the query.
    let mut current_type = qtype;
    // indicates if `inquiring` is searching for the qname provided or
    // for a name server that may have the required information
    let mut search_for_qname = true;

    // Since it might take an arbitrary number of steps, we enter an unbounded loop.
    loop {
        // query chace database
        // NOTE: `LIMIT 1` improves the performance when using `.fetch_one`
        tracing::info!("Searching the cache database for {}.", currently_quering);
        let res = sqlx::query_as::<_, CachedRecord>(r#"SELECT id, address, host, priority, domain, expiration_date, ttl, record_type FROM entries WHERE (domain = $1) LIMIT 1"#)
            .bind(&currently_quering)
            .fetch_one(&db_pool)
            .await;
        match res {
            Ok(cr) => {
                match handling_record(
                    &cr,
                    &db_pool,
                    &mut search_for_qname,
                    &mut current_ns,
                    &mut currently_quering,
                    &qname,
                    &mut current_type,
                    &qtype,
                )
                .await
                {
                    Some(record) => return Ok(record),
                    None => {}
                }
            }
            Err(e) => {
                tracing::info!("Couldn't find a valid entry in the cache, error:\n{}", e);
            }
        };

        // Query the server
        let server = (current_ns, 53);
        let response = lookup(&currently_quering, current_type, server).await?;
        // We are searching for a dns server
        if !search_for_qname {
            if let Some(record) = response.get_random_a_rec() {
                current_ns = record.register_record(&db_pool).await?;
                // We found a new dns server to query,
                // so we resume querying for the qname
                currently_quering = qname.to_string();
                current_type = qtype;
                search_for_qname = true;
                continue;
            }
        }

        // Entries in the answer section, and no errors, we found the answer.
        if !response.answers.is_empty() && response.header.rescode == ResultCode::NOERROR {
            let record = response.get_random_a_rec().unwrap();
            let _ = record.register_record(&db_pool).await?;
            return Ok(response);
        }

        //`NXDOMAIN` reply, which is the authoritative name servers
        // way of telling us that the name doesn't exist.
        if response.header.rescode == ResultCode::NXDOMAIN {
            return Ok(response);
        }

        // Try to find a new nameserver based on NS and a corresponding A
        // record in the `Additional section`. If this succeeds, we can switch name server
        // and retry the loop.
        if let Some(record) = response.get_resolved_ns(&currently_quering) {
            current_ns = record.register_record(&db_pool).await?;
            continue;
        }

        // We found no useful resources in the `Additional section`,
        // so we stop the search for qname and we search for the ip of ns, we
        // will resume the query for qname once we resolve this one.
        // If no NS records exist, we'll go with what the last server told us.
        currently_quering = match response.get_unresolved_ns(&currently_quering) {
            Some(x) => x.to_string(),
            None => return Ok(response),
        };
        current_type = QueryType::A;
        search_for_qname = false;
        current_ns = root_addr;
    }
}

/// # `cached_compose_response`
///
/// `query_handler`'s helper, composes a response packet give a specific request, obtains data only
/// from the cache.
/// TODO: test
pub async fn cached_compose_response(request: &mut Packet, db_pool: &SqlitePool) -> Packet {
    if let Some(question) = request.questions.pop() {
        tracing::info!("Received query: {:?}", question);
        tracing::info!("Searching the cache database for {}.", &question.qname);
        let res = sqlx::query_as::<_, CachedRecord>(r#"SELECT id, address, host, priority, domain, expiration_date, ttl, record_type FROM entries WHERE (domain = $1) LIMIT 1"#)
                .bind(&question.qname)
                .fetch_all(db_pool)
            .await;

        match res {
            Ok(mut vector) => {
                while let Some(cr) = vector.pop() {
                    if cr.is_valid() {
                        // record is valid
                        tracing::info!("Found valid record for {} in the cache.", &cr.domain,);
                        let mut response = Packet::new();
                        match response.add_cr_to_answers(&cr) {
                            Ok(_) => {
                                response.add_info(
                                    request.header.id,
                                    false,
                                    true,
                                    true,
                                    response.header.rescode,
                                );
                                return response;
                            }
                            Err(e) => {
                                tracing::error!("Incorrect data has been found in the cache database, it's necessary a debug, the server is still capable of responding to requests from the clients without the cache, but the cache is unreliable, wrong data may be served with this configuration, consider disabling the cache database with `-c` flag. Error:\n{}", e);
                                let mut r = Packet::new();
                                r.add_info(
                                    request.header.id,
                                    false,
                                    true,
                                    true,
                                    ResultCode::SERVFAIL,
                                );
                                return r;
                            }
                        }
                    } else {
                        match cr.delete_from_db(db_pool).await {
                            Ok(_) => {
                                tracing::info!(
                                    "Removed expired record for {} from the cache.",
                                    cr.domain
                                );
                            }
                            Err(e) => {
                                tracing::error!("The database has failed to cancel an entry, it's necessary a debug, the server is still capable of responding to requests from the clients without the cache, but the cache is unreliable, wrong data may be served with this configuration, consider disabling the cache database with `-c` flag. Error:\n{}", e);
                            }
                        }
                        let mut r = Packet::new();
                        r.add_info(request.header.id, false, true, true, ResultCode::SERVFAIL);
                        return r;
                    };
                }
                let mut r = Packet::new();
                r.add_info(request.header.id, false, true, true, ResultCode::SERVFAIL);
                return r;
            }
            Err(e) => {
                tracing::info!("Couldn't find a valid entry in the cache, error:\n{}", e);
                let mut r = Packet::new();
                r.add_info(request.header.id, false, true, true, ResultCode::SERVFAIL);
                return r;
            }
        }
    }
    tracing::info!("Received a malformed packet. Responding with a `ResultCode::FORMERR`");
    let mut r = Packet::new();
    r.add_info(request.header.id, false, true, true, ResultCode::FORMERR);
    r
}
