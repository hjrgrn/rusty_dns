use std::{error::Error, fs};

use dns::{
    configuration::{get_settings, Settings},
    run,
    structs::{
        buffer::BytePacketBuffer,
        header::ResultCode,
        packet::Packet,
        questions_and_records::{QueryType, Question},
    },
    telemetry::{get_subscriber, init_subscriber},
};
use once_cell::sync::Lazy;
use sqlx::{sqlite::SqliteConnectOptions, SqlitePool};
use tokio::{net::UdpSocket, select, task::JoinHandle};
use tokio_util::sync::CancellationToken;

/// Ensures that the `tracing` stack is only initialised once using `once_cell`
static TRACING: Lazy<()> = Lazy::new(|| {
    let default_filter_level = "info".to_string();
    let subscriber_name = "test".to_string();
    // NOTE: We cannot assign the output of `get_subscriber` to a variable based on the
    // value TEST_LOG because the sink is part of the type returned by `get_subscriber`,
    // therefore they are not the same type.
    // We could work around it, but this is the most straight forward way of moving forward.
    if std::env::var("TEST_LOG").is_ok() {
        let subscriber = get_subscriber(subscriber_name, default_filter_level, std::io::stdout);
        init_subscriber(subscriber);
    } else {
        let subscriber = get_subscriber(subscriber_name, default_filter_level, std::io::sink);
        init_subscriber(subscriber);
    }
});

/// # `TestApp`
///
/// Contains the informations needed to interact with the spawned test server.
pub struct TestApp {
    /// `addr` is the address of the test server, it can be passed to
    /// `(std|tokio)::net::UdpSocket.connect` in order to connect to it.
    pub addr: String,
    /// `cancellation_token` is needed for graceful shutdown,
    /// `TestApp.cancellation_token.cancel` needs to be called at
    /// the end of the test function.
    pub cancellation_token: CancellationToken,
    /// `handle` is needed for the graceful shutdown, `TestApp.handle.await`
    /// needs to be called after having called `TestApp.cancellation_token.cancel`.
    pub handle: JoinHandle<()>,
}

/// # `spawn_app`
///
/// Spawns the server application in the background,
/// returns `TestApp` or an error stating what went wrong.
/// Perform necessary cleanup if something went wrong.
/// TODO: comments, review, refactoring, then acknoledge the tests that don't work
pub async fn spawn_app() -> Result<TestApp, Box<dyn Error>> {
    // The first time `initialize` is invoked the code `TRACING` is executed.
    // All other invocations will instead skip execution.
    Lazy::force(&TRACING);
    // Obtain settings
    let mut settings = get_settings()?;
    // Setting up the socket
    let server_sock = UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("Failed to bind to port.");
    let port = server_sock.local_addr().unwrap().port();
    let addr = format!("127.0.0.1:{}", port);
    // Setting up the database
    settings.set_test_db();
    let db_options = SqliteConnectOptions::new()
        .filename(&settings.get_db_path())
        .create_if_missing(true);
    let db_pool = match SqlitePool::connect_with(db_options).await {
        Ok(dbp) => dbp,
        Err(e) => {
            match fs::remove_file(&settings.get_db_path()) {
                Ok(_) => {}
                Err(e) => {
                    tracing::warn!("Failed to remove the temporary database:\n{}", e);
                }
            }
            return Err(Box::new(e));
        }
    };
    match sqlx::migrate!("./migrations").run(&db_pool).await {
        Ok(_) => {}
        Err(e) => {
            db_pool.close().await;
            match fs::remove_file(&settings.get_db_path()) {
                Ok(_) => {}
                Err(e) => {
                    tracing::warn!("Failed to remove the temporary database:\n{}", e);
                }
            }
            return Err(Box::new(e));
        }
    };
    // Setting up the cancellation token
    let cancellation_token = CancellationToken::new();
    // Spawning the test server and setting up the handle
    let handle = tokio::spawn(switch(
        db_pool,
        server_sock,
        settings,
        cancellation_token.clone(),
    ));
    Ok(TestApp {
        addr,
        cancellation_token,
        handle,
    })
}

/// # `switch`
///
/// This function allows for a gracefull shutdown in a test enviroment.
async fn switch(
    db_pool: SqlitePool,
    sock: UdpSocket,
    settings: Settings,
    token: CancellationToken,
) {
    let db_path = settings.get_db_path();
    select! {
        _ = token.cancelled() => {
            db_pool.close().await;
            fs::remove_file(db_path).expect("Failed to remove temporary db.");
        }
        _ = run(sock, settings, db_pool.clone()) => {}
    }
}

/// # `get_query_packet`
///
/// Get a properly configured query packet, ready to be turned into a buffer
pub fn get_query_packet(id: u16, domain: &str) -> Packet {
    // generate query packet
    let mut query_packet = Packet::new();
    query_packet.header.id = id;
    query_packet.header.recursion_desired = true;
    query_packet.header.truncated_message = false;
    query_packet.header.authoritative_answer = false;
    query_packet.header.opcode = 0;
    query_packet.header.response = false;
    query_packet.header.rescode = ResultCode::NOERROR;
    query_packet.header.checking_disabled = false;
    query_packet.header.authed_data = true;
    query_packet.header.z = false;
    query_packet.header.recursion_available = false;
    query_packet.header.questions = 1;
    query_packet.header.answers = 0;
    query_packet.header.authoritative_entries = 0;
    query_packet.header.resource_entries = 0;
    query_packet
        .questions
        .push(Question::new(domain.to_owned(), QueryType::A));
    query_packet
}

/// # `get_response_packet`
///
/// Send the provided query buffer to the clinet socket and
/// awaits for a properly formatted dns packet in response.
/// Returns the response.
pub async fn get_response_packet(
    client_sock: UdpSocket,
    mut query_buffer: &[u8],
) -> Result<Packet, Box<dyn Error>> {
    // send packet
    client_sock.send(&mut query_buffer).await?;

    // obtaining the response
    let mut response_buffer = BytePacketBuffer::new();
    client_sock.recv_from(&mut response_buffer.buf).await?;
    let response_packet = Packet::from_buffer(&mut response_buffer)?;
    Ok(response_packet)
}

/// # `get_client_sock`
///
/// Opens a client socket with a random port number,
/// connects it to the provided address, returns
/// the client socket.
/// NOTE: This function doesn't return a `Result` but it panics the test
/// that calls it if something goes
/// wrong.
pub async fn get_client_sock(addr: &str) -> UdpSocket {
    let client_sock = UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("Failed to create the client socket.");
    client_sock
        .connect(addr)
        .await
        .expect("Fail to connect the client socket to the server socket");
    client_sock
}
