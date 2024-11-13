use tracing::{subscriber::set_global_default, Subscriber};
use tracing_bunyan_formatter::{BunyanFormattingLayer, JsonStorageLayer};
use tracing_subscriber::{fmt::MakeWriter, layer::SubscriberExt, EnvFilter, Registry};

/// Compose multiple layesr into a `tracing`'s subscriber
///
/// # Implementation Notes
///
/// We are using `impl Subscriber` as return type to avoid
/// having to spell out the actual type of the returned subscriber,
/// which is indeed quite complex.
/// We need to explicitly call out that the returned subscriber is
/// `Send` and `Sync` to make it possible to pass it to `init_subscriber`
/// later on.
pub fn get_subscriber<Sink>(
    name: String,
    env_filter: String,
    sink: Sink,
) -> impl Subscriber + Send + Sync
where
    // This weired syntax is a higher-ranked trait bound (HRTB)
    // It basically means that `Sink` implements the `MakeWriter`
    // trait for all choices of the lifetime parameter `'a`
    // Check out [nomicon](https://doc.rust-lang.org/nomicon/hrtb.html)
    // for more informations.
    Sink: for<'a> MakeWriter<'a> + Send + Sync + 'static,
{
    // Print all spans at info-level or above if RUST_LOG hasn't been set.
    let env_filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(env_filter));
    let formatting_layer = BunyanFormattingLayer::new(
        name, sink, // Output the formatted span to our sink.
    );

    // The `with` method is provided by `SubscriberExt`, an extension trait for `Subscriber`
    // exposed by `tracing_subscriber`.
    Registry::default()
        .with(env_filter)
        .with(JsonStorageLayer)
        .with(formatting_layer)
}

/// Register a subscriber as global default to process span data
///
/// It should only be called once!
pub fn init_subscriber(subscriber: impl Subscriber + Send + Sync) {
    // `set_global_default` can be used by applications to specify what subscriber should be used
    // to process spans
    set_global_default(subscriber).expect("Failed to set subscriber.");
}
