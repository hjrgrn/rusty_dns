use std::{env, error::Error, net::Ipv4Addr};

use config::Config;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct Settings {
    local_server: ServerSettings,
    root_server: ServerSettings,
    database: DatabaseSettings,
}

impl Settings {
    pub fn get_local_server_full_domain(&self) -> String {
        self.local_server.get_full_domain()
    }

    pub fn get_root_server_full_domain(&self) -> String {
        self.root_server.get_full_domain()
    }

    pub fn get_local_server_addr(&self) -> Ipv4Addr {
        self.local_server.get_addr()
    }

    pub fn get_root_server_addr(&self) -> Ipv4Addr {
        self.root_server.get_addr()
    }

    pub fn get_db_url(&self) -> String {
        self.database.get_db_url()
    }

    pub fn get_migrations_dir(&self) -> String {
        self.database.get_migrations_dir()
    }

    // # `set_test_db`
    //
    // Genetare a random name for a test database the will be used instead of the name provided in
    // the config.
    pub fn set_test_db(&mut self) {
        self.database.set_test_env();
    }

    /// # `get_db_path`
    ///
    /// Obtains the path to the database file
    pub fn get_db_path(&self) -> String {
        self.database.get_path()
    }
}

#[derive(Debug, Deserialize)]
struct ServerSettings {
    addr: Ipv4Addr,
    port: u16,
}

impl ServerSettings {
    fn get_full_domain(&self) -> String {
        format!("{}:{}", &self.addr, &self.port)
    }
    fn get_addr(&self) -> Ipv4Addr {
        self.addr.clone()
    }
}

#[derive(Debug, Deserialize)]
struct DatabaseSettings {
    path: String,
    migrations_dir: String,
}

impl DatabaseSettings {
    /// # `get_db_url`
    ///
    /// Gives back a fully formatted database path that can be used
    /// as a argument for `sqlx::SqlitePool::connect` and similar.
    fn get_db_url(&self) -> String {
        format!("sqlite://{}", self.path)
    }
    /// # `get_migrations_dir`
    fn get_migrations_dir(&self) -> String {
        self.migrations_dir.clone()
    }
    /// # `set_test_env`
    ///
    /// Creates the name of the test database
    fn set_test_env(&mut self) {
        self.path = format!("instance/{}.sqlite", uuid::Uuid::new_v4());
    }

    /// `get_path`
    ///
    /// Obtains the path to the sqlite database file
    fn get_path(&self) -> String {
        self.path.clone()
    }
}

pub fn get_settings() -> Result<Settings, Box<dyn Error>> {
    let path = env::current_dir()?.join("Configuration.toml");
    let settings = Config::builder()
        .add_source(config::File::from(path))
        .build()?;
    Ok(settings.try_deserialize::<Settings>()?)
}
