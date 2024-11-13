use std::{
    error::Error,
    net::{Ipv4Addr, Ipv6Addr},
    str::FromStr,
};

use chrono::{DateTime, Local};
use sqlx::SqlitePool;

use super::{
    auxiliaries::CResult,
    questions_and_records::{QueryType, Record},
};

#[derive(Debug, sqlx::FromRow, Clone)]
pub struct CachedRecord {
    pub id: u32,
    pub address: Option<String>,
    pub host: Option<String>,
    pub priority: Option<u16>,
    pub domain: String,
    pub expiration_date: DateTime<Local>,
    pub ttl: u32,
    pub record_type: u16,
}

impl CachedRecord {
    /// # `is_valid`
    ///
    /// Returns true if the record isn't expired,
    /// false otherwise.
    pub fn is_valid(&self) -> bool {
        let now = Local::now();
        if self.expiration_date >= now {
            return true;
        }
        false
    }

    /// # `record_from_cache`
    ///
    /// This method returns a `Result` that may contain a `Record` ready
    /// to be inserted into a `Packet`.
    /// This method consumes the `CachedRecord` instance.
    /// If an error is returned from this method it means that we have records
    /// in our cache that are wrongly formatted, meaning we have a serious problem.
    pub fn record_from_cache(&self) -> Result<Record, Box<dyn Error>> {
        let record_type = QueryType::from_num(self.record_type);
        match record_type {
            QueryType::A => {
                let raw_addr = match &self.address {
                    Some(ra) => ra,
                    None => {
                        return Err("Some records haven't been stored correctly".into());
                    }
                };
                let addr = match Ipv4Addr::from_str(raw_addr) {
                    Ok(a) => a,
                    Err(e) => {
                        return Err(e.into());
                    }
                };
                return Ok(Record::A {
                    domain: self.domain.clone(),
                    addr,
                    ttl: self.ttl,
                });
            }
            QueryType::CNAME => {
                let host = match &self.host {
                    Some(h) => h.clone(),
                    None => {
                        return Err("Some records haven't been stored correctly".into());
                    }
                };
                return Ok(Record::CNAME {
                    domain: self.domain.clone(),
                    host,
                    ttl: self.ttl,
                });
            }
            QueryType::MX => {
                let host = match &self.host {
                    Some(h) => h,
                    None => {
                        return Err("Some records haven't been stored correctly".into());
                    }
                };
                let priority = match self.priority {
                    Some(p) => p,
                    None => {
                        return Err("Some records haven't been stored correctly".into());
                    }
                };
                return Ok(Record::MX {
                    domain: self.domain.clone(),
                    priority,
                    host: host.clone(),
                    ttl: self.ttl,
                });
            }
            QueryType::AAAA => {
                let raw_addr = match &self.address {
                    Some(ra) => ra,
                    None => {
                        return Err("Some records haven't been stored correctly".into());
                    }
                };
                let addr = match Ipv6Addr::from_str(raw_addr) {
                    Ok(a) => a,
                    Err(e) => {
                        return Err(e.into());
                    }
                };
                return Ok(Record::AAAA {
                    domain: self.domain.clone(),
                    addr,
                    ttl: self.ttl,
                });
            }
            _other => {
                return Err("This should not happen.".into());
            }
        };
    }

    /// `Delete From DB`
    ///
    /// Deletes the cached record from the database
    #[tracing::instrument(
        "Deleting entry from the cache database."
        skip(self, db_pool)
        fields(
            domain_name = self.domain,
        )
    )]
    pub async fn delete_from_db(&self, db_pool: &SqlitePool) -> CResult<()> {
        match sqlx::query(r#"DELETE FROM entries WHERE (id = $1)"#)
            .bind(self.id)
            .execute(db_pool)
            .await
        {
            Ok(_) => {
                return Ok(());
            }
            Err(e) => {
                // If this variant is found it means we have incorrect
                // data in our chache
                return Err(e.into());
            }
        }
    }
}
