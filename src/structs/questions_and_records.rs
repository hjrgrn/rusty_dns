use std::{
    net::{Ipv4Addr, Ipv6Addr},
    time::Duration,
};

use chrono::Local;
use sqlx::SqlitePool;

use super::{auxiliaries::CResult, buffer::BytePacketBuffer};

#[derive(Debug, Clone)]
pub struct Question {
    pub qname: String,
    pub qtype: QueryType,
}

impl Question {
    pub fn new(qname: String, qtype: QueryType) -> Question {
        Question { qname, qtype }
    }

    /// # `read`
    ///
    /// Given a `BytePacketBuffer` this method will try to parse a single question of
    /// a DNS packet, the `BytePacketBuffer` provided will needs to be well formed
    /// and `BytePacketBuffer.pos` needs to be in the correct positon, if something
    /// goes wrong an error is returned.
    pub fn read(&mut self, buffer: &mut BytePacketBuffer) -> CResult<()> {
        buffer.read_qname(&mut self.qname)?;
        self.qtype = QueryType::from_num(buffer.read_u16()?);
        let _ = buffer.read_u16()?; // This is always 1

        Ok(())
    }

    /// # `write`
    ///
    /// Write information present in the instance to the buffer provided.
    /// `BytePacketBuffer.pos` needs to be in the correct positon for it to work.
    pub fn write(&self, buffer: &mut BytePacketBuffer) -> CResult<()> {
        buffer.write_qname(&self.qname)?;

        let typenum = self.qtype.to_num();
        buffer.write_u16(typenum)?;
        buffer.write_u16(1)?;

        Ok(())
    }
}

#[derive(PartialEq, Debug, Eq, Clone, Hash, Copy)]
pub enum QueryType {
    UNKNOWN(u16),
    A,     // 1
    NS,    // 2
    CNAME, // 5
    MX,    // 15
    AAAA,  // 28
}

impl QueryType {
    pub fn from_num(num: u16) -> QueryType {
        match num {
            1 => QueryType::A,
            2 => QueryType::NS,
            5 => QueryType::CNAME,
            15 => QueryType::MX,
            28 => QueryType::AAAA,
            _ => QueryType::UNKNOWN(num),
        }
    }

    pub fn to_num(&self) -> u16 {
        match *self {
            QueryType::UNKNOWN(x) => x,
            QueryType::A => 1,
            QueryType::NS => 2,
            QueryType::CNAME => 5,
            QueryType::MX => 15,
            QueryType::AAAA => 28,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Record {
    UNKNOWN {
        domain: String,
        qtype: u16,
        data_len: u16,
        ttl: u32,
    }, // 0
    A {
        domain: String,
        addr: Ipv4Addr,
        ttl: u32,
    }, // 1
    NS {
        domain: String,
        host: String,
        ttl: u32,
    }, // 2
    CNAME {
        domain: String,
        host: String,
        ttl: u32,
    }, // 5
    MX {
        domain: String,
        priority: u16,
        host: String,
        ttl: u32,
    }, // 15
    AAAA {
        domain: String,
        addr: Ipv6Addr,
        ttl: u32,
    }, // 28
}

impl Record {
    /// `read`
    ///
    /// Given a `BytePacketBuffer` this method will try to parse a single record of
    /// a DNS packet, the `BytePacketBuffer` provided will needs to be well formed
    /// and `BytePacketBuffer.pos` needs to be in the correct positon, if something
    /// goes wrong an error is returned.
    pub fn read(buffer: &mut BytePacketBuffer) -> CResult<Record> {
        let mut domain = String::new();
        buffer.read_qname(&mut domain)?;
        let qtype_num = buffer.read_u16()?;
        let qtype = QueryType::from_num(qtype_num);
        let _ = buffer.read_u16()?;
        let ttl = buffer.read_u32()?;
        let data_len = buffer.read_u16()?;

        match qtype {
            QueryType::A => {
                let raw_addr = buffer.read_u32()?;
                let addr = Ipv4Addr::new(
                    ((raw_addr >> 24) & 0xFF) as u8,
                    ((raw_addr >> 16) & 0xFF) as u8,
                    ((raw_addr >> 8) & 0xFF) as u8,
                    (raw_addr & 0xFF) as u8,
                );
                Ok(Record::A { domain, addr, ttl })
            }
            QueryType::AAAA => {
                let raw_addr1 = buffer.read_u32()?;
                let raw_addr2 = buffer.read_u32()?;
                let raw_addr3 = buffer.read_u32()?;
                let raw_addr4 = buffer.read_u32()?;
                let addr = Ipv6Addr::new(
                    ((raw_addr1 >> 16) & 0xFFFF) as u16,
                    (raw_addr1 & 0xFFFF) as u16,
                    ((raw_addr2 >> 16) & 0xFFFF) as u16,
                    (raw_addr2 & 0xFFFF) as u16,
                    ((raw_addr3 >> 16) & 0xFFFF) as u16,
                    (raw_addr3 & 0xFFFF) as u16,
                    ((raw_addr4 >> 16) & 0xFFFF) as u16,
                    (raw_addr4 & 0xFFFF) as u16,
                );

                Ok(Record::AAAA { domain, addr, ttl })
            }
            QueryType::NS => {
                let mut ns = String::new();
                buffer.read_qname(&mut ns)?;
                Ok(Record::NS {
                    domain,
                    host: ns,
                    ttl,
                })
            }
            QueryType::CNAME => {
                let mut cname = String::new();
                buffer.read_qname(&mut cname)?;
                Ok(Record::CNAME {
                    domain,
                    host: cname,
                    ttl,
                })
            }
            QueryType::MX => {
                let priority = buffer.read_u16()?;
                let mut mx = String::new();
                buffer.read_qname(&mut mx)?;

                Ok(Record::MX {
                    domain,
                    priority,
                    host: mx,
                    ttl,
                })
            }
            QueryType::UNKNOWN(_) => {
                buffer.step(data_len as usize)?;

                Ok(Record::UNKNOWN {
                    domain,
                    qtype: qtype_num,
                    data_len,
                    ttl,
                })
            }
        }
    }

    /// # `write`
    ///
    /// Write information present in the instance to the buffer provided.
    /// `BytePacketBuffer.pos` needs to be in the correct positon for it to work.
    pub fn write(&self, buffer: &mut BytePacketBuffer) -> CResult<usize> {
        let start_pos = buffer.pos();

        match *self {
            Record::A {
                ref domain,
                ref addr,
                ttl,
            } => {
                buffer.write_qname(domain)?;
                buffer.write_u16(QueryType::A.to_num())?;
                buffer.write_u16(1)?;
                buffer.write_u32(ttl)?;
                buffer.write_u16(4)?;

                let octets = addr.octets();
                buffer.write_u8(octets[0])?;
                buffer.write_u8(octets[1])?;
                buffer.write_u8(octets[2])?;
                buffer.write_u8(octets[3])?;
            }
            Record::NS {
                ref domain,
                ref host,
                ttl,
            } => {
                buffer.write_qname(domain)?;
                buffer.write_u16(QueryType::NS.to_num())?;
                buffer.write_u16(1)?;
                buffer.write_u32(ttl)?;

                let pos = buffer.pos();
                buffer.write_u16(0)?;

                buffer.write_qname(host)?;

                let size = buffer.pos() - (pos + 2);
                buffer.set_u16(pos, size as u16)?;
            }
            Record::CNAME {
                ref domain,
                ref host,
                ttl,
            } => {
                buffer.write_qname(domain)?;
                buffer.write_u16(QueryType::CNAME.to_num())?;
                buffer.write_u16(1)?;
                buffer.write_u32(ttl)?;

                let pos = buffer.pos();
                buffer.write_u16(0)?;

                buffer.write_qname(host)?;

                let size = buffer.pos() - (pos + 2);
                buffer.set_u16(pos, size as u16)?;
            }
            Record::MX {
                ref domain,
                priority,
                ref host,
                ttl,
            } => {
                buffer.write_qname(domain)?;
                buffer.write_u16(QueryType::MX.to_num())?;
                buffer.write_u16(1)?;
                buffer.write_u32(ttl)?;

                let pos = buffer.pos();
                buffer.write_u16(0)?;

                buffer.write_u16(priority)?;
                buffer.write_qname(host)?;

                let size = buffer.pos() - (pos + 2);
                buffer.set_u16(pos, size as u16)?;
            }
            Record::AAAA {
                ref domain,
                ref addr,
                ttl,
            } => {
                buffer.write_qname(domain)?;
                buffer.write_u16(QueryType::AAAA.to_num())?;
                buffer.write_u16(1)?;
                buffer.write_u32(ttl)?;
                buffer.write_u16(16)?;

                for octet in &addr.segments() {
                    buffer.write_u16(*octet)?;
                }
            }
            Record::UNKNOWN { .. } => {
                tracing::info!("Skipping record: {:?}", self);
            }
        }

        Ok(buffer.pos() - start_pos)
    }

    /// # `get_ttl`
    ///
    /// Gives me back the time to live field of a record.
    /// NOTE: TTL is a field in a Dns Record that determines how long
    /// a DNS resolver should cache a DNS query before requesting a new one,
    /// and, as a result, how long it takes for record updates to reach end users.
    /// It is expressed in seconds.
    pub fn get_ttl(&self) -> u32 {
        match self {
            Record::UNKNOWN {
                domain: _,
                qtype: _,
                data_len: _,
                ttl,
            } => ttl.to_owned(),
            Record::A {
                domain: _,
                addr: _,
                ttl,
            } => ttl.to_owned(),
            Record::NS {
                domain: _,
                host: _,
                ttl,
            } => ttl.to_owned(),
            Record::CNAME {
                domain: _,
                host: _,
                ttl,
            } => ttl.to_owned(),
            Record::MX {
                domain: _,
                priority: _,
                host: _,
                ttl,
            } => ttl.to_owned(),
            Record::AAAA {
                domain: _,
                addr: _,
                ttl,
            } => ttl.to_owned(),
        }
    }

    /// # `register_record`
    ///
    /// This method registers the record in the cache database.
    #[tracing::instrument(
        name = "Registering a new record in the cache database",
        skip(self, db_pool)
    )]
    pub async fn register_record(&self, db_pool: &SqlitePool) -> CResult<Ipv4Addr> {
        match self {
            // TODO: we need to think about different record types
            Record::A { domain, addr, ttl } => {
                // Using the newly find server as name server
                let expiration_date = Local::now() + Duration::from_secs(*ttl as u64);
                sqlx::query(r#"INSERT INTO entries (address, domain, expiration_date, ttl, record_type) VALUES ($1, $2, $3, $4, $5)"#)
                            .bind(addr.to_string())
                            .bind(domain)
                            .bind(expiration_date)
                            .bind(ttl)
                            .bind(1)
                            .execute(db_pool)
                            .await?;
                tracing::info!("Registerd a new entry for the domain {}", domain);
                return Ok(addr.clone());
            }
            _other => {
                // TODO: if this happens, it means that we have received a malformed packet
                // from one of the servers that we have encoutered, we need to investigate what the
                // correct response is in this situation, for the time being we are going to
                // responsd with a server fail error
                return Err("Expected a A Record from a name server, got something else. Responding to the client with a Server Fail packet.".into());
            }
        }
    }
}
