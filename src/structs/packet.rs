use std::net::Ipv4Addr;

use super::{
    auxiliaries::CResult,
    buffer::BytePacketBuffer,
    db_queries::CachedRecord,
    header::{Header, ResultCode},
    questions_and_records::{QueryType, Question, Record},
};

#[derive(Debug, Clone)]
pub struct Packet {
    pub header: Header,
    pub questions: Vec<Question>,
    pub answers: Vec<Record>,
    pub authorities: Vec<Record>,
    pub resources: Vec<Record>,
}

impl Packet {
    pub fn new() -> Packet {
        Packet {
            header: Header::new(),
            questions: Vec::new(),
            answers: Vec::new(),
            authorities: Vec::new(),
            resources: Vec::new(),
        }
    }

    /// `Add Info`
    ///
    /// Helper function that modifies specific informations on the header
    pub fn add_info(
        &mut self,
        id: u16,
        recursion_desired: bool,
        recursion_available: bool,
        response: bool,
        rescode: ResultCode,
    ) {
        self.header.id = id;
        self.header.recursion_desired = recursion_desired;
        self.header.recursion_available = recursion_available;
        self.header.response = response;
        self.header.rescode = rescode;
    }

    /// `Add Record`
    ///
    /// This method receives a `CachedRecord` instance, convert it into
    /// a record(if possible) and push said record in the answer section
    /// of the packet.
    pub fn add_cr_to_answers(&mut self, cr: &CachedRecord) -> CResult<()> {
        let record = cr.record_from_cache()?;
        self.header.answers = self.header.answers + 1;
        self.answers.push(record);
        Ok(())
    }

    /// `From Buffer`
    ///
    /// Information provided by the buffer passed as the argument will be
    /// structurized into an instance of `Packet`, on success, an error
    /// will be returned if buffer is malformed.
    pub fn from_buffer(buffer: &mut BytePacketBuffer) -> CResult<Packet> {
        // new packet
        let mut result = Packet::new();

        // parsing header
        result.header.read(buffer)?;

        // parsing questions
        for _ in 0..result.header.questions {
            let mut question = Question::new("".to_string(), QueryType::UNKNOWN(0));
            question.read(buffer)?;
            result.questions.push(question);
        }
        // parsing answers
        for _ in 0..result.header.answers {
            let rec = Record::read(buffer)?;
            result.answers.push(rec);
        }
        // parsing authoritative entries
        for _ in 0..result.header.authoritative_entries {
            let rec = Record::read(buffer)?;
            result.authorities.push(rec);
        }
        // parsing resource entries
        for _ in 0..result.header.resource_entries {
            let rec = Record::read(buffer)?;
            result.resources.push(rec);
        }

        Ok(result)
    }

    /// # `write`
    ///
    /// Provided a `BytePacketBuffer` this method writes all the Informations
    /// contained in a `Packet` object into it in the form of a stream of bytes,
    /// in order for this method to work the position of the `BytePacketBuffer`
    /// needs to be 0.
    pub fn write(&mut self, buffer: &mut BytePacketBuffer) -> CResult<()> {
        // TODO: maybe we could make so that the posizion of `buffer` is
        // initialized to 0, since we require it to be so

        // Completing the header
        self.header.questions = self.questions.len() as u16;
        self.header.answers = self.answers.len() as u16;
        self.header.authoritative_entries = self.authorities.len() as u16;
        self.header.resource_entries = self.resources.len() as u16;

        // Writing the header to buffer
        self.header.write(buffer)?;

        // Writing `Question section`
        for question in &self.questions {
            question.write(buffer)?;
        }
        // Writing `Answer section`
        for rec in &self.answers {
            rec.write(buffer)?;
        }
        // Writing `Authority section`
        for rec in &self.authorities {
            rec.write(buffer)?;
        }
        // Writing `Additiona section`
        for rec in &self.resources {
            rec.write(buffer)?;
        }

        Ok(())
    }

    /// # `error_packet`
    ///
    /// Generates an error packet given an id and a `ResultCode`, if the
    /// rescode is `ResultCode::NOERROR` it will return an error.
    /// TODO: we need to rithink this
    pub fn error_packet(rescode: ResultCode, id: u16) -> CResult<Packet> {
        let mut error_packet = Packet::new();
        match rescode {
            ResultCode::NOERROR => {
                return Err("ResultCode::NOERROR has been provided".into());
            }
            _others => {
                error_packet.header.rescode = rescode;
            }
        }
        error_packet.header.response = true;
        error_packet.header.id = id;

        Ok(error_packet)
    }

    /// #`get_resolved_ns`
    ///
    /// Some name servers when queried for an NS record often return
    /// the IP address of the server in the `Additional section`.
    /// This function match iterates over the result in the `Authority section`
    /// and checks if a corresponding A record of a server that is an authority
    /// to our query is present in the `Additional section`, returns the address
    /// of this last one if possible.
    pub fn get_resolved_ns(&self, qname: &str) -> Option<Record> {
        // Get an iterator over the nameservers in the `Authority section`
        self.get_ns(qname)
            // Looking for a matching A record in the `Additional section`.
            // Since we just want the first valid record, we can just
            // build a stream of matching records.
            .flat_map(|(_, host)| {
                self.resources
                    .iter()
                    // Filter for A records where the domain match the host
                    // of the NS record that we are currently processing
                    .filter_map(move |record| match record {
                        Record::A { domain, .. } if domain == host => Some(record.clone()),
                        _ => None,
                    })
            })
            // .map(|addr| addr.clone())
            .next()
    }

    /// # `get_ns`
    ///
    /// `get_resolved_ns`'s and `get_unresolved_ns`'s helper function which
    /// returns an iterator over all name servers in the authorities section,
    /// represented as (domain, host) tuples
    fn get_ns<'a>(&'a self, qname: &'a str) -> impl Iterator<Item = (&'a str, &'a str)> {
        self.authorities
            .iter()
            // In practice, these are always NS records in well formed packages.
            // Convert the NS records to a tuple which has only the data we need
            // to make it easy to work with.
            .filter_map(|record| match record {
                Record::NS { domain, host, .. } => Some((domain.as_str(), host.as_str())),
                _ => None,
            })
            // Discard servers which aren't authoritative to our query
            .filter(move |(domain, _)| qname.ends_with(*domain))
    }

    /// #`get_unresolved_ns`
    ///
    /// The last server provided us with the name of an authoritative server
    /// that we will query for the information we need, so we need to find
    /// the ip address of this last one, this function returns the name
    /// of a server authoritative to our query.
    pub fn get_unresolved_ns<'a>(&'a self, qname: &'a str) -> Option<&'a str> {
        self.get_ns(qname).map(|(_, host)| host).next()
    }

    /// #`get_random_a`
    ///
    /// Gets a random A record and extract the ip from it, if there is one
    pub fn get_random_a_ip(&self) -> Option<Ipv4Addr> {
        self.answers
            .iter()
            .filter_map(|record| match record {
                Record::A { addr, .. } => Some(*addr),
                _ => None,
            })
            .next()
    }

    /// #`get_random_a_rec`
    ///
    /// Gets a random A record from the packet, if there is one
    pub fn get_random_a_rec(&self) -> Option<Record> {
        self.answers
            .iter()
            .filter_map(|record| match record {
                Record::A { .. } => Some(record.clone()),
                _ => None,
            })
            .next()
    }
}
