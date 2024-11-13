use super::{auxiliaries::CResult, buffer::BytePacketBuffer};

#[derive(Debug, Clone)]
pub struct Header {
    /// A random identifier assigned to query packets.
    /// Response packets must reply with the same id.
    /// This is needed to differentiate responses due
    /// to the stateless nature of UDP.
    pub id: u16, // 16 bits

    /// Set by the sender of the request if the server should
    /// attempt to resolve the query recursively if it does
    /// not have an answer readily available.
    pub recursion_desired: bool,    // 1 bit
    /// Set to 1 if the message length exceeds 512 bytes.
    /// Traditionally a hint that the query can be reissued using TCP,
    /// for which the length limitation doesn't apply.
    pub truncated_message: bool,    // 1 bit
    /// Set to 1 if the responding server is authoritative:
    /// that is, it "owns" - the domain queried.
    pub authoritative_answer: bool, // 1 bit
    /// Typically always 0, see RFC1035 for details.
    pub opcode: u8,                 // 4 bits
    /// 0 for queries, 1 for responses.
    pub response: bool,             // 1 bit

    /// Set by the server to indicate the status of the response,
    /// i.e. whether or not it was successful or failed, and in the
    /// latter case providing details about the cause of the failure.
    pub rescode: ResultCode,       // 4 bits
    /// indicates whether a security-aware resolver should disable
    /// signature validation (i.e., not check DNSSEC records) in a query,
    /// when the checking disabled bit is set to 1, it means that the
    /// resolver is willing to accept non-verified data in the response.
    pub checking_disabled: bool,   // 1 bit
    /// indicate whether the DNS packet contains authenticated data or not,
    /// it is set to 1 if the packet contains authenticated data,
    /// and 0 otherwise.
    pub authed_data: bool,         // 1 bit
    /// Originally reserved for later use, but now used for DNSSEC queries.
    pub z: bool,                   // 1 bit
    /// Set by the server to indicate whether or not recursive
    /// queries are allowed.
    pub recursion_available: bool, // 1 bit

    /// The number of entries in the Question Section
    pub questions: u16,             // 16 bits
    /// The number of entries in the Answer Section
    pub answers: u16,               // 16 bits
    /// The number of entries in the Authority Section
    pub authoritative_entries: u16, // 16 bits
    /// The number of entries in the Additional Section
    pub resource_entries: u16,      // 16 bits
}

impl Header {
    pub fn new() -> Header {
        Header {
            id: 0,

            recursion_desired: false,
            truncated_message: false,
            authoritative_answer: false,
            opcode: 0,
            response: false,

            rescode: ResultCode::NOERROR,
            checking_disabled: false,
            authed_data: false,
            z: false,
            recursion_available: false,

            questions: 0,
            answers: 0,
            authoritative_entries: 0,
            resource_entries: 0,
        }
    }

    /// `read`
    ///
    /// Given a `BytePacketBuffer` this method will try to parse the header of
    /// a DNS packet, the `BytePacketBuffer` provided will needs to be well formed
    /// and `BytePacketBuffer.pos` needs to be in the correct positon(0), if something
    /// goes wrong an error is returned.
    pub fn read(&mut self, buffer: &mut BytePacketBuffer) -> CResult<()> {
        self.id = buffer.read_u16()?;

        let flags = buffer.read_u16()?;
        let flags_a = (flags >> 8) as u8;
        let flags_b = (flags & 0xFF) as u8;

        self.recursion_desired = (flags_a & 1) > 0;
        self.truncated_message = (flags_a & (1 << 1)) > 0;
        self.authoritative_answer = (flags_a & (1 << 2)) > 0;
        self.opcode = (flags_a >> 3) & 0x0F;
        self.response = (flags_a & (1 << 7)) > 0;

        self.rescode = ResultCode::from_num(flags_b & 0x0F);
        self.checking_disabled = (flags_b & (1 << 4)) > 0;
        self.authed_data = (flags_b & (1 << 5)) > 0;
        self.z = (flags_b & (1 << 6)) > 0;
        self.recursion_available = (flags_b & (1 << 7)) > 0;

        self.questions = buffer.read_u16()?;
        self.answers = buffer.read_u16()?;
        self.authoritative_entries = buffer.read_u16()?;
        self.resource_entries = buffer.read_u16()?;

        Ok(())
    }

    /// # `write`
    ///
    /// Given a `BytePacketBuffer` it writes all the informations present
    /// in the header on it, for the operation to be completed `BytePacketBuffer::pos`
    /// needs to be 0.
    pub fn write(&mut self, buffer: &mut BytePacketBuffer) -> CResult<()> {
        buffer.write_u16(self.id)?;

        buffer.write_u8(
            (self.recursion_desired as u8)
                | ((self.truncated_message as u8) << 1)
                | ((self.authoritative_answer as u8) << 2)
                | (self.opcode << 3)
                | ((self.response as u8) << 7) as u8,
        )?;

        buffer.write_u8(
            (self.rescode as u8)
                | ((self.checking_disabled as u8) << 4)
                | ((self.authed_data as u8) << 5)
                | ((self.z as u8) << 6)
                | ((self.recursion_available as u8) << 7),
        )?;

        buffer.write_u16(self.questions)?;
        buffer.write_u16(self.answers)?;
        buffer.write_u16(self.authoritative_entries)?;
        buffer.write_u16(self.resource_entries)?;

        Ok(())
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ResultCode {
    NOERROR = 0,
    FORMERR = 1,
    SERVFAIL = 2,
    NXDOMAIN = 3,
    NOTIMP = 4,
    REFUSED = 5,
}

impl ResultCode {
    pub fn from_num(num: u8) -> ResultCode {
        match num {
            1 => ResultCode::FORMERR,
            2 => ResultCode::SERVFAIL,
            3 => ResultCode::NXDOMAIN,
            4 => ResultCode::NOTIMP,
            5 => ResultCode::REFUSED,
            0 | _ => ResultCode::NOERROR,
        }
    }
}
