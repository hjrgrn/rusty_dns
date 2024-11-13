use super::{auxiliaries::CResult, header::ResultCode, packet::Packet};

/// # `BytePacketBuffer`
///
/// Buffer that contains the binary form of a packet
pub struct BytePacketBuffer {
    /// The bytes of the packet
    pub buf: [u8; 512],
    /// Value that keeps track of the position in the buffer
    pos: usize,
}

impl BytePacketBuffer {
    pub fn new() -> Self {
        let buf = [0; 512];
        let pos = 0;
        BytePacketBuffer { buf, pos }
    }

    // TODO: comment
    pub fn new_error_packet(rescode: ResultCode, id: u16) -> CResult<Self> {
        let mut error_packet = Packet::error_packet(rescode, id)?;
        let mut buffer = Self::new();
        error_packet.write(&mut buffer)?;
        Ok(buffer)
    }

    /// Current position within buffer
    pub fn pos(&self) -> usize {
        self.pos
    }

    /// Reads one byte, advances the cursor accordingly,
    /// returns the byte read or an error
    /// if tried to read a byte that is out of bound
    pub fn read_u8(&mut self) -> CResult<u8> {
        if self.pos >= 512 {
            return Err("End of buffer".into());
        }

        let res = self.buf[self.pos];
        self.pos = self.pos + 1;
        Ok(res)
    }

    /// Reads two bytes, advances the cursor accordingly,
    /// returns the bytes read or an error
    /// if tried to read a byte that is out of bound
    pub fn read_u16(&mut self) -> CResult<u16> {
        let res = ((self.read_u8()? as u16) << 8) | (self.read_u8()? as u16);
        Ok(res)
    }

    /// Reads four bytes, advances the cursor accordingly,
    /// returns the bytes read or an error
    /// if tried to read a byte that is out of bound
    pub fn read_u32(&mut self) -> CResult<u32> {
        let res = ((self.read_u8()? as u32) << 24)
            | ((self.read_u8()? as u32) << 16)
            | ((self.read_u8()? as u32) << 8)
            | (self.read_u8()? as u32);
        Ok(res)
    }

    /// Get a single byte, without changing the buffer position
    pub fn get(&self, pos: usize) -> CResult<u8> {
        if pos >= 512 {
            return Err("End of buffer".into());
        }
        Ok(self.buf[pos])
    }

    /// Change buffer position
    pub fn seek(&mut self, pos: usize) -> CResult<()> {
        self.pos = pos;
        Ok(())
    }

    /// Get a range of bytes, doesn't change the current position
    pub fn get_range(&self, start: usize, len: usize) -> CResult<&[u8]> {
        if start + len >= 512 {
            return Err("End of buffer".into());
        }
        Ok(&self.buf[start..start + len as usize])
    }

    /// Step the buffer position forward a specific number of steps
    pub fn step(&mut self, steps: usize) -> CResult<()> {
        self.pos = self.pos + steps;
        Ok(())
    }

    /// # `read_qname`
    ///
    /// Reads domain names, taking labels into consideration.
    /// Will take something like \[3\]www\[6\]google\[3\]com\[0\] and append
    /// www.google.com to the `&mut String` provided.
    pub fn read_qname(&mut self, outstr: &mut String) -> CResult<()> {
        // Since we might encounter jumps, we'll keep track of our position
        // locally as opposed to using the position within the struct. This
        // allows us to move the shared position to a point past our current
        // qname, while keeping track of our progress on the current qname
        // using this variable.
        let mut pos = self.pos();
        // track whether or not we've jumped
        let mut jumped = false;
        let max_jumps = 5;
        let mut jumps_performed = 0;
        // delimiter, starts as an empty str and mutes into "." after the first
        // iteration of the loop
        let mut delim = "";

        loop {
            // Limiting the maximum number of jumps to avoid eventual infinite cycles
            if jumps_performed > max_jumps {
                return Err(format!("Limit of {} jumps exceeded", max_jumps).into());
            }
            // Beginning of the label, labels strat with length in bytes
            let len = self.get(pos)?;

            // If len has the two most significant bit set, it represents a
            // jump to some other offset in the packet: 0xc0 = 11000000
            if (len & 0xC0) == 0xC0 {
                // Update the buffer position to a point past the current
                // label. We don't need to touch it any further.
                if !jumped {
                    self.seek(pos + 2)?;
                }
                // Read another byte, calculate offset and perform the jump by
                // updating our local position variable
                let b2 = self.get(pos + 1)? as u16;
                let offset = (((len as u16) ^ 0xC0) << 8) | b2;
                pos = offset as usize;
                // Indicate that a jump was performed.
                jumped = true;
                jumps_performed = jumps_performed + 1;
                continue;
            }

            // Move a single byte forward to move past the length byte.
            pos = pos + 1;
            // Domain names are terminated by an empty label of length 0,
            // so if the length is zero we're done.
            if len == 0 {
                break;
            }

            // Append the delimiter to our output buffer first.
            outstr.push_str(delim);
            // Extract the actual ASCII bytes for this label and append them
            // to the output buffer.
            let str_buffer = self.get_range(pos, len as usize)?;
            outstr.push_str(&String::from_utf8_lossy(str_buffer).to_lowercase());

            delim = ".";
            // Move forward the full length of the label.
            pos = pos + len as usize;
        }

        if !jumped {
            self.seek(pos)?;
        }

        Ok(())
    }

    pub fn write_u8(&mut self, val: u8) -> CResult<()> {
        if self.pos >= 512 {
            return Err("End of buffer".into());
        }
        self.buf[self.pos] = val;
        self.pos = self.pos + 1;
        Ok(())
    }

    pub fn write_u16(&mut self, val: u16) -> CResult<()> {
        self.write_u8((val >> 8) as u8)?;
        self.write_u8((val & 0xFF) as u8)?;
        Ok(())
    }

    pub fn write_u32(&mut self, val: u32) -> CResult<()> {
        self.write_u16((val >> 16) as u16)?;
        self.write_u16((val & 0xFFFF) as u16)?;
        Ok(())
    }

    /// # `write_qname`
    ///
    /// Formats and write the provided name on the buffer in the
    /// form of a stream of bytes, if possible.
    pub fn write_qname(&mut self, qname: &str) -> CResult<()> {
        for label in qname.split('.') {
            let len = label.len();
            if len > 0x34 {
                return Err("Single label exceeds 63 characters of length".into());
            }

            self.write_u8(len as u8)?;
            for b in label.as_bytes() {
                self.write_u8(*b)?;
            }
        }

        self.write_u8(0)?;

        Ok(())
    }

    fn set_u8(&mut self, pos: usize, val: u8) -> CResult<()> {
        if pos >= 512 {
            return Err("End of buffer".into());
        }
        self.buf[pos] = val;

        Ok(())
    }

    pub fn set_u16(&mut self, pos: usize, val: u16) -> CResult<()> {
        self.set_u8(pos, (val >> 8) as u8)?;
        self.set_u8(pos + 1, (val & 0xFF) as u8)?;
        Ok(())
    }
}
