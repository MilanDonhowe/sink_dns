// This is a minimal DNS message parser made with reference per RFC1035.
// This decodes DNS messages into their Header/Question/Resource Record format.
// However, this does not delicately handle each resource record sub-type.

use std::collections::HashSet;

#[derive(Debug)]
pub struct Header {
    id: u16,
    pub(crate) query_or_response: bool, // query or response
    opcode: u8, // 4 bits max
    authoritative_answer: bool,
    truncation: bool,
    recursion_desired: bool,
    recursion_available: bool,
    #[allow(dead_code)]
    z: bool,
    response_code: u8,
    question_count: u16,
    pub(crate) answer_count: u16,
    pub(crate) name_server_count: u16,
    pub(crate) additional_record_count: u16
}


#[derive(Debug)]
pub struct Question {
    pub(crate) name: String,
    pub(crate) qtype: u16,
    pub(crate) qclass: u16
}

#[derive(Debug)]
pub struct ResourceRecord {
    name: String,
    rr_type: u16,
    rr_class: u16,
    ttl: u32,
    rd_length: u16,
    rdata: Option<Vec<u8>>
}

#[derive(Debug)]
pub enum DnsDecodingError {
    InvalidLength,
    InvalidLabelEncoding,
    CompressedLabelLoop,
    UnimplementedType,
    NoQuestions,
    MalformedDomainName
}

#[derive(Debug)]
pub struct DnsMessage {
    pub(crate) header: Header,
    pub(crate) questions: Option<Vec<Question>>,
    pub(crate) answers: Option<Vec<ResourceRecord>>,
    pub(crate) authority: Option<Vec<ResourceRecord>>,
    pub(crate) additional: Option<Vec<ResourceRecord>>
}


impl DnsMessage {

    
    fn serialize_domain_name(&self, domain_name: &String) -> Vec<u8>{
        let mut buffer = Vec::new();
        domain_name.split(".").for_each(|x|{
           buffer.push(x.len() as u8);
           for b in x.as_bytes().iter() {
            buffer.push(*b);
           }
        });
        // label sequence should end with zero-length label if uncompressed
        // IF the label is compressed then we neglect this null byte but 
        // presently that's not implemented.
        buffer.push(0x00);
        buffer
    }

    fn serialize_record(&self, record: &ResourceRecord) -> Vec<u8>{
        let mut buffer = self.serialize_domain_name(&record.name);
        for x in record.rr_type.to_be_bytes() {
            buffer.push(x);
        }
        for x in record.rr_class.to_be_bytes() {
            buffer.push(x);
        }
        for x in record.ttl.to_be_bytes() {
            buffer.push(x);
        }
        for x in record.rd_length.to_be_bytes() {
            buffer.push(x);
        }
        
        match &record.rdata {
            Some(rdata) => {
                for x in rdata {
                    buffer.push(*x);
                }
            }
            None => {}
        }

        buffer
    }

    fn serialize_question(&self, question: &Question) -> Vec<u8>{
        let mut buffer = self.serialize_domain_name(&question.name);

        for b in question.qtype.to_be_bytes().iter() {
            buffer.push(*b);
        }

        for b in question.qclass.to_be_bytes().iter() {
            buffer.push(*b);
        }
        
        buffer
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut packet = Vec::new();
        for b in self.header.id.to_be_bytes().iter() {
            packet.push(*b);
        }
        // re-build flags word
        let mut flags: u16 = 0;
        flags += (self.header.query_or_response as u16) << 15;
        flags += (self.header.opcode as u16) << 11;
        flags += (self.header.authoritative_answer as u16) << 10;
        flags += (self.header.truncation as u16) << 9;
        flags += (self.header.recursion_desired as u16) << 8;
        flags += (self.header.recursion_available as u16) << 7;
        // skip Z--should be zero
        flags += (self.header.response_code as u16) & 0b0000_0000_0000_1111;
        for b in flags.to_be_bytes().iter() {
            packet.push(*b);
        }
        for b in self.header.question_count.to_be_bytes().iter() {
            packet.push(*b);
        }
        for b in self.header.answer_count.to_be_bytes().iter() {
            packet.push(*b);
        }
        for b in self.header.name_server_count.to_be_bytes().iter() {
            packet.push(*b);
        }
        for b in self.header.additional_record_count.to_be_bytes().iter() {
            packet.push(*b);
        }

        // serialize all questions
        match &self.questions {
            Some(qs) => {
                for q in qs.iter(){
                    for b in self.serialize_question(q).iter() {
                        packet.push(*b);
                    }
                }
            }
            None => {}
        }

        // now serialize all resource records (via .serialize_record)
        match &self.answers {
            Some(rs) => {
                for rr in rs.iter(){
                    for b in self.serialize_record(rr).iter() {
                        packet.push(*b);
                    }
                }
            }
            None => {}
        }

        match &self.authority {
            Some(rs) => {
                for rr in rs.iter(){
                    for b in self.serialize_record(rr).iter() {
                        packet.push(*b);
                    }
                }
            }
            None => {}
        }

        match &self.additional {
            Some(rs) => {
                for rr in rs.iter(){
                    for b in self.serialize_record(rr).iter() {
                        packet.push(*b);
                    }
                }
            }
            None => {}
        }

        // we should not attempt to send paylodas exceeding the DNS UDP payload scheme.
        // this is a hard fail.
        assert!(packet.len() < 512);

        packet
    }
}

// should return (label, offset)
fn parse_labels(full_dns_msg: &[u8], offset: &usize) -> Result<(String, usize), DnsDecodingError>{
    let mut stack: Vec<usize> = Vec::new();
    let mut parts: Vec<String> = Vec::new();

    let mut tracked_pointers: HashSet<u8> = HashSet::new();

    let offset = *offset;
    stack.push(offset);

    // we want to also return the offset of the packet after we have the processed the sequential bytes
    // we need to take some care here as the label sequence may contain pointers that result in non-sequential 
    // packet processing.
    let mut total_offset: usize = offset;
    let mut loop_back = false;
    
    while stack.len() > 0 {
        let cursor = stack.pop();
        let Some(cursor) = cursor else {
            return Err(DnsDecodingError::InvalidLabelEncoding);
        };

        // 1. check if this is a pointer
        let label_start_byte = *full_dns_msg.get(cursor).ok_or(DnsDecodingError::InvalidLength)?;
        if label_start_byte & 0b1100_0000 != 0 {
            // new offset is referenced pointer
            let offset = label_start_byte & 0b0011_1111;
            stack.push(offset as usize);
            // we stop tracking how many bytes we've read from our initial offset the moment we encounter a pointer
            if loop_back == false {
                total_offset += 1;
            }
            loop_back=true;
            /*
                Ok, so we need to account for potentially malicious dns packets using pointers that reference each other (i.e., infinite loop).
            */
            if tracked_pointers.contains(&label_start_byte) {
                return Err(DnsDecodingError::CompressedLabelLoop);
            }
            tracked_pointers.insert(label_start_byte);
            continue;
        }
        // 2. check if zero-length (loop exit condition)
        if label_start_byte == 0 {
            if loop_back == false { 
                total_offset += 1;
            }
            continue;
        }
        
        // 3. non-pointer label (so label_start_byte indicates a length)
        let cursor = cursor + 1;

        let label = str::from_utf8(full_dns_msg.get(cursor .. cursor + label_start_byte as usize).ok_or(DnsDecodingError::InvalidLength)?).map_err(|_|DnsDecodingError::InvalidLabelEncoding)?;
        let label = label.to_string();
        parts.push(label);

        if loop_back == false {
            // +1 for the length byte
            total_offset += 1+label_start_byte as usize;
        }
        
        // push next byte into stack to look into
        stack.push(cursor + label_start_byte as usize);
        continue;
        
    }

    Ok((parts.join("."), total_offset))

}



fn parse_resource_record(packet: &[u8], cursor: usize) -> Result<(ResourceRecord, usize), DnsDecodingError> {
    // name
    //let (domain, mut cursor) = parse_domain_name(packet, cursor)?;
    let (domain, mut cursor) = parse_labels(packet, &cursor)?;

    // type
    let rr_type  = u16::from_be_bytes(packet.get(cursor..cursor+2).ok_or(DnsDecodingError::InvalidLength)?.try_into().map_err(|_|DnsDecodingError::InvalidLength)?);
    cursor += 2;

    // class
    let rr_class  = u16::from_be_bytes(packet.get(cursor..cursor+2).ok_or(DnsDecodingError::InvalidLength)?.try_into().map_err(|_|DnsDecodingError::InvalidLength)?);
    cursor += 2;

    // ttl
    let ttl  = u32::from_be_bytes(packet.get(cursor..cursor+4).ok_or(DnsDecodingError::InvalidLength)?.try_into().map_err(|_|DnsDecodingError::InvalidLength)?);
    cursor += 4;

    // rd length
    let rd_length  = u16::from_be_bytes(packet.get(cursor..cursor+2).ok_or(DnsDecodingError::InvalidLength)?.try_into().map_err(|_|DnsDecodingError::InvalidLength)?);
    cursor += 2;

    // rdata
    let rdata: Vec<u8>  = packet.get(cursor..cursor + (rd_length as usize)).ok_or(DnsDecodingError::InvalidLength)?.to_vec();
    cursor += rd_length as usize;



    Ok (
        (
            ResourceRecord {
                name: domain,
                rr_type,
                rr_class,
                ttl,
                rd_length,
                rdata: if rdata.len() > 0 { Some(rdata) } else  { None }
            },
            cursor
        )
    )

}

pub fn parse_packet(packet: &[u8]) -> Result<DnsMessage, DnsDecodingError>  {

    /*
       1. Parse standard 12 byte DNS Message header
    */

    let id = u16::from_be_bytes(packet.get(0..2).ok_or(DnsDecodingError::InvalidLength)?.try_into().map_err(|_| DnsDecodingError::InvalidLength)?);
    let flags = u16::from_be_bytes(packet.get(2..4).ok_or(DnsDecodingError::InvalidLength)?.try_into().map_err(|_|DnsDecodingError::InvalidLength)?);

    let qr: bool = (flags & 0b1000_0000_0000_0000 >> 15) != 0; // query (0) or response (1)
    let opcode: u8 = (flags & 0b0111_1000_0000_0000 >> 11) as u8; // querty type (0=normal, 1=inverse, 2=status)
    let aa: bool = (flags & 0b0000_0100_0000_0000 >> 10) != 0; // Authoritative Answer
    let tc: bool = (flags & 0b0000_0010_0000_0000 >> 9) != 0; // truncation (was msg truncated?)
    let rd: bool =  (flags & 0b0000_0001_0000_0000 >> 8) != 0; // Recursion desired 
    let ra: bool = (flags & 0b0000_0000_1000_0000 >> 7 ) != 0; // RA set or cleared if server provides recursion
    let z: bool = (flags & 0b0000_0000_0111_0000 >> 4) != 0; // must be zero
    let rcode: u8 = (flags & 0b0000_0000_0000_1111) as u8; // error code if any (0 for success)

    // # questions in question section
    let qdcount = u16::from_be_bytes(packet.get(4..6).ok_or(DnsDecodingError::InvalidLength)?.try_into().map_err(|_|DnsDecodingError::InvalidLength)?);
    // # resource records in answer section
    let ancount = u16::from_be_bytes(packet.get(6..8).ok_or(DnsDecodingError::InvalidLength)?.try_into().map_err(|_|DnsDecodingError::InvalidLength)?);
    // # name server resource records in authority records section
    let nscount = u16::from_be_bytes(packet.get(8..10).ok_or(DnsDecodingError::InvalidLength)?.try_into().map_err(|_|DnsDecodingError::InvalidLength)?);
    // # resource records in additional records section
    let arcount = u16::from_be_bytes(packet.get(10..12).ok_or(DnsDecodingError::InvalidLength)?.try_into().map_err(|_|DnsDecodingError::InvalidLength)?);

    let header = Header {
        id,
        query_or_response: qr,
        opcode,
        authoritative_answer: aa,
        truncation: tc,
        recursion_desired: rd,
        recursion_available: ra,
        z,
        response_code: rcode,
        question_count: qdcount,
        answer_count: ancount,
        name_server_count: nscount,
        additional_record_count: arcount
    };

    /* 
        2. Parse any questions 
    */
    
    let mut message = DnsMessage {
        header,
        questions: None,
        answers: None,
        authority: None,
        additional: None
    };

    let mut questions: Vec<Question> = Vec::new();
    let mut main_cursor = 12;

    for _ in 0..message.header.question_count {
        // Q-Name
        let (domain, mut cursor) = parse_labels(packet, &main_cursor)?;
        //parse_domain_name(packet, main_cursor)?;
        // Q-Type
        let qtype = u16::from_be_bytes(packet.get(cursor..cursor+2).ok_or(DnsDecodingError::InvalidLength)?.try_into().map_err(|_|DnsDecodingError::InvalidLength)?);
        cursor += 2;
        // Q-Class
        let qclass = u16::from_be_bytes(packet.get(cursor..cursor+2).ok_or(DnsDecodingError::InvalidLength)?.try_into().map_err(|_|DnsDecodingError::InvalidLength)?);
        cursor += 2;

        questions.push(
            Question {
                name: domain,
                qtype,
                qclass
            }
        );

        // update cursor reference in parent scope
        main_cursor = cursor;
    }

    if questions.len() > 0 {
        message.questions = Some(questions);
    }

    /*
        3. parse any resource records
    */

    // parse answer records
    let mut answers = Vec::new();
    for _ in 0..message.header.answer_count {
        let (record, cursor) = parse_resource_record(packet, main_cursor)?;
        answers.push(record);
        main_cursor = cursor;
    }
    if answers.len() > 0 {
        message.answers = Some(answers);
    }
    
    // parse authority records
    let mut authority = Vec::new();
    for _ in 0..message.header.name_server_count {
        let (record, cursor) = parse_resource_record(packet, main_cursor)?;
        authority.push(record);
        main_cursor = cursor;
    }
    if authority.len() > 0 {
        message.authority = Some(authority);
    }

    // parse additional records
    let mut additional_records = Vec::new();
    for _ in 0..message.header.additional_record_count {
        let (record, cursor) = parse_resource_record(packet, main_cursor)?;
        additional_records.push(record);
        main_cursor = cursor;
    }
    if additional_records.len() > 0 {
        message.additional = Some(additional_records);
    }

    // 4. return parsed message back
    Ok(message)

}


pub fn build_nullreply(question: &Question) -> Result<ResourceRecord, DnsDecodingError> {
    let mut record = ResourceRecord {
        name: question.name.clone(),
        rr_type: question.qtype,
        rr_class: question.qclass,
        ttl: 3600, // default to one hour
        rd_length: 0,
        rdata: None
    };
    
    // https://www.rfc-editor.org/info/rfc1035/#section-3.4.1
    match record.rr_type {
        // Match A class (=1)
       1 => {
        record.rd_length = 4;
        record.rdata = Some(vec![0; 4]);
       }
       // Match AAAA class (https://datatracker.ietf.org/doc/html/rfc3596)
       28 => {
        record.rd_length = 16;
        record.rdata = Some(vec![0; 16]);
       }
       // HTTPS specific (https://www.rfc-editor.org/info/rfc9460/)
       65 => {
        // Return null payload
       }
       _ => {
        return Err(DnsDecodingError::UnimplementedType);
       }
    }

    Ok(record)
}