/*
    lib.rs nxdns

*/
mod dns;

use std::{collections::HashMap, error::Error};
use tokio::sync::mpsc::{Sender};
use std::net::SocketAddr;

use crate::dns::DnsDecodingError;


pub enum BlockEntry {
    BlockPacket(Vec<u8>),
    Address(String),
    ForwardTraffic,
    Block
}

pub type MSG = (Vec<u8>, SocketAddr);

pub async fn process_dns_packet(packet: &[u8], send_addr: SocketAddr, block_list: &HashMap<String, BlockEntry>, forward_dns: &Sender<MSG>, direct_reply: &Sender<MSG>) -> Result<(), dns::DnsDecodingError>{
    // This needs to be very fast
    // 1. Parse DNS packet (at least to the extent where we can determine if the query is in our block list)
    let mut dns_msg = dns::parse_packet(packet)?;

    println!("Parsed DNS MSG: {:?}", dns_msg);

    // okay so technically it is possible to have multiple DNS names in a single query.
    // so we have to do a little magic here for forwarding results back to the resolver.

    // we forward dns packets outbound if any of the questions reference non-blocked domains
    let mut dont_block = false;
    let mut records = Vec::new();
    
    // stub resolver sent us a message without a question?  That's almost certainly a decoding error.
    let questions = dns_msg.questions.ok_or(DnsDecodingError::NoQuestions)?;


    for question in questions.iter() {
        match block_list.get(&question.name) {
            Some(_) => {
                // build a dns reply
                dns_msg.header.answer_count += 1;
                let blank_record = dns::build_nullreply(&question)?;
                records.push(blank_record);
            }
            None => {
                // Alright, let's forward this packet
                dont_block = true;
                break;
            }
        }
    }
    // re-move questions back into dns_msg struct
    dns_msg.questions = Some(questions);
    dns_msg.answers = Some(records);

    if dont_block {
        println!("[*] sending msg to upstream dns");
        let _ = forward_dns.send( (packet.to_vec(), send_addr) ).await;
    } else {
        println!("[*] sending block msg direct to stub dns");
        // this is a response
        dns_msg.header.query_or_response = true;

        // TODO: add better OPT record handling
        dns_msg.additional = None;
        dns_msg.header.additional_record_count=0;

        // do I ever need to handle NS records?
        dns_msg.authority = None;
        dns_msg.header.name_server_count = 0;
        
        let _ = direct_reply.send( (dns_msg.serialize(), send_addr) ).await;
    }
    

    Ok(())
}