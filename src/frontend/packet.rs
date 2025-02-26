use std::fs::File;
use std::io::{Read, BufReader};
use anyhow::Result;
use log::trace;

use crate::frontend::c_header::*;
use crate::frontend::f_header::*;
use crate::frontend::trap_type::*;

#[derive(Debug)]
pub struct Packet {
    pub is_compressed: bool,
    pub c_header: CHeader,
    pub f_header: FHeader,
    pub trap_type: TrapType,
    pub target_address: u64,
    pub trap_address: u64,
    pub timestamp: u64,
}

// Initialize a packet with default values
impl Packet {
    fn new() -> Packet {
        Packet {
            is_compressed: false,
            c_header: CHeader::CNa,
            f_header: FHeader::FRes,
            trap_type: TrapType::TNone,
            target_address: 0,
            trap_address: 0,
            timestamp: 0,
        }
    }
}

fn read_u8(stream: &mut BufReader<File>) -> Result<u8> {
    let mut buf = [0u8; 1];
    stream.read_exact(&mut buf)?;
    Ok(buf[0])
}

const VAR_MASK: u8 = 0b1000_0000;
const VAR_LAST: u8 = 0b1000_0000;
const VAR_OFFSET: u8 = 7;
const VAR_VAL_MASK: u8 = 0b0111_1111;

fn read_varint(stream: &mut BufReader<File>) -> Result<u64> {
    let mut result = Vec::new();
    loop {
        let byte = read_u8(stream)?;
        trace!("byte: {:08b}", byte);
        result.push(byte);
        if byte & VAR_MASK == VAR_LAST { break; }
    }
    Ok(result.iter().rev().fold(0, |acc, &x| (acc << VAR_OFFSET) | (x & VAR_VAL_MASK) as u64))
} 

pub fn read_packet(stream: &mut BufReader<File>) -> Result<Packet> {
    let mut packet = Packet::new();
    let first_byte = read_u8(stream)?;
    trace!("first_byte: {:08b}", first_byte);
    let c_header = CHeader::from(first_byte & C_HEADER_MASK);
    match c_header {
        CHeader::CTb | CHeader::CNt | CHeader::CIj => {
            packet.timestamp = (first_byte & C_TIMESTAMP_MASK) as u64 >> 2;
            packet.f_header = FHeader::from(c_header.clone());
            packet.c_header = c_header.clone();
            packet.is_compressed = true;
        }
        CHeader::CNa => {
            packet.is_compressed = false;
            let f_header = FHeader::from((first_byte & F_HEADER_MASK) >> FHEADER_OFFSET);
            // println!("f_header: {:?}", f_header);
            match f_header {
                FHeader::FTb | FHeader::FNt | FHeader::FIj => {
                    let timestamp = read_varint(stream)?;
                    packet.timestamp = timestamp;
                    packet.f_header = f_header;
                    packet.c_header = CHeader::CNa;
                }
                FHeader::FUj => {
                    let target_address = read_varint(stream)?;
                    packet.target_address = target_address;
                    let timestamp = read_varint(stream)?;
                    packet.timestamp = timestamp;
                    packet.f_header = f_header;
                    packet.c_header = CHeader::CNa;
                }
                FHeader::FSync => {
                    let _ = read_varint(stream)?; // branch mode, unused in sync end packets
                    let target_address = read_varint(stream)?;
                    packet.target_address = target_address;
                    let timestamp = read_varint(stream)?;
                    packet.timestamp = timestamp;
                    packet.f_header = f_header;
                    packet.c_header = CHeader::CNa;
                }
                FHeader::FTrap => {
                    let trap_type = TrapType::from((first_byte & TRAP_TYPE_MASK) >> TRAP_TYPE_OFFSET);
                    packet.trap_type = trap_type;
                    let trap_address = read_varint(stream)?;
                    packet.trap_address = trap_address;
                    let target_address = read_varint(stream)?;
                    packet.target_address = target_address;
                    let timestamp = read_varint(stream)?;
                    packet.timestamp = timestamp;
                    packet.f_header = f_header;
                    packet.c_header = CHeader::CNa;
                }
                _ => {
                    println!("Invalid FHeader value: {}", first_byte);
                }
            }
        }
    }
    Ok(packet)
}

pub fn read_first_packet(stream: &mut BufReader<File>) -> Result<Packet> {
    let mut packet = Packet::new();
    let first_byte = read_u8(stream)?;
    trace!("first_byte: {:08b}", first_byte);
    let c_header = CHeader::from(first_byte & C_HEADER_MASK);
    assert!(c_header == CHeader::CNa);
    let f_header = FHeader::from((first_byte & F_HEADER_MASK) >> FHEADER_OFFSET);
    assert!(f_header == FHeader::FSync);
    let target_address = read_varint(stream)?;
    packet.target_address = target_address;
    let timestamp = read_varint(stream)?;
    packet.timestamp = timestamp;
    Ok(packet)
}
