extern crate clap;

use clap::Parser;

use anyhow::Result;

use std::fs::File;
use std::io::{BufReader, Read};

const VAR_MASK: u8 = 0b1000_0000;
// const VAR_CONT: u8 = 0b0000_0000;
const VAR_LAST: u8 = 0b1000_0000;
const VAR_OFFSET: u8 = 7;
const VAR_VAL_MASK: u8 = 0b0111_1111;

#[derive(Parser)]
#[command(name = "useit_decoder", version = "0.1.0", about = "Decode useit trace files")]
struct Args {
    // path to the encoded trace file
    #[arg(short, long)]
    encoded_trace: String,
    // path to the decoded trace file
    #[arg(short, long, default_value_t = String::from("trace_useit.dump"))]
    decoded_trace: String,
}

fn read_u8(stream: &mut BufReader<File>) -> Result<u8> {
    let mut buf = [0u8; 1];
    stream.read_exact(&mut buf)?;
    Ok(buf[0])
}

fn read_u32(stream: &mut BufReader<File>) -> Result<u32> {
    let mut buf = [0u8; 4];
    stream.read_exact(&mut buf)?;
    Ok(u32::from_le_bytes(buf))
}

fn read_varint(stream: &mut BufReader<File>) -> Result<u64> {
    let mut result = Vec::new();
    loop {
        let byte = read_u8(stream)?;
        result.push(byte);
        if byte & VAR_MASK == VAR_LAST { break; }
    }
    Ok(result.iter().rev().fold(0, |acc, &x| (acc << VAR_OFFSET) | (x & VAR_VAL_MASK) as u64))
} 

// convert one-hot encoded maks to a Vec of indices
fn ohe2indices(mask: u32) -> Vec<u32> {
    (0..32).filter(|i| (mask & (1 << i)) != 0).collect()
}

fn main() -> Result<()> {
    let args = Args::parse();

    let encoded_trace_file = File::open(args.encoded_trace.clone())?;
    let mut encoded_trace_reader : BufReader<File> = BufReader::new(encoded_trace_file);

    let header = read_u32(&mut encoded_trace_reader)?;
    println!("header: {:?}", header);

    let target_counters = ohe2indices(header);
    println!("target_counters: {:?}", target_counters);

    // while there are more things in the stream
    while let Ok(counter) = read_varint(&mut encoded_trace_reader) {
        println!("counter: {:?}", counter);
    }

    Ok(())
}
