extern crate clap;
extern crate object;
extern crate capstone;
extern crate bus;
extern crate log;
extern crate env_logger;
extern crate gcno_reader;
mod frontend {
    pub mod packet;
    pub mod br_mode;
    pub mod c_header;
    pub mod f_header;
    pub mod trap_type;
    pub mod bp_double_saturating_counter;
}
mod backend {
    pub mod abstract_receiver;
    pub mod event;
    pub mod stats_receiver;
    pub mod txt_receiver;
    pub mod json_receiver;
    pub mod afdo_receiver;
    pub mod gcda_receiver;
    pub mod stack_unwinder;
    pub mod speedscope_receiver;
    pub mod vpp_receiver;
    pub mod foc_receiver;
    pub mod vbb_receiver;
}

use frontend::f_header::FHeader;

// file IO
use std::fs::File;
use std::io::{Read, BufReader};
// collections 
use std::collections::HashMap;
// argparse dependency
use clap::Parser;
// objdump dependency
use capstone::prelude::*;
use capstone::arch::riscv::{ArchMode, ArchExtraMode};
use capstone::Insn;
use object::{Object, ObjectSection};
// bus dependency
use bus::Bus;
use std::thread;
// frontend dependency
use frontend::bp_double_saturating_counter::BpDoubleSaturatingCounter;
use frontend::br_mode::BrMode;
// backend dependency
use backend::event::{Entry, Event};
use backend::stats_receiver::StatsReceiver;
use backend::txt_receiver::TxtReceiver;
use backend::json_receiver::JsonReceiver;
use backend::afdo_receiver::AfdoReceiver;
use backend::abstract_receiver::AbstractReceiver;
use backend::gcda_receiver::GcdaReceiver;
use backend::speedscope_receiver::SpeedscopeReceiver;
use backend::vpp_receiver::VPPReceiver;
use backend::foc_receiver::FOCReceiver;
use backend::vbb_receiver::VBBReceiver;
// error handling
use anyhow::Result;
// logging
use log::{debug, trace};

const BRANCH_OPCODES: &[&str] = &["beq", "bge", "bgeu", "blt", "bltu", "bne", "beqz", "bnez",
                                "bgez", "blez", "bltz", "bgtz", "bgt", "ble", "bgtu", "bleu",
                                "c.beqz", "c.bnez", "c.bltz", "c.bgez"];
const IJ_OPCODES: &[&str] = &["jal", "j", "call", "tail", "c.j", "c.jal"];
const UJ_OPCODES: &[&str] = &["jalr", "jr", "c.jr", "c.jalr", "ret"];
const BUS_SIZE: usize = 1024;

#[derive(Clone, Parser)]
#[command(name = "trace-decoder", version = "0.1.0", about = "Decode trace files")]
struct Args {
    // path to the encoded trace file
    #[arg(short, long)]
    encoded_trace: String,
    // path to the binary file
    #[arg(short, long)]
    binary: String,
    // path to the decoded trace file
    #[arg(short, long, default_value_t = String::from("trace.dump"))]
    decoded_trace: String,
    // branch mode
    #[arg(long, default_value_t = 0)]
    br_mode: u64,
    // branch prediction number of entries
    #[arg(long, default_value_t = 1024)]
    bp_entries: u64,
    // print the timestamp in the decoded trace file
    #[arg(short, long, default_value_t = false)]
    timestamp: bool,
    // output the decoded trace in stats format
    #[arg(long, default_value_t = false)]
    to_stats: bool,
    // output the decoded trace in text format
    #[arg(long, default_value_t = true)]
    to_txt: bool,
    // output the decoded trace in JSON format
    #[arg(long, default_value_t = false)]
    to_json: bool,
    // output the decoded trace in afdo format
    #[arg(long, default_value_t = false)]
    to_afdo: bool,
    // path to the gcno file, must be provided if to_afdo is true
    #[arg(long, default_value_t = String::from(""))]
    gcno: String,
    // output the decoded trace in gcda format
    #[arg(long, default_value_t = false)]
    to_gcda: bool,
    // output the decoded trace in speedscope format
    #[arg(long, default_value_t = false)]
    to_speedscope: bool,
    // output the decoded trace in vpp format
    #[arg(long, default_value_t = false)]
    to_vpp: bool,
    // output the decoded trace in foc format
    #[arg(long, default_value_t = false)]
    to_foc: bool,
    // output the decoded trace in vbb format
    #[arg(long, default_value_t = false)]
    to_vbb: bool,
}

fn refund_addr(addr: u64) -> u64 {
    addr << 1
}

// FIXME: hacky way to get the offset operand, always the last one
fn compute_offset(insn: &Insn) -> i64 {
    // trace!("insn: {:?}", insn);
    let offset = insn.op_str().unwrap().split(",").last().unwrap();
    // remove leading spaces
    let offset = offset.trim();
    // trace!("offset: {:?}", offset);
    let offset_value: i64;
    if offset.starts_with("-0x") {
        offset_value = i64::from_str_radix(&offset[3..], 16).unwrap() * -1;
    } else if offset.starts_with("0x") {
        offset_value = i64::from_str_radix(&offset[2..], 16).unwrap();
    } else if offset.starts_with("-") {
        offset_value = i64::from_str_radix(&offset[1..], 10).unwrap() * -1;
    } else {
        offset_value = i64::from_str_radix(&offset, 10).unwrap();
    }
    offset_value
}

// step until encountering a br/jump
fn step_bb(pc: u64, insn_map: &HashMap<u64, &Insn>, bus: &mut Bus<Entry>, br_mode: &BrMode) -> u64 {
    let mut pc = pc;
    let stop_on_ij = *br_mode == BrMode::BrTarget;
    loop {
        let insn = insn_map.get(&pc).unwrap();
        bus.broadcast(Entry::new_insn(insn));
        if stop_on_ij {
            if BRANCH_OPCODES.contains(&insn.mnemonic().unwrap()) || IJ_OPCODES.contains(&insn.mnemonic().unwrap()) || UJ_OPCODES.contains(&insn.mnemonic().unwrap()) {
                break;
            } else {
                pc += insn.len() as u64;
            }
        } else {
            if BRANCH_OPCODES.contains(&insn.mnemonic().unwrap()) || UJ_OPCODES.contains(&insn.mnemonic().unwrap()) {
                break;
            } else if IJ_OPCODES.contains(&insn.mnemonic().unwrap()) {
                let new_pc = (pc as i64 + compute_offset(insn) as i64) as u64;
                pc = new_pc;
            } else {
                pc += insn.len() as u64;
            }
        }
    }
    pc
}

fn step_bb_until(pc: u64, insn_map: &HashMap<u64, &Insn>, target_pc: u64, bus: &mut Bus<Entry>) -> u64 {
    // println!("stepping bb from pc: {:x} until pc: {:x}", pc, target_pc);
    let mut pc = pc;

    loop {
        let insn = insn_map.get(&pc).unwrap();
        bus.broadcast(Entry::new_insn(insn));
        if BRANCH_OPCODES.contains(&insn.mnemonic().unwrap()) || IJ_OPCODES.contains(&insn.mnemonic().unwrap()) {
            break;
        }
        if pc == target_pc {
            break;
        }
        pc += insn.len() as u64;
    }
    pc
}

// frontend decoding packets and pushing entries to the bus
fn trace_decoder(args: &Args, mut bus: Bus<Entry>) -> Result<()> {
    let mut elf_file = File::open(args.binary.clone())?;
    let mut elf_buffer = Vec::new();
    elf_file.read_to_end(&mut elf_buffer)?;
    let elf = object::File::parse(&*elf_buffer)?;
    assert!(elf.architecture() == object::Architecture::Riscv64);

    // Find the .text section (where the executable code resides)
    let text_section = elf.section_by_name(".text").ok_or_else(|| anyhow::anyhow!("No .text section found"))?;
    let text_data = text_section.data()?;
    let entry_point = elf.entry();

    let cs = Capstone::new()
        .riscv()
        .mode(ArchMode::RiscV64)
        .extra_mode([ArchExtraMode::RiscVC].iter().copied())
        .detail(true)
        .build()?;

    let decoded_instructions = cs.disasm_all(&text_data, entry_point)?;
    debug!("[main] found {} instructions", decoded_instructions.len());

    // create a map of address to instruction 
    let mut insn_map : HashMap<u64, &Insn> = HashMap::new();
    for insn in decoded_instructions.as_ref() {
        insn_map.insert(insn.address(), insn);
    }

    let encoded_trace_file = File::open(args.encoded_trace.clone())?;
    let mut encoded_trace_reader : BufReader<File> = BufReader::new(encoded_trace_file);

    let mut bp_counter = BpDoubleSaturatingCounter::new(args.bp_entries);

    let br_mode = BrMode::from(args.br_mode);
    let mode_is_predict = br_mode == BrMode::BrPredict || br_mode == BrMode::BrHistory;

    let packet = frontend::packet::read_first_packet(&mut encoded_trace_reader)?;
    let mut packet_count = 0;

    trace!("packet: {:?}", packet);
    let mut pc = refund_addr(packet.target_address);
    let mut timestamp = packet.timestamp;
    bus.broadcast(Entry::new_timed_event(Event::Start, packet.timestamp, pc, 0));

    while let Ok(packet) = frontend::packet::read_packet(&mut encoded_trace_reader) {
        packet_count += 1;
        // special handling for the last packet, should be unlikely hinted
        trace!("[{}]: packet: {:?}", packet_count, packet);
        if packet.f_header == FHeader::FSync {
            pc = step_bb_until(pc, &insn_map, refund_addr(packet.target_address), &mut bus);
            println!("detected FSync packet, trace ending!");
            bus.broadcast(Entry::new_timed_event(Event::End, packet.timestamp, pc, 0));
            break;
        } else if packet.f_header == FHeader::FTrap {
            pc = step_bb_until(pc, &insn_map, packet.trap_address, &mut bus);
            pc = refund_addr(packet.target_address ^ (pc >> 1));
            timestamp += packet.timestamp;
            bus.broadcast(Entry::new_timed_trap(packet.trap_type, timestamp, packet.trap_address, pc));
        } else if mode_is_predict && packet.f_header == FHeader::FTb { // predicted hit
            bus.broadcast(Entry::new_timed_event(Event::BPHit, packet.timestamp, pc, pc));
            // predict for timestamp times
            for _ in 0..packet.timestamp {
                pc = step_bb(pc, &insn_map, &mut bus, &br_mode);
                let insn_to_resolve = insn_map.get(&pc).unwrap();
                if !BRANCH_OPCODES.contains(&insn_to_resolve.mnemonic().unwrap()) {
                    bus.broadcast(Entry::new_timed_event(Event::Panic, 0, pc, 0));
                    panic!("pc: {:x}, timestamp: {}, insn: {:?}", pc, timestamp, insn_to_resolve);
                 }
                let taken = bp_counter.predict(pc, true);
                if taken {
                    let new_pc = (pc as i64 + compute_offset(insn_to_resolve) as i64) as u64;
                    bus.broadcast(Entry::new_timed_event(Event::TakenBranch, timestamp, pc, new_pc));
                    pc = new_pc;
                } else {
                    let new_pc = pc + insn_to_resolve.len() as u64;
                    bus.broadcast(Entry::new_timed_event(Event::NonTakenBranch, timestamp, pc, new_pc));
                    pc = new_pc;
                }
            }
        } else if mode_is_predict && packet.f_header == FHeader::FNt { // predicted miss
            timestamp += packet.timestamp;
            bus.broadcast(Entry::new_timed_event(Event::BPMiss, timestamp, pc, pc));
            pc = step_bb(pc, &insn_map, &mut bus, &br_mode);
            let insn_to_resolve = insn_map.get(&pc).unwrap();
            if !BRANCH_OPCODES.contains(&insn_to_resolve.mnemonic().unwrap()) {
                bus.broadcast(Entry::new_timed_event(Event::Panic, 0, pc, 0));
                panic!("pc: {:x}, timestamp: {}, insn: {:?}", pc, timestamp, insn_to_resolve);
             }
            let taken = bp_counter.predict(pc, false);
            if !taken { // reverse as we mispredicted
                let new_pc = (pc as i64 + compute_offset(insn_to_resolve) as i64) as u64;
                bus.broadcast(Entry::new_timed_event(Event::TakenBranch, timestamp, pc, new_pc));
                pc = new_pc;
            } else {
                let new_pc = pc + insn_to_resolve.len() as u64;
                bus.broadcast(Entry::new_timed_event(Event::NonTakenBranch, timestamp, pc, new_pc));
                pc = new_pc;
            }
        } else  {
            // trace!("pc before step_bb: {:x}", pc);
            pc = step_bb(pc, &insn_map, &mut bus, &br_mode);
            let insn_to_resolve = insn_map.get(&pc).unwrap();
            // trace!("pc after step_bb: {:x}", pc);
            timestamp += packet.timestamp;
            match packet.f_header {
                FHeader::FTb => {
                    if !BRANCH_OPCODES.contains(&insn_to_resolve.mnemonic().unwrap()) {
                       bus.broadcast(Entry::new_timed_event(Event::Panic, 0, pc, 0));
                       panic!("pc: {:x}, timestamp: {}, insn: {:?}", pc, timestamp, insn_to_resolve);
                    }
                    let new_pc = (pc as i64 + compute_offset(insn_to_resolve) as i64) as u64;
                    bus.broadcast(Entry::new_timed_event(Event::TakenBranch, timestamp, pc, new_pc));
                    // trace!("pc before br: {:x}, after taken branch: {:x}", pc, new_pc);
                    pc = new_pc;
                }
                FHeader::FNt => {
                    if !BRANCH_OPCODES.contains(&insn_to_resolve.mnemonic().unwrap()) {
                        bus.broadcast(Entry::new_timed_event(Event::Panic, 0, pc, 0));
                        panic!("pc: {:x}, timestamp: {}, insn: {:?}", pc, timestamp, insn_to_resolve);
                    }
                    let new_pc = pc + insn_to_resolve.len() as u64;
                    bus.broadcast(Entry::new_timed_event(Event::NonTakenBranch, timestamp, pc, new_pc));
                    // trace!("pc before nt: {:x}, after nt: {:x}", pc, new_pc);
                    pc = new_pc;
                }
                FHeader::FIj => {
                    if !IJ_OPCODES.contains(&insn_to_resolve.mnemonic().unwrap()) {
                        bus.broadcast(Entry::new_timed_event(Event::Panic, 0, pc, 0));
                        panic!("pc: {:x}, timestamp: {}, insn: {:?}", pc, timestamp, insn_to_resolve);
                    }
                    let new_pc = (pc as i64 + compute_offset(insn_to_resolve) as i64) as u64;
                    bus.broadcast(Entry::new_timed_event(Event::InferrableJump, timestamp, pc, new_pc));
                    // trace!("pc before ij: {:x}, after ij: {:x}", pc, new_pc);
                    pc = new_pc;
                }
                FHeader::FUj => {
                    if !UJ_OPCODES.contains(&insn_to_resolve.mnemonic().unwrap()) {
                        bus.broadcast(Entry::new_timed_event(Event::Panic, 0, pc, 0));
                        panic!("pc: {:x}, timestamp: {}, insn: {:?}", pc, timestamp, insn_to_resolve);
                    }
                    let new_pc = refund_addr(packet.target_address ^ (pc >> 1));
                    bus.broadcast(Entry::new_timed_event(Event::UninferableJump, timestamp, pc, new_pc));
                    // trace!("pc before uj: {:x}, after uj: {:x}", pc, new_pc);
                    pc = new_pc;
                }
                _ => {
                    bus.broadcast(Entry::new_timed_event(Event::Panic, 0, pc, 0));
                    panic!("unknown FHeader: {:?}", packet.f_header);
                }
            }
            // log the timestamp
        }
    }

    drop(bus);
    println!("[Success] Decoded {} packets", packet_count);

    Ok(())
}

fn main() -> Result<()> {
    env_logger::init();
    let args = Args::parse();

    let mut bus: Bus<Entry> = Bus::new(BUS_SIZE);
    let mut receivers: Vec<Box<dyn AbstractReceiver>> = vec![];

    // add a receiver to the bus for stats output
    if args.to_stats {
        let encoded_trace_file = File::open(args.encoded_trace.clone())?;
        // get the file size
        let file_size = encoded_trace_file.metadata()?.len();
        // close the file
        drop(encoded_trace_file);
        let stats_bus_endpoint = bus.add_rx();
        receivers.push(Box::new(StatsReceiver::new(stats_bus_endpoint, BrMode::from(args.br_mode), file_size)));
    }
    
    // add a receiver to the bus for txt output
    if args.to_txt {
        let txt_bus_endpoint = bus.add_rx();
        receivers.push(Box::new(TxtReceiver::new(txt_bus_endpoint)));
    }

    // add a receiver to the bus for json output
    if args.to_json {
        let json_bus_endpoint = bus.add_rx();
        receivers.push(Box::new(JsonReceiver::new(json_bus_endpoint)));
    }

    if args.to_afdo {
        let afdo_bus_endpoint = bus.add_rx();
        let mut elf_file = File::open(args.binary.clone())?;
        let mut elf_buffer = Vec::new();
        elf_file.read_to_end(&mut elf_buffer)?;
        let elf = object::File::parse(&*elf_buffer)?;
        receivers.push(Box::new(AfdoReceiver::new(afdo_bus_endpoint, elf.entry().clone())));
        drop(elf_file);
    }

    if args.to_gcda {
        let gcda_bus_endpoint = bus.add_rx();
        receivers.push(Box::new(GcdaReceiver::new(gcda_bus_endpoint, args.gcno.clone(), args.binary.clone())));
    }

    if args.to_speedscope {
        let speedscope_bus_endpoint = bus.add_rx();
        receivers.push(Box::new(SpeedscopeReceiver::new(speedscope_bus_endpoint, args.binary.clone())));
    }

    if args.to_vpp {
        let vpp_bus_endpoint = bus.add_rx();
        receivers.push(Box::new(VPPReceiver::new(vpp_bus_endpoint, args.binary.clone(), args.br_mode == 0)));
    }

    if args.to_foc {
        let foc_bus_endpoint = bus.add_rx();
        receivers.push(Box::new(FOCReceiver::new(foc_bus_endpoint, args.binary.clone())));
    }

    if args.to_vbb {
        let vbb_bus_endpoint = bus.add_rx();
        receivers.push(Box::new(VBBReceiver::new(vbb_bus_endpoint)));
    }

    let frontend_handle = thread::spawn(move || trace_decoder(&args, bus));
    let receiver_handles: Vec<_> = receivers.into_iter()
        .map(|mut receiver| thread::spawn(move || receiver.try_receive_loop()))
        .collect();

    // Handle frontend thread
    match frontend_handle.join() {
        Ok(result) => result?,
        Err(e) => {
            // still join the receivers
            for handle in receiver_handles {
                handle.join().unwrap();
            }
            println!("frontend thread panicked: {:?}", e);
            return Err(anyhow::anyhow!("Frontend thread panicked: {:?}", e));
        }
    }

    // Handle receiver threads
    for (i, handle) in receiver_handles.into_iter().enumerate() {
        if let Err(e) = handle.join() {
            return Err(anyhow::anyhow!("Receiver thread {} panicked: {:?}", i, e));
        }
    }

    Ok(())
}
