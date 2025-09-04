use crate::backend::event::{Entry, Event};
use crate::backend::abstract_receiver::{AbstractReceiver, BusReceiver};
use crate::backend::stack_unwinder::{StackUnwinder, SymbolInfo};
use bus::BusReader;
use std::fs::File;
use std::io::{BufWriter, Write};

pub struct AtomicReceiver {
    writer: BufWriter<File>,
    receiver: BusReceiver,
    unwinder: StackUnwinder,
    symbol_index: std::collections::BTreeMap<u64, SymbolInfo>,
    call_stack: Vec<SymbolInfo>,
    last_ts: u64,  // track most recent timestamp
}

impl AtomicReceiver {
    pub fn new(bus_rx: BusReader<Entry>, elf_path: String) -> Self {
        let unwinder = StackUnwinder::new(elf_path.clone()).unwrap();
        let mut symbol_index = std::collections::BTreeMap::new();
        for (&addr, info) in unwinder.func_symbol_map().iter() {
            symbol_index.insert(addr, info.clone());
        }
        AtomicReceiver {
            writer: BufWriter::new(File::create("trace.atomics.txt").unwrap()),
            receiver: BusReceiver { name: "atomics".into(), bus_rx, checksum: 0 },
            unwinder,
            symbol_index,
            call_stack: Vec::new(),
            last_ts: 0,
        }
    }

    /// Is this a load-reserved, store-conditional, or atomic memory operation?
    fn is_atomic_insn(insn: &rvdasm::insn::Insn) -> bool {
        let name = insn.get_name();
        name.starts_with("lr.")
         || name.starts_with("sc.")
         || name.starts_with("amo")
    }
}

impl AbstractReceiver for AtomicReceiver {
    fn bus_rx(&mut self) -> &mut BusReader<Entry> {
        &mut self.receiver.bus_rx
    }

    fn _bump_checksum(&mut self) {
        self.receiver.checksum += 1;
    }

    fn _receive_entry(&mut self, entry: Entry) {
        // If entry carries a timestamp, update last_ts
        if let Some(ts) = entry.timestamp {
            self.last_ts = ts;
        }
        // update the local call stack
        match entry.event {
            Event::InferrableJump | Event::TrapException | Event::TrapInterrupt => {
                let (ok, _, maybe_info) = self.unwinder.step_ij(entry.clone());
                if ok {
                    if let Some(info) = maybe_info {
                        self.call_stack.push(info);
                    }
                }
            }
            Event::UninferableJump | Event::TrapReturn => {
                let (ok, _, closed, opened) = self.unwinder.step_uj(entry.clone());
                if ok {
                    for _ in closed {
                        self.call_stack.pop();
                    }
                    if let Some(info) = opened {
                        self.call_stack.push(info);
                    }
                }
            }
            _ => {}
        }

        // if this entry carries an instruction, check for atomic ops
        if let Some(insn) = entry.insn {
            if AtomicReceiver::is_atomic_insn(&insn) {
                let ts = self.last_ts;
                let pc = entry.arc.0;
                // print the atomic instruction
                writeln!(self.writer, "[{:>10}] 0x{:08x}: {}", ts, pc, insn.to_string()).unwrap();
                // print call stack
                writeln!(self.writer, "  Call stack:").unwrap();
                for frame in &self.call_stack {
                    // find the start address for this frame
                    let addr = self.symbol_index.iter()
                        .find_map(|(&a, info)| if info.index == frame.index { Some(a) } else { None })
                        .unwrap_or(0);
                    writeln!(self.writer, "    {} @ 0x{:x}", frame.name, addr).unwrap();
                }
                writeln!(self.writer).unwrap();
            }
        }
    }

    fn _flush(&mut self) {
        self.writer.flush().unwrap();
    }
}
