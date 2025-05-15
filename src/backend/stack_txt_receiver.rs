use crate::backend::event::{Entry, Event};
use crate::backend::abstract_receiver::{AbstractReceiver, BusReceiver};
use crate::backend::stack_unwinder::{StackUnwinder, SymbolInfo};
use bus::BusReader;
use std::fs::File;
use std::io::{BufWriter, Write};
use std::collections::BTreeMap;

pub struct StackTxtReceiver {
    writer: BufWriter<File>,
    receiver: BusReceiver,
    stack_unwinder: StackUnwinder,
    symbol_index: BTreeMap<u64, SymbolInfo>,
    // maintain local call stack
    call_stack: Vec<SymbolInfo>,
}

impl StackTxtReceiver {
    pub fn new(bus_rx: BusReader<Entry>, elf_path: String) -> Self {
        let stack_unwinder = StackUnwinder::new(elf_path.clone()).unwrap();
        let mut symbol_index = BTreeMap::new();
        for (&addr, info) in stack_unwinder.func_symbol_map().iter() {
            symbol_index.insert(addr, info.clone());
        }
        StackTxtReceiver {
            writer: BufWriter::new(File::create("trace.stack.txt").unwrap()),
            receiver: BusReceiver { name: "stacktxt".to_string(), bus_rx, checksum: 0 },
            stack_unwinder,
            symbol_index,
            call_stack: Vec::new(),
        }
    }

    fn lookup_symbol(&self, pc: u64) -> Option<(&u64, &SymbolInfo)> {
        self.symbol_index.range(..=pc).next_back()
    }
}

impl AbstractReceiver for StackTxtReceiver {
    fn bus_rx(&mut self) -> &mut BusReader<Entry> {
        &mut self.receiver.bus_rx
    }

    fn _bump_checksum(&mut self) {
        self.receiver.checksum += 1;
    }

    fn _receive_entry(&mut self, entry: Entry) {
        match entry.event {
            Event::InferrableJump | Event::TrapException | Event::TrapInterrupt => {
                let ts = entry.timestamp.unwrap_or(0);
                let pc = entry.arc.1;
                // update local stack
                let (success, _, maybe_info) = self.stack_unwinder.step_ij(entry.clone());
                if success {
                    if let Some(info) = maybe_info {
                        self.call_stack.push(info);
                    }
                }
                // lookup symbol
                let sym_desc = if let Some((start, info)) = self.lookup_symbol(pc) {
                    format!("{} @ 0x{:x}", info.name, start)
                } else {
                    format!("0x{:x}", pc)
                };
                writeln!(self.writer, "[timestamp: {}] {:?} -> {}", ts, entry.event, sym_desc).unwrap();
                writeln!(self.writer, "  Call stack:").unwrap();
                for frame in &self.call_stack {
                    writeln!(self.writer, "    {} @ 0x{:x}", frame.name, self.symbol_index.iter().find_map(|(&addr, inf)| if inf.index == frame.index { Some(addr) } else { None }).unwrap()).unwrap();
                }
                writeln!(self.writer).unwrap();
            }
            Event::UninferableJump | Event::TrapReturn => {
                let ts = entry.timestamp.unwrap_or(0);
                let pc = entry.arc.1;
                let (success, _, closed, opened) = self.stack_unwinder.step_uj(entry.clone());
                if success {
                    for _ in closed {
                        self.call_stack.pop();
                    }
                    if let Some(info) = opened {
                        self.call_stack.push(info);
                    }
                }
                let sym_desc = if let Some((start, info)) = self.lookup_symbol(pc) {
                    format!("{} @ 0x{:x}", info.name, start)
                } else {
                    format!("0x{:x}", pc)
                };
                writeln!(self.writer, "[timestamp: {}] {:?} -> {}", ts, entry.event, sym_desc).unwrap();
                writeln!(self.writer, "  Call stack:").unwrap();
                for frame in &self.call_stack {
                    writeln!(self.writer, "    {} @ 0x{:x}", frame.name, self.symbol_index.iter().find_map(|(&addr, inf)| if inf.index == frame.index { Some(addr) } else { None }).unwrap()).unwrap();
                }
                writeln!(self.writer).unwrap();
            }
            _ => {}
        }
    }

    fn _flush(&mut self) {
        self.writer.flush().unwrap();
    }
}
