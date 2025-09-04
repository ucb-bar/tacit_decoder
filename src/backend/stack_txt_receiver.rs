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
}

impl StackTxtReceiver {
    pub fn new(bus_rx: BusReader<Entry>, elf_path: String) -> Self {
        let stack_unwinder = StackUnwinder::new(elf_path.clone()).unwrap();

        // Build a map from function start address -> SymbolInfo
        let mut symbol_index = BTreeMap::new();
        for (&addr, info) in stack_unwinder.func_symbol_map().iter() {
            symbol_index.insert(addr, info.clone());
        }

        StackTxtReceiver {
            writer: BufWriter::new(File::create("trace.stack.txt").unwrap()),
            receiver: BusReceiver { name: "stacktxt".into(), bus_rx, checksum: 0 },
            stack_unwinder,
            symbol_index,
        }
    }

    /// Look up the symbol whose start address is the greatest <= PC
    fn lookup_symbol(&self, pc: u64) -> Option<(&u64, &SymbolInfo)> {
        self.symbol_index.range(..=pc).next_back()
    }

    /// Helper to dump the current unwinder stack
    fn dump_current_stack(&mut self) -> std::io::Result<()> {
        writeln!(self.writer, "  Call stack:")?;
        // This requires you add to StackUnwinder:
        //    pub fn current_frame_addrs(&self) -> &[u64];
        for frame_addr in self.stack_unwinder.current_frame_addrs() {
            let info = &self.symbol_index[&frame_addr];
            writeln!(self.writer, "    {} @ 0x{:x}", info.name, frame_addr)?;
        }
        writeln!(self.writer)?;
        Ok(())
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

                // update the unwinder’s internal stack
                let _ = self.stack_unwinder.step_ij(entry.clone());

                // describe the new PC
                let sym_desc = if let Some((start, info)) = self.lookup_symbol(pc) {
                    format!("{} @ 0x{:x}", info.name, start)
                } else {
                    format!("0x{:x}", pc)
                };

                writeln!(self.writer, "[timestamp: {}] {:?} -> {}", ts, entry.event, sym_desc).unwrap();
                self.dump_current_stack().unwrap();
            }

            Event::UninferableJump | Event::TrapReturn => {
                let ts = entry.timestamp.unwrap_or(0);
                let pc = entry.arc.1;

                // pop/push via the unwinder
                let _ = self.stack_unwinder.step_uj(entry.clone());

                let sym_desc = if let Some((start, info)) = self.lookup_symbol(pc) {
                    format!("{} @ 0x{:x}", info.name, start)
                } else {
                    format!("0x{:x}", pc)
                };

                writeln!(self.writer, "[timestamp: {}] {:?} -> {}", ts, entry.event, sym_desc).unwrap();
                self.dump_current_stack().unwrap();
            }
            _ => {}
        }
    }

    fn _flush(&mut self) {
        self.writer.flush().unwrap();
    }
}
