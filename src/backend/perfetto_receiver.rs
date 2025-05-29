use crate::backend::event::{Entry, Event};
use crate::backend::abstract_receiver::{AbstractReceiver, BusReceiver};
use crate::backend::stack_unwinder::{StackUnwinder, SymbolInfo};
use bus::BusReader;
use std::fs::File;
use std::io::{BufWriter, Write};
use serde_json::json;
use log::debug;

/// A Chrome Tracing (Perfetto) JSON receiver for RISC‑V trace decoding,
/// but using the unwinder’s stack as the ground truth.
pub struct PerfettoReceiver {
    writer: BufWriter<File>,
    receiver: BusReceiver,
    unwinder: StackUnwinder,
    events: Vec<String>,
    start_ts: u64,
    end_ts: u64,
    last_frames: Vec<u64>, // addresses of frame starts we saw last
}

impl PerfettoReceiver {
    pub fn new(bus_rx: BusReader<Entry>, elf_path: String) -> Self {
        debug!("PerfettoReceiver::new");
        let unwinder = StackUnwinder::new(elf_path).unwrap();
        PerfettoReceiver {
            writer: BufWriter::new(File::create("trace.perfetto.json").unwrap()),
            receiver: BusReceiver { name: "perfetto".into(), bus_rx, checksum: 0 },
            unwinder,
            events: Vec::new(),
            start_ts: 0,
            end_ts: 0,
            last_frames: Vec::new(),
        }
    }

    /// Diff last_frames vs the unwinder’s current_frame_addrs, and
    /// emit E- and B- events to catch up.
    fn diff_stack(&mut self, ts: u64) {
        let new_frames = self.unwinder.current_frame_addrs();
        // find common prefix
        let mut i = 0;
        while i < self.last_frames.len()
            && i < new_frames.len()
            && self.last_frames[i] == new_frames[i]
        {
            i += 1;
        }
        // pop any old frames beyond i
        for &addr in self.last_frames[i..].iter().rev() {
            let sym = self.unwinder.get_symbol_info(addr);
            let evt = json!({
                "name": sym.name,
                "cat": "function",
                "ph": "E",    // end
                "ts": ts,
                "pid": 0,
                "tid": 0,
                "args": {}
            });
            self.events.push(evt.to_string());
        }
        // push any new frames beyond i
        for &addr in &new_frames[i..] {
            let sym = self.unwinder.get_symbol_info(addr);
            let evt = json!({
                "name": sym.name,
                "cat": "function",
                "ph": "B",   // begin
                "ts": ts,
                "pid": 0,
                "tid": 0,
                "args": { "addr": format!("0x{:x}", addr) }
            });
            self.events.push(evt.to_string());
        }
        self.last_frames = new_frames;
    }
}

impl AbstractReceiver for PerfettoReceiver {
    fn bus_rx(&mut self) -> &mut BusReader<Entry> {
        &mut self.receiver.bus_rx
    }

    fn _bump_checksum(&mut self) {
        self.receiver.checksum += 1;
    }

    fn _receive_entry(&mut self, entry: Entry) {
        let ts = entry.timestamp.unwrap_or(0);
        match entry.event {
            Event::Start => {
                self.start_ts = ts;
            }
            Event::End => {
                self.end_ts = ts;
            }
            Event::InferrableJump
            | Event::TrapException
            | Event::TrapInterrupt
            | Event::UninferableJump
            | Event::TrapReturn => {
                // feed the unwinder
                if entry.event == Event::InferrableJump
                    || entry.event == Event::TrapException
                    || entry.event == Event::TrapInterrupt
                {
                    let _ = self.unwinder.step_ij(entry.clone());
                } else {
                    let _ = self.unwinder.step_uj(entry.clone());
                }
                // now diff and emit the proper B/E events
                self.diff_stack(ts);
            }
            _ => {}
        }
    }

    fn _flush(&mut self) {
        if self.end_ts == 0 {
            self.end_ts = self.start_ts;
        }

        // finally close any remaining frames
        // we simply treat this like ts = end_ts
        self.diff_stack(self.end_ts);

        // write out the combined traceEvents
        writeln!(self.writer, "{{").unwrap();
        writeln!(self.writer, "  \"traceEvents\": [").unwrap();
        for (i, ev) in self.events.iter().enumerate() {
            let comma = if i + 1 < self.events.len() { "," } else { "" };
            writeln!(self.writer, "    {}{}", ev, comma).unwrap();
        }
        writeln!(self.writer, "  ]").unwrap();
        writeln!(self.writer, "}}\n").unwrap();
        self.writer.flush().unwrap();
    }
}

