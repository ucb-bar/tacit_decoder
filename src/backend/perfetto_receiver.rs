use crate::backend::event::{Entry, Event};
use crate::backend::abstract_receiver::{AbstractReceiver, BusReceiver};
use crate::backend::stack_unwinder::StackUnwinder;
use bus::BusReader;
use std::fs::File;
use std::io::{BufWriter, Write};
use serde_json::json;
use log::debug;

/// A Chrome Tracing (Perfetto) JSON receiver for RISC‑V trace decoding.
pub struct PerfettoReceiver {
    writer: BufWriter<File>,
    receiver: BusReceiver,
    unwinder: StackUnwinder,
    events: Vec<String>,
    start_ts: u64,
    end_ts: u64,
}

impl PerfettoReceiver {
    /// Construct a new PerfettoReceiver, writing to `trace.perfetto.json`.
    pub fn new(bus_rx: BusReader<Entry>, elf_path: String) -> Self {
        debug!("PerfettoReceiver::new");
        let unwinder = StackUnwinder::new(elf_path.clone()).unwrap();
        PerfettoReceiver { 
            writer: BufWriter::new(File::create("trace.perfetto.json").unwrap()),
            receiver: BusReceiver { name: "perfetto".to_string(), bus_rx, checksum: 0 },
            unwinder,
            events: Vec::new(),
            start_ts: 0,
            end_ts: 0,
        }
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
        // Use timestamp if present, else 0
        let ts = entry.timestamp.unwrap_or(0);
        match entry.event {
            Event::Start => {
                self.start_ts = ts;
            }
            Event::End => {
                self.end_ts = ts;
            }
            Event::InferrableJump | Event::TrapException | Event::TrapInterrupt => {
                // Push a "B" event on call
                if let (true, _, Some(sym)) = self.unwinder.step_ij(entry.clone()) {
                    let evt = json!({
                        "name": sym.name,
                        "cat": "function",
                        "ph": "B",
                        "ts": ts,
                        "pid": 0,
                        "tid": 0,
                        "args": { "addr": format!("0x{:x}", entry.arc.1) }
                    });
                    self.events.push(evt.to_string());
                }
            }
            Event::UninferableJump | Event::TrapReturn => {
                // Pop frames on return
                let (success, _, closed, tail) = self.unwinder.step_uj(entry.clone());
                if success {
                    for sym in closed {
                        let evt = json!({
                            "name": sym.name,
                            "cat": "function",
                            "ph": "E",
                            "ts": ts,
                            "pid": 0,
                            "tid": 0,
                            "args": {}
                        });
                        self.events.push(evt.to_string());
                    }
                }
                // Tail-call: immediately push new frame
                if let Some(sym) = tail {
                    let evt = json!({
                        "name": sym.name,
                        "cat": "function",
                        "ph": "B",
                        "ts": ts,
                        "pid": 0,
                        "tid": 0,
                        "args": { "addr": format!("0x{:x}", entry.arc.1) }
                    });
                    self.events.push(evt.to_string());
                }
            }
            _ => {}
        }
    }

    fn _flush(&mut self) {
        // If no explicit end timestamp, use last event timestamp (approximate)
        if self.end_ts == 0 {
            if let Some(last) = self.events.last() {
                // best effort: reuse start_ts
                self.end_ts = self.start_ts;
            }
        }
        // Close any remaining open frames
        for sym in self.unwinder.flush() {
            let evt = json!({
                "name": sym.name,
                "cat": "function",
                "ph": "E",
                "ts": self.end_ts,
                "pid": 0,
                "tid": 0,
                "args": {}
            });
            self.events.push(evt.to_string());
        }

        // Write Chrome tracing JSON
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
