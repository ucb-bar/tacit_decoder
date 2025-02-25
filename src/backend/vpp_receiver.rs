use crate::backend::event::{Entry, Event};
use crate::backend::abstract_receiver::{AbstractReceiver, BusReceiver};
use crate::backend::stack_unwinder::StackUnwinder;

use bus::BusReader;
use std::fs::File;
use std::io::{BufWriter, Write};
use std::collections::HashMap;
use log::debug;

#[derive(Hash, PartialEq, Eq, Clone)]
pub struct Path{
  addr: u64,
  path: Vec<bool>,
}

pub struct VPPReceiver {
  writer: BufWriter<File>,
  receiver: BusReceiver,
  stack_unwinder: StackUnwinder,
  // path -> time intervals
  path_records: HashMap<Path, Vec<u64>>,
  curr_paths: Vec<Path>,
  start_timestamp: u64,
}

impl VPPReceiver {
  pub fn new(bus_rx: BusReader<Entry>, elf_path: String) -> Self {
    debug!("Creating VPPReceiver");
    Self {
      writer: BufWriter::new(File::create("trace.vpp.txt").unwrap()),
      receiver: BusReceiver {
        name: "vpp".to_string(),
        bus_rx,
        checksum: 0,
      },
      stack_unwinder: StackUnwinder::new(elf_path).unwrap(),
      path_records: HashMap::new(),
      curr_paths: Vec::new(),
      start_timestamp: 0,
    }
  }
}

impl AbstractReceiver for VPPReceiver {
  fn bus_rx(&mut self) -> &mut BusReader<Entry> {
    &mut self.receiver.bus_rx
  }

  fn _bump_checksum(&mut self) {
    self.receiver.checksum += 1;
  }

  fn _receive_entry(&mut self, entry: Entry) {
    match entry.event {
      Event::InferrableJump => {
        let (success, frame_stack_size, _) = self.stack_unwinder.step_ij(entry.clone());
        if success {
          debug!("Starting new path on address {:#x}", entry.arc.1);
          self.curr_paths.push(Path {
            addr: entry.arc.1,
            path: Vec::new(),
          });
          self.start_timestamp = entry.timestamp.unwrap();
        }
      }
      Event::UninferableJump => {
        let (success, frame_stack_size, _, _) = self.stack_unwinder.step_uj(entry.clone());
        debug!("frame_stack_size: {}", frame_stack_size);
        // at least one path is closed
        if success {
          // we should close paths until frame_stack_size match
          while self.curr_paths.len() > frame_stack_size {
            let curr_path = self.curr_paths.pop().unwrap();
            debug!("Closing path on current path {:#x}", curr_path.addr);
            // if curr_path is contained in path_records, add the time interval to the record
            if let Some(path_record) = self.path_records.get_mut(&curr_path) {
              path_record.push(entry.timestamp.unwrap() - self.start_timestamp);
            }
            // otherwise, create a new record
            else {
              self.path_records.insert(curr_path.clone(), vec![entry.timestamp.unwrap() - self.start_timestamp]);
            }
          }
        }
      }
      Event::TakenBranch => {
        if let Some(curr_path) = self.curr_paths.last_mut() {
          curr_path.path.push(true);
        }
      }
      Event::NonTakenBranch => {
        if let Some(curr_path) = self.curr_paths.last_mut() {
          curr_path.path.push(false);
        }
      }
      _ => {
        // ignore other events
      }
    }
  }

  fn _flush(&mut self) {
    for (path, intervals) in self.path_records.iter() {
      // addr
      self.writer.write_all(format!("PATH:{:#x}-", path.addr).as_bytes()).unwrap();
      // path, each taken and not taken
      self.writer.write_all(format!("{}\n", path.path.iter()
          .map(|&b| if b { '1' } else { '0' })
          .collect::<String>())
          .as_bytes()).unwrap();
      // information about the path, can obtain from the stack unwinder
      let symbol_info = self.stack_unwinder.get_symbol_info(path.addr);
      self.writer.write_all(format!("INFO: {}: {}, line: {}\n", symbol_info.name, symbol_info.file, symbol_info.line).as_bytes()).unwrap();
      // intervals
      self.writer.write_all(format!("INTERVALS: {:?}\n", intervals).as_bytes()).unwrap();
      self.writer.write_all(b"\n").unwrap();
    }
    self.writer.flush().unwrap();
  }
}
