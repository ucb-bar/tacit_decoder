use crate::backend::event::{Entry, Event};
use crate::backend::abstract_receiver::{AbstractReceiver, BusReceiver};
use crate::backend::stack_unwinder::StackUnwinder;

use bus::BusReader;
use std::fs::File;
use std::io::{BufWriter, Write};
use std::collections::HashMap;

#[derive(Hash, PartialEq, Eq, Clone)]
pub struct Path {
  addr: u64,
  path: Vec<bool>,
}

pub struct VPPReceiver {
  writer: BufWriter<File>,
  receiver: BusReceiver,
  stack_unwinder: StackUnwinder,
  // path -> time intervals
  path_records: HashMap<Path, Vec<u64>>,
  path_bb_records: HashMap<Path, Vec<Vec<u64>>>,
  curr_paths: Vec<Path>, // stack for currently in-progress paths
  start_timestamps: Vec<u64>, // stack for start timestamps of currently in-progress paths
  bb_timestamps: Vec<Vec<u64>>, // timestamps of each basic block
  use_bb_analysis: bool,
}

impl VPPReceiver {
  pub fn new(bus_rx: BusReader<Entry>, elf_path: String, use_bb_analysis: bool) -> Self {
    Self {
      writer: BufWriter::new(File::create("trace.vpp.txt").unwrap()),
      receiver: BusReceiver {
        name: "vpp".to_string(),
        bus_rx,
        checksum: 0,
      },
      stack_unwinder: StackUnwinder::new(elf_path).unwrap(),
      path_records: HashMap::new(),
      path_bb_records: HashMap::new(),
      curr_paths: Vec::new(),
      start_timestamps: Vec::new(),
      bb_timestamps: Vec::new(),
      use_bb_analysis: use_bb_analysis,
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
        let (success, _ , _) = self.stack_unwinder.step_ij(entry.clone());
        if success {
          // debug!("Starting new path on address {:#x}", entry.arc.1);
          self.curr_paths.push(Path {
            addr: entry.arc.1,
            path: Vec::new(),
          });
          self.start_timestamps.push(entry.timestamp.unwrap());
          if self.use_bb_analysis {
            self.bb_timestamps.push(vec![entry.timestamp.unwrap()]);
          }
        }
      }
      Event::UninferableJump => {
        let (success, frame_stack_size, _, _) = self.stack_unwinder.step_uj(entry.clone());
        // at least one path is closed
        if success {
          // we should close paths until frame_stack_size match
          while self.curr_paths.len() > frame_stack_size {
            let curr_path = self.curr_paths.pop().unwrap();
            let start_timestamp = self.start_timestamps.pop().unwrap();
            // if curr_path is contained in path_records, add the time interval to the record
            if let Some(path_record) = self.path_records.get_mut(&curr_path) {
              path_record.push(entry.timestamp.unwrap() - start_timestamp);
              if self.use_bb_analysis {
                let bb_timestamp = self.bb_timestamps.pop().unwrap();
                self.path_bb_records.get_mut(&curr_path).unwrap().push(bb_timestamp.iter().map(|&t| t - start_timestamp).collect());
              }
            }
            // otherwise, create a new record
            else {
              self.path_records.insert(curr_path.clone(), vec![entry.timestamp.unwrap() - start_timestamp]);
              if self.use_bb_analysis {
                let bb_timestamp = self.bb_timestamps.pop().unwrap();
                self.path_bb_records.insert(curr_path.clone(), Vec::new());
                self.path_bb_records.get_mut(&curr_path).unwrap().push(bb_timestamp.iter().map(|&t| t - start_timestamp).collect());
              }
            }
          }
        }
      }
      Event::TakenBranch => {
        if let Some(curr_path) = self.curr_paths.last_mut() {
          curr_path.path.push(true);
          if self.use_bb_analysis {
            self.bb_timestamps.last_mut().unwrap().push(entry.timestamp.unwrap());
          }
        }
      }
      Event::NonTakenBranch => {
        if let Some(curr_path) = self.curr_paths.last_mut() {
          curr_path.path.push(false);
          if self.use_bb_analysis {
            self.bb_timestamps.last_mut().unwrap().push(entry.timestamp.unwrap());
          }
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
      if self.use_bb_analysis {
        self.writer.write_all(format!("BB INTERVALS: {:?}\n", self.path_bb_records.get(path).unwrap()).as_bytes()).unwrap();
      }
      self.writer.write_all(b"\n").unwrap();
    }
    self.writer.flush().unwrap();
  }
}
