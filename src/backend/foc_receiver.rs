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

pub struct FOCReceiver {
  writer: BufWriter<File>,
  receiver: BusReceiver,
  stack_unwinder: StackUnwinder,
  // path -> time intervals
  path_records: HashMap<Path, Vec<u64>>,
  curr_path: Option<Path>,
  start_timestamp: u64,
  path_time: Vec<(Path, u64)>,
}

impl FOCReceiver {
  pub fn new(bus_rx: BusReader<Entry>, elf_path: String) -> Self {
    debug!("Creating FOCReceiver");
    Self {
      writer: BufWriter::new(File::create("trace.foc.txt").unwrap()),
      receiver: BusReceiver {
        name: "foc".to_string(),
        bus_rx,
        checksum: 0,
      },
      stack_unwinder: StackUnwinder::new(elf_path).unwrap(),
      path_records: HashMap::new(),
      curr_path: None,
      start_timestamp: 0,
      path_time: Vec::new(),
    }
  }
}

impl AbstractReceiver for FOCReceiver {
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
        if success && frame_stack_size == 1 {
          debug!("Starting new path on address {:#x}", entry.arc.1);
          self.curr_path = Some(Path {
            addr: entry.arc.1,
            path: Vec::new(),
          });
          self.start_timestamp = entry.timestamp.unwrap();
        }
      }
      Event::UninferableJump => {
        let (success, frame_stack_size, _) = self.stack_unwinder.step_uj(entry.clone());
        debug!("frame_stack_size: {}", frame_stack_size);
        if success && (frame_stack_size == 0) {
          debug!("frame_stack_size is {}", frame_stack_size);
          if let Some(curr_path) = self.curr_path.as_ref() {
            debug!("Closing path on current path {:#x}", curr_path.addr);
          } else {
            debug!("No current path");
          }
          debug!("Hello");
          let curr_path_ref = self.curr_path.as_ref();
          let curr_path_unwraped = curr_path_ref.unwrap();
          debug!("Closing path on current path {:#x}", curr_path_unwraped.addr);
          // if curr_path is contained in path_records, add the time interval to the record
          if let Some(path_record) = self.path_records.get_mut(&self.curr_path.as_ref().unwrap()) {
            path_record.push(entry.timestamp.unwrap() - self.start_timestamp);
          }
          // otherwise, create a new record
          else {
            self.path_records.insert(self.curr_path.as_ref().unwrap().clone(), vec![entry.timestamp.unwrap() - self.start_timestamp]);
          }
          self.path_time.push((self.curr_path.as_ref().unwrap().clone(), entry.timestamp.unwrap() - self.start_timestamp));
          self.curr_path = None;
        }
      }
      Event::TakenBranch => {
        if let Some(curr_path) = self.curr_path.as_mut() {
          curr_path.path.push(true);
        }
      }
      Event::NonTakenBranch => {
        if let Some(curr_path) = self.curr_path.as_mut() {
          curr_path.path.push(false);
        }
      }
      _ => {
        // ignore other events
      }
    }
  }

  fn _flush(&mut self) {
    // the first one is warmup
    // let first_entry = self.path_time.remove(0);
    // self.writer.write_all(format!("warmup   ,time: {},", first_entry.1).as_bytes()).unwrap();
    // self.writer.write_all(format!("PATH:{:#x}-", first_entry.0.addr).as_bytes()).unwrap();
    // self.writer.write_all(format!("{}", first_entry.0.path.iter()
    //     .map(|&b| if b { '1' } else { '0' })
    //     .collect::<String>())
    //     .as_bytes()).unwrap();
    // self.writer.write_all(b"\n").unwrap();
    for (i, (path, time)) in self.path_time.iter().enumerate() {
      // every first one is a cache warmup
      if i % 2 == 1 {
        let vq = (i-1) as f32 * 2.0 * std::f32::consts::PI / self.path_time.len() as f32;
        // format float to 3 decimal places
        let vq_str = format!("{:.3}", vq);
        self.writer.write_all(format!("vq: {},", vq_str).as_bytes()).unwrap();
        // time
        self.writer.write_all(format!("time: {},", time).as_bytes()).unwrap();
        // addr
        self.writer.write_all(format!("PATH:{:#x}-", path.addr).as_bytes()).unwrap();
        // path, each taken and not taken
        self.writer.write_all(format!("{}", path.path.iter()
            .map(|&b| if b { '1' } else { '0' })
            .collect::<String>())
            .as_bytes()).unwrap();
          self.writer.write_all(b"\n").unwrap();
      }
    }
    self.writer.flush().unwrap();
  }
}

