use crate::backend::event::{Entry, Event};
use crate::backend::abstract_receiver::{AbstractReceiver, BusReceiver};

use bus::BusReader;
use std::fs::File;
use std::io::{BufWriter, Write};
use std::collections::HashMap;

#[derive(Hash, PartialEq, Eq, Clone)]
pub struct BB {
  start_addr: u64,
  end_addr: u64,
}

pub struct VBBReceiver {
  writer: BufWriter<File>,
  receiver: BusReceiver,
  bb_records: HashMap<BB, Vec<u64>>,
  prev_addr: u64,
  prev_timestamp: u64,
}

impl VBBReceiver {
  pub fn new(bus_rx: BusReader<Entry>) -> Self {
    Self {
      writer: BufWriter::new(File::create("trace.vbb.txt").unwrap()),
      receiver: BusReceiver {
        name: "vbb".to_string(),
        bus_rx,
        checksum: 0,
      },
      bb_records: HashMap::new(),
      prev_addr: 0,
      prev_timestamp: 0,
    }
  }
}

impl AbstractReceiver for VBBReceiver {
  fn bus_rx(&mut self) -> &mut BusReader<Entry> {
    &mut self.receiver.bus_rx
  }

  fn _bump_checksum(&mut self) {
    self.receiver.checksum += 1;
  }

  fn _receive_entry(&mut self, entry: Entry) {
    match entry.event {
      Event::Start => {
        self.prev_addr = entry.arc.0;
        self.prev_timestamp = entry.timestamp.unwrap();
      }
      Event::InferrableJump | Event::UninferableJump | Event::TakenBranch | Event::NonTakenBranch => {
        let curr_addr = entry.arc.0;
        let curr_timestamp = entry.timestamp.unwrap();
        let bb = BB { start_addr: self.prev_addr, end_addr: curr_addr };
        if self.bb_records.contains_key(&bb) {
          self.bb_records.get_mut(&bb).unwrap().push(curr_timestamp - self.prev_timestamp);
        } else {
          self.bb_records.insert(bb, vec![curr_timestamp - self.prev_timestamp]);
        }
        self.prev_addr = entry.arc.1;
        self.prev_timestamp = curr_timestamp;
      }
      _ => {}
    }
  }

  fn _flush(&mut self) {
    for (bb, intervals) in self.bb_records.iter() {
      self.writer.write_all(format!("BB: {:#x}-{:#x}, INTERVALS: {:?}\n", bb.start_addr, bb.end_addr, intervals).as_bytes()).unwrap();
    }
    self.writer.flush().unwrap();
  }
}
