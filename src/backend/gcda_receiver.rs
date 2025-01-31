  use crate::backend::event::{Entry, Event};
use crate::backend::abstract_receiver::{AbstractReceiver, BusReceiver};
use bus::BusReader;
use std::fs::File;
use std::io::BufWriter;
use gcno_reader::reader::GCNOReader;
use gcno_reader::cfg::{ControlFlowGraph, ReportedEdge, SourceLocation};
use indexmap::IndexMap;
use addr2line::Loader;
use object::{Object, ObjectSymbol};
use std::fs;
use log::{trace, debug};
pub struct GcdaReceiver {
  writer: BufWriter<File>,
  receiver: BusReceiver,
  edge_map: IndexMap<String, Vec<ReportedEdge>>,
  loader: Loader,
  func_symbol_map: IndexMap<u64, (String, u64)>,
  cfg: ControlFlowGraph,
}

impl GcdaReceiver {
  pub fn new(bus_rx: BusReader<Entry>, gcno_path: String, elf_path: String) -> Self {
    // gcno handler
    let mut gcno_reader = GCNOReader::new(gcno_path.clone()).unwrap();
    let gcno = gcno_reader.parse().unwrap();
    let cfg = ControlFlowGraph::from(gcno);
    // addr2line handler
    let loader = Loader::new(elf_path.clone()).unwrap();
    // object handler
    let elf_data = fs::read(elf_path.clone()).unwrap();
    let obj_file = object::File::parse(&*elf_data).unwrap();
    let edge_map = cfg.report_instrumented_edges();
    let mut func_symbol_map = IndexMap::new();
    for symbol in obj_file.symbols() {
      if symbol.kind() == object::SymbolKind::Text {
        let func_name = symbol.name().unwrap();
        let func_addr = symbol.address();
        if let Some((_name, edges)) = edge_map.iter().find(|(_, edges)| edges.iter().any(|e| e.entry && e.func_name == func_name)) {
          if let Some(_) = edges.iter().find(|e| e.entry && e.func_name == func_name) {
            func_symbol_map.insert(func_addr, (String::from(func_name), 0));
          }
        }
      }
    }

    Self { writer: BufWriter::new(File::create(gcno_path.clone().replace(".gcno", ".gcda")).unwrap()), 
          receiver: BusReceiver { name: "gcda".to_string(), bus_rx: bus_rx, checksum: 0 },
          edge_map: edge_map,
          loader: loader,
          func_symbol_map: func_symbol_map,
          cfg: cfg,
    }
  }
}

impl AbstractReceiver for GcdaReceiver {

  fn bus_rx(&mut self) -> &mut BusReader<Entry> {
    &mut self.receiver.bus_rx
  }

  fn _bump_checksum(&mut self) {
    self.receiver.checksum += 1;
  }

  fn _receive_entry(&mut self, entry: Entry) {
    match entry.event {
      Event::TakenBranch | Event::NonTakenBranch | Event::InferrableJump | Event::UninferableJump => {
        let from_source: SourceLocation = SourceLocation::from_addr2line(self.loader.find_location(entry.arc.0).unwrap());
        let to_source: SourceLocation = SourceLocation::from_addr2line(self.loader.find_location(entry.arc.1).unwrap());
        // match this to the edge map
        for (_, edges) in self.edge_map.iter_mut() {
          for edge in edges.iter_mut() {
            if edge.from.contains(&from_source) && edge.to.contains(&to_source) {
              edge.increment_count();
              // a special debug for function "FloorPowerOfTwo"
              if edge.func_name == "FloorPowerOfTwo" {
                debug!("edge count: {:?}", edge.count);
              }
            }
          }
        }
      }
      Event::None => {
        if let Some(edge_count) = self.func_symbol_map.get_mut(&entry.arc.0) {
          edge_count.1 += 1;
        }
      }
      _ => {}
    }
  }

  fn _flush(&mut self) {
    // merge the edge count with the edge map
    for (func_name, edges) in self.edge_map.iter_mut() {
      for edge in edges.iter_mut() {
        if edge.entry == true {
          for (_, (iter_func_name, count)) in self.func_symbol_map.iter() {
            if iter_func_name == func_name {
              trace!("merged entry edge for function: {:?}", func_name);
              edge.count += *count;
            }
          }
        }
      }
    }
    self.cfg.write_gcda(&self.edge_map, &mut self.writer);
  }
}
