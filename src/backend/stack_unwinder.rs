use indexmap::IndexMap;
use std::collections::HashMap;

// objdump dependency
use rvdasm::disassembler::*;
use rvdasm::insn::*;
use object::{Object, ObjectSection, ObjectSymbol, SectionFlags};
use object::elf::SHF_EXECINSTR;

use std::fs::File;
use std::io::Read;
use gcno_reader::cfg::SourceLocation;

use std::fs;
use addr2line::Loader;

use log::{trace, debug, warn};
use anyhow::Result;

use crate::backend::event::{Entry, Event};

// everything you need to know about a symbol
#[derive(Clone)]
pub struct SymbolInfo {
    pub name: String,
    pub index: u32, 
    pub line: u32,
    pub file: String,
}

pub struct StackUnwinder {
    // addr -> symbol info <name, index, line, file>
    func_symbol_map: IndexMap<u64, SymbolInfo>,
    // index -> addr range
    idx_2_addr_range: IndexMap<u32, (u64, u64)>,
    // addr -> insn
    insn_map: HashMap<u64, Insn>,
    // stack model
    frame_stack: Vec<u32>, // Queue of index
}

impl StackUnwinder {
    pub fn new(elf_path: String) -> Result<Self> {
        // create insn_map
        let mut elf_file = File::open(elf_path.clone())?;
        let mut elf_buffer = Vec::new();
        elf_file.read_to_end(&mut elf_buffer)?;
        let elf = object::File::parse(&*elf_buffer)?;
        let elf_arch = elf.architecture();

        let xlen = if elf_arch == object::Architecture::Riscv64 {
            Xlen::XLEN64
        } else if elf_arch == object::Architecture::Riscv32 {
            Xlen::XLEN32
        } else {
            panic!("Unsupported architecture: {:?}", elf_arch);
        };

        let das = Disassembler::new(xlen);

        let mut insn_map = HashMap::new();
        for section in elf.sections() {
            if let object::SectionFlags::Elf { sh_flags } = section.flags() {
                if sh_flags & (SHF_EXECINSTR as u64) != 0 {
                    let addr = section.address();
                    let data = section.data()?;
                    let sec_map = das.disassemble_all(&data, addr);
                    debug!(
                        "section `{}` @ {:#x}: {} insns",
                        section.name().unwrap_or("<unnamed>"),
                        addr,
                        sec_map.len()
                    );
                    insn_map.extend(sec_map);
                }
            }
        }
        if insn_map.is_empty() {
            return Err(anyhow::anyhow!("No executable instructions found in ELF file"));
        }
        trace!("[StackUnwinder::new] found {} instructions", insn_map.len());
        
        // Re‑open ELF for symbol processing
        let elf_data = fs::read(&elf_path)?;
        let obj_file = object::File::parse(&*elf_data)?;
        let loader = Loader::new(&elf_path)
            .map_err(|e| anyhow::Error::msg(e.to_string()))?;

        // Gather indices of all executable sections
        let exec_secs: std::collections::HashSet<_> = obj_file
            .sections()
            .filter_map(|sec| {
                if let SectionFlags::Elf { sh_flags } = sec.flags() {
                    if sh_flags & (SHF_EXECINSTR as u64) != 0 {
                        return Some(sec.index());
                    }
                }
                None
            })
            .collect();

        // Build func_symbol_map from _all_ symbols in executable sections
        let mut func_symbol_map: IndexMap<u64, SymbolInfo> = IndexMap::new();
        let mut next_index = 0;
        for symbol in obj_file.symbols() {
            // only symbols tied to an exec section
            if let Some(sec_idx) = symbol.section_index() {
                if exec_secs.contains(&sec_idx) {
                    if let Ok(name) = symbol.name() {
                        if !name.starts_with("$x") {
                            let addr = symbol.address();
                            // lookup source location (may return None)
                            if let Ok(Some(loc)) = loader.find_location(addr) {
                                let src: SourceLocation = SourceLocation::from_addr2line(Some(loc));
                                let info = SymbolInfo {
                                    name: name.to_string(),
                                    index: next_index,
                                    line: src.lines,
                                    file: src.file.to_string(),
                                };
                                // dedupe aliases: prefer non‑empty over empty
                                if let Some(existing) = func_symbol_map.get_mut(&addr) {
                                    if existing.name.trim().is_empty() && !info.name.trim().is_empty() {
                                        *existing = info;
                                    } else {
                                        warn!(
                                            "func_addr 0x{:x} already in map as `{}`, ignoring alias `{}`",
                                            addr, existing.name, info.name
                                        );
                                    }
                                } else {
                                    func_symbol_map.insert(addr, info);
                                    next_index += 1;
                                }
                            }
                        }
                    }
                }
            }
        }

        // print the size of the func_symbol_map
        debug!("func_symbol_map size: {}", func_symbol_map.len());

        // sort the func_symbol_map by address
        let mut func_symbol_addr_sorted = func_symbol_map.keys().cloned().collect::<Vec<u64>>();
        func_symbol_addr_sorted.sort();
        
        // create the idx_2_addr_range map
        let mut idx_2_addr_range = IndexMap::new();
        for (addr, func_info) in func_symbol_map.iter() {
            let curr_position = func_symbol_addr_sorted.iter().position(|&x| x == *addr).unwrap();
            let next_position = if curr_position == func_symbol_addr_sorted.len() - 1 { 0 } else { curr_position + 1 };
            let next_addr = func_symbol_addr_sorted[next_position];
            idx_2_addr_range.insert(func_info.index, (addr.clone(), next_addr.clone()));
        }

        Ok(Self {
            func_symbol_map: func_symbol_map,
            idx_2_addr_range: idx_2_addr_range,
            insn_map: insn_map,
            frame_stack: Vec::new(),
        })
    }

    pub fn func_symbol_map(&self) -> &IndexMap<u64, SymbolInfo> {
        &self.func_symbol_map
    }
    
    // return (success, frame_stack_size, symbol_info)
    pub fn step_ij(&mut self, entry: Entry) -> (bool, usize, Option<SymbolInfo>) {
        assert!(entry.event == Event::InferrableJump || entry.event == Event::TrapException || entry.event == Event::TrapInterrupt);
        if self.func_symbol_map.contains_key(&entry.arc.1) {
            let frame_idx = self.func_symbol_map[&entry.arc.1].index;
            self.frame_stack.push(frame_idx);
            return (true, self.frame_stack.len(), Some(self.func_symbol_map[&entry.arc.1].clone()));
        } else {
            // warn!("step_ij: func_symbol_map does not contain the jump address: {:#x}", entry.arc.1);
            return (false, self.frame_stack.len(), None);
        }
    }

    pub fn step_uj(&mut self, entry: Entry) -> (bool, usize, Vec<SymbolInfo>, Option<SymbolInfo>) {
        assert!(entry.event == Event::UninferableJump || entry.event == Event::TrapReturn);
        // get the previous instruction - is it a ret or c.jr ra?
        let prev_insn = self.insn_map.get(&entry.arc.0).unwrap();
        let target_frame_addr = entry.arc.1;
        let mut closed_frames = Vec::new();
        // if we come in with an empty stack, we did not close any frames
        if self.frame_stack.is_empty() {
            return (false, self.frame_stack.len(), closed_frames, None);
        }
        if prev_insn.is_indirect_jump() {
            loop {
                // peek the top of the stack
                if let Some(frame_idx) = self.frame_stack.last() {
                    // if this function range is within the target frame range, we can stop
                    let (start, end) = self.idx_2_addr_range[frame_idx];
                    if target_frame_addr >= start && target_frame_addr < end {
                        return (true, self.frame_stack.len(), closed_frames, None);
                    }
                    // if not, pop the stack
                    if let Some(frame_idx) = self.frame_stack.pop() {
                        let func_start_addr = self.idx_2_addr_range[&frame_idx].0;
                        closed_frames.push(self.func_symbol_map[&func_start_addr].clone());
                    }
                // could have dropped to a frame outside the target range
                } else {
                    // is this a tail call?
                    if self.func_symbol_map.contains_key(&entry.arc.1) {
                        // push the new frame
                        self.frame_stack.push(self.func_symbol_map[&entry.arc.1].index);
                        return (true, self.frame_stack.len(), closed_frames, Some(self.func_symbol_map[&entry.arc.1].clone()));
                    } else {
                        return (true, self.frame_stack.len(), closed_frames, None);
                    }
                }
            } 
        } else {
            // not a return
            return (false, self.frame_stack.len(), closed_frames, None);
        }
    }

    pub fn flush(&mut self) -> Vec<SymbolInfo> {
        let mut closed_frames = Vec::new();
        while let Some(frame_idx) = self.frame_stack.pop() {
            trace!("closing frame while flushing: {}", frame_idx);
            closed_frames.push(self.func_symbol_map[&self.idx_2_addr_range[&frame_idx].0].clone());
        }
        closed_frames
    }

    pub fn get_symbol_info(&self, addr: u64) -> SymbolInfo {
        self.func_symbol_map[&addr].clone()
    }
}
