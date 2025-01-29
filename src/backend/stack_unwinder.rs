use indexmap::IndexMap;
use std::collections::HashMap;

// objdump dependency
use capstone::prelude::*;
use capstone::arch::riscv::{ArchMode, ArchExtraMode};
use capstone::Insn;
use object::{Object, ObjectSection, ObjectSymbol};

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

#[derive(Clone)]
pub struct InsnInfo {
    pub address: u64,
    pub len: usize,
    pub bytes: Vec<u8>,
    pub mnemonic: String,
    pub op_str: String,
}

impl<'a> From<&Insn<'a>> for InsnInfo {
    fn from(insn: &Insn<'a>) -> Self {
        Self {
            address: insn.address(),
            len: insn.len(),
            bytes: insn.bytes().to_vec(),
            mnemonic: insn.mnemonic().unwrap().to_string(),
            op_str: insn.op_str().unwrap().to_string(),
        }
    }
}

pub struct StackUnwinder {
    // addr -> symbol info <name, index, line, file>
    func_symbol_map: IndexMap<u64, SymbolInfo>,
    // index -> addr range
    idx_2_addr_range: IndexMap<u32, (u64, u64)>,
    // addr -> insn
    insn_map: HashMap<u64, InsnInfo>,
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
        assert!(elf.architecture() == object::Architecture::Riscv64);

        // Find the .text section (where the executable code resides)
        let text_section = elf.section_by_name(".text").ok_or_else(|| anyhow::anyhow!("No .text section found"))?;
        let text_data = text_section.data()?;
        let entry_point = elf.entry();

        let cs = Capstone::new()
            .riscv()
            .mode(ArchMode::RiscV64)
            .extra_mode([ArchExtraMode::RiscVC].iter().copied())
            .detail(true)
            .build()?;

        let decoded_instructions = cs.disasm_all(&text_data, entry_point)?;
        trace!("[StackUnwinder::new] found {} instructions", decoded_instructions.len());

        // create a map of address to instruction 
        let mut insn_map : HashMap<u64, InsnInfo> = HashMap::new();
        for insn in decoded_instructions.as_ref() {
            insn_map.insert(insn.address(), InsnInfo::from(insn));
        }

        // create func_symbol_map
        let mut func_symbol_map: IndexMap<u64, SymbolInfo> = IndexMap::new();
        // object handler
        let elf_data = fs::read(elf_path.clone()).unwrap();
        let obj_file = object::File::parse(&*elf_data).unwrap();
        let loader = Loader::new(elf_path.clone()).unwrap();
        let mut next_index = 0;
        
        // find the first text symbol and get its section
        let text_symbol = obj_file.symbols().find(|s| s.kind() == object::SymbolKind::Text).unwrap();
        let text_section = text_symbol.section();
        
        /*
        we cannot directly use s.kind() == object::SymbolKind::Text because it is not equivalent to section == .text
        the labels in assembly will be ommitted if we do so;
        instead, we filter by section == .text and then filter out the symbols that start with $x
        $x is a dummy symbol marking the march compilation options
         */
        for symbol in obj_file.symbols().filter(|s| s.section() == text_section && !s.name().unwrap().starts_with("$x")) {
            let func_addr = symbol.address();
            let loc: SourceLocation = SourceLocation::from_addr2line(loader.find_location(func_addr).unwrap());
            let func_info = SymbolInfo {
                name: String::from(symbol.name().unwrap()),
                index: next_index,
                line: loc.lines,
                file: String::from(loc.file),
            };
            // debug!("func_info: addr: {:#x}, name: {}, index: {}", func_addr, func_info.name, func_info.index);
            // check if the func_addr is already in the map
            if func_symbol_map.contains_key(&func_addr) {
                warn!("func_addr: {:#x} already in the map with name: {}", func_addr, func_symbol_map[&func_addr].name);
                warn!("{} is alias and will be ignored", func_info.name);
            } else {
                func_symbol_map.insert(func_addr, func_info);
                next_index += 1;
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

    pub fn step_uj(&mut self, entry: Entry) -> (bool, usize, Vec<SymbolInfo>) {
        assert!(entry.event == Event::UninferableJump || entry.event == Event::TrapReturn);
        // get the previous instruction - is it a ret or c.jr ra?
        let prev_insn = self.insn_map.get(&entry.arc.0).unwrap();
        let target_frame_addr = entry.arc.1;
        let mut closed_frames = Vec::new();
        // if we come in with an empty stack, we did not close any frames
        if self.frame_stack.is_empty() {
            return (false, self.frame_stack.len(), closed_frames);
        }
        // if we come in with an em
        if prev_insn.mnemonic == "ret" || (prev_insn.mnemonic == "c.jr" && prev_insn.op_str == "ra") {
            loop {
                // peek the top of the stack
                if let Some(frame_idx) = self.frame_stack.last() {
                    // if this function range is within the target frame range, we can stop
                    let (start, end) = self.idx_2_addr_range[frame_idx];
                    if target_frame_addr >= start && target_frame_addr < end {
                        return (true, self.frame_stack.len(), closed_frames);
                    }
                    // if not, pop the stack
                    if let Some(frame_idx) = self.frame_stack.pop() {
                        trace!("closing frame: {}", frame_idx);
                        let func_start_addr = self.idx_2_addr_range[&frame_idx].0;
                        closed_frames.push(self.func_symbol_map[&func_start_addr].clone());
                    } // if the stack is empty, we are done
                    else {
                        return (true, self.frame_stack.len(), closed_frames);
                    }
                // could have dropped to a frame outside the target range
                } else {
                    return (true, self.frame_stack.len(), closed_frames);
                }
            } 
        } else {
            // not a return
            return (false, self.frame_stack.len(), closed_frames);
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
