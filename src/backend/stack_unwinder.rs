use indexmap::IndexMap;
use std::collections::HashMap;

// objdump dependency
use capstone::prelude::*;
use capstone::arch::riscv::{ArchMode, ArchExtraMode};
use capstone::Insn;
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

pub fn decode_elf_instructions<'a>(
    elf: &'a object::File,
    cs: &'a Capstone,
) -> Result<Vec<capstone::Instructions<'a>>> {
    let mut all_decoded_insns = Vec::new();
    debug!("Processing executable ELF sections:");
    for section in elf.sections() {
        let name = section.name().unwrap_or("<unnamed>");
        let flags = section.flags();

        if let object::SectionFlags::Elf { sh_flags } = flags {
            if sh_flags & (SHF_EXECINSTR as u64) != 0 {
                let entry_point = section.address();
                let text_data = section.data()?;
                
                debug!("  Executable Section: {} at {:#x}", name, entry_point);
                // disassemble using the provided Capstone reference;
                let decoded_instructions = cs.disasm_all(&text_data, entry_point)?;
                debug!("[main] {}: found {} instructions", name, decoded_instructions.len());

                // Save the decoded instructions for later use.
                all_decoded_insns.push(decoded_instructions);
            }
        }
    }

    if all_decoded_insns.is_empty() {
        return Err(anyhow::anyhow!("No executable instructions found in ELF file"));
    }
    Ok(all_decoded_insns)
}

/// Given a slice of decoded instruction groups, build a map from instruction address
/// to a reference to the instruction. 
pub fn build_insn_map<'a>(
    decoded_insns: &'a [capstone::Instructions<'a>],
) -> HashMap<u64, &'a capstone::Insn<'a>> {
    let mut insn_map = HashMap::new();
    for group in decoded_insns {
        for insn in group.iter() {
            insn_map.insert(insn.address(), insn);
        }
    }
    insn_map
}

impl StackUnwinder {
    pub fn new(elf_path: String) -> Result<Self> {
        // Open and read the ELF file
        let mut elf_file = File::open(elf_path.clone())?;
        let mut elf_buffer = Vec::new();
        elf_file.read_to_end(&mut elf_buffer)?;
        let elf = object::File::parse(&*elf_buffer)?;
        assert!(elf.architecture() == object::Architecture::Riscv64);

        // Initialize Capstone disassembler.
        let cs = Capstone::new()
            .riscv()
            .mode(ArchMode::RiscV64)
            .extra_mode([ArchExtraMode::RiscVC].iter().copied())
            .detail(true)
            .build()?;

        // Use our new functions to decode instructions from all executable sections.
        let all_decoded_insns = decode_elf_instructions(&elf, &cs)?;
        let insn_refs_map = build_insn_map(&all_decoded_insns);

        // Create a map of address to instruction info from the insn_refs_map.
        let mut insn_map: HashMap<u64, InsnInfo> = HashMap::new();
        for (&addr, insn) in insn_refs_map.iter() {
            insn_map.insert(addr, InsnInfo::from(*insn));
        }

        // Create func_symbol_map.
        let mut func_symbol_map: IndexMap<u64, SymbolInfo> = IndexMap::new();
        // Re-read the ELF data for symbol processing.
        let elf_data = fs::read(elf_path.clone())?;
        let obj_file = object::File::parse(&*elf_data)?;
        // Convert the loader error into an anyhow error so that its error type is Send + Sync.
        let loader = Loader::new(elf_path.clone())
            .map_err(|e| anyhow::Error::msg(e.to_string()))?;
        let mut next_index = 0;

        // Build a set of all executable section indices.
        use std::collections::HashSet;
        let exe_section_indices: HashSet<_> = obj_file.sections()
            .filter_map(|section| {
                let flags = section.flags();
                if let object::SectionFlags::Elf { sh_flags } = flags {
                    if sh_flags & (SHF_EXECINSTR as u64) != 0 {
                        return Some(section.index());
                    }
                }
                None
            })
            .collect();

        // Iterate over all symbols from executable sections.
        for symbol in obj_file.symbols() {
            if let Some(section_index) = symbol.section_index() {
                if exe_section_indices.contains(&section_index) {
                    if let Ok(name) = symbol.name() {
                        // Skip dummy symbols
                        if !name.starts_with("$x") {
                            let func_addr = symbol.address();
                            if let Ok(Some(location)) = loader.find_location(func_addr) {
                                let loc: SourceLocation = SourceLocation::from_addr2line(Some(location));
                                let new_info = SymbolInfo {
                                    name: name.to_string(),
                                    index: next_index,
                                    line: loc.lines,
                                    file: loc.file.to_string(),
                                };

                                if let Some(existing) = func_symbol_map.get_mut(&func_addr) {
                                    // If the existing entry has an empty name and the new one does not,
                                    // update the entry.
                                    if existing.name.trim().is_empty() && !new_info.name.trim().is_empty() {
                                        debug!(
                                            "Updating symbol at {:#x} from an empty name to {}",
                                            func_addr, new_info.name
                                        );
                                        *existing = new_info;
                                    } else {
                                        warn!(
                                            "func_addr: {:#x} already in the map with name: {}",
                                            func_addr, existing.name
                                        );
                                        warn!("{} is alias and will be ignored", new_info.name);
                                    }
                                } else {
                                    func_symbol_map.insert(func_addr, new_info);
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

        debug!("Function Symbol Map:");
        for (addr, sym_info) in &func_symbol_map {
            debug!("Address: 0x{:x}, Name: {}", addr, sym_info.name);
        }




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
        // if we come in with an em
        if prev_insn.mnemonic == "ret" || (prev_insn.mnemonic == "c.jr" && prev_insn.op_str == "ra") {
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
