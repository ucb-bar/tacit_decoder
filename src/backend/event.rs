use capstone::Insn;
use crate::frontend::trap_type::TrapType;
use serde::Serialize;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum Event {
    None,
    Start,
    TakenBranch,
    NonTakenBranch,
    UninferableJump,
    InferrableJump,
    End,
    TrapException,
    TrapInterrupt,
    TrapReturn,
    BPHit,
    BPMiss,
}

impl Event {
    pub fn from_trap_type(trap_type: TrapType) -> Self {
        match trap_type {
            TrapType::TException => Event::TrapException,
            TrapType::TInterrupt => Event::TrapInterrupt,
            TrapType::TReturn => Event::TrapReturn,
            TrapType::TNone => panic!("TNone should not be converted to Event"),
        }
    }

    pub fn to_string(&self) -> String {
        match self {
            Event::None => "None".to_string(),
            Event::Start => "Start".to_string(),
            Event::TakenBranch => "TakenBranch".to_string(),
            Event::NonTakenBranch => "NonTakenBranch".to_string(),
            Event::UninferableJump => "UninferableJump".to_string(),
            Event::InferrableJump => "InferrableJump".to_string(),
            Event::End => "End".to_string(),
            Event::TrapException => "TrapException".to_string(),
            Event::TrapInterrupt => "TrapInterrupt".to_string(),
            Event::TrapReturn => "TrapReturn".to_string(),
            Event::BPHit => "BPHit".to_string(),
            Event::BPMiss => "BPMiss".to_string(),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Entry {
    pub event: Event,
    pub arc: (u64, u64), // from, to
    pub insn_bytes: Vec<u8>,
    pub insn_mnemonic: Option<String>,
    pub insn_op_str: Option<String>,
    pub insn_len: usize,
    pub timestamp: Option<u64>,
}

impl Entry {
    pub fn new_timed_event(event: Event, timestamp: u64, from: u64, to: u64) -> Self {
        Self { event, arc: (from, to), insn_bytes: vec![], insn_mnemonic: None, insn_op_str: None, insn_len: 0, timestamp: Some(timestamp) }
    }

    pub fn new_insn(insn: &Insn) -> Self {
        Self { event: Event::None, arc: (insn.address(), 0), insn_bytes: insn.bytes().to_vec(), insn_mnemonic: Some(insn.mnemonic().unwrap().to_string()), insn_op_str: Some(insn.op_str().unwrap().to_string()), insn_len: insn.len(), timestamp: None }
    }

    pub fn new_timed_trap(trap_type: TrapType, timestamp: u64, from: u64, to: u64) -> Self {
        Self { event: Event::from_trap_type(trap_type), arc: (from, to), insn_bytes: vec![], insn_mnemonic: None, insn_op_str: None, insn_len: 0, timestamp: Some(timestamp) }
    }
}
