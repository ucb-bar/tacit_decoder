use rvdasm::insn::Insn;
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
    Panic
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
            Event::Panic => "Panic".to_string(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct Entry {
    pub event: Event,
    pub arc: (u64, u64), // from, to
    pub insn: Option<Insn>,
    pub timestamp: Option<u64>,
}

impl Entry {
    pub fn new_timed_event(event: Event, timestamp: u64, from: u64, to: u64) -> Self {
        Self { event, arc: (from, to), insn: None, timestamp: Some(timestamp) }
    }

    pub fn new_insn(insn: &Insn, address: u64) -> Self {
        Self { event: Event::None, arc: (address, address + insn.get_len() as u64), insn: Some(insn.clone()), timestamp: None }
    }

    pub fn new_timed_trap(trap_type: TrapType, timestamp: u64, from: u64, to: u64) -> Self {
        Self { event: Event::from_trap_type(trap_type), arc: (from, to), insn: None, timestamp: Some(timestamp) }
    }
}
