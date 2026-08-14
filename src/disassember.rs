use iced_x86::{Decoder, DecoderOptions, FlowControl, Formatter, Instruction, IntelFormatter};
use std::fmt;

pub struct Disassemer {
    bit: u32,
}

impl Disassemer {
    pub fn make(bit: u32) -> Disassemer {
        Disassemer { bit }
    }

    pub fn decode_one(&self, data: &[u8], ip: u64) -> Option<MyInst> {
        let mut decoder = Decoder::new(self.bit, data, DecoderOptions::NONE);
        decoder.set_ip(ip);

        if !decoder.can_decode() {
            return None;
        }

        let instruction = decoder.decode();

        Some(MyInst::make(instruction))
    }
}

#[derive(Debug)]
pub struct MyInst(Instruction);

impl MyInst {
    pub fn make(inst: Instruction) -> MyInst {
        MyInst(inst)
    }

    pub fn stringity(&self) -> String {
        let mut formatter = IntelFormatter::new();
        let mut output = String::new();
        formatter.format(&self.0, &mut output);
        output
    }

    pub fn is_call(&self) -> bool {
        let flow = self.0.flow_control();
        flow == FlowControl::Call
    }

    pub fn is_indirct_call(&self) -> bool {
        let flow = self.0.flow_control();
        flow == FlowControl::IndirectCall
    }

    pub fn is_jmp(&self) -> bool {
        let flow = self.0.flow_control();
        flow == FlowControl::UnconditionalBranch
    }

    pub fn is_indirct_jmp(&self) -> bool {
        let flow = self.0.flow_control();
        flow == FlowControl::IndirectBranch
    }

    pub fn is_branch(&self) -> bool {
        let flow = self.0.flow_control();
        flow == FlowControl::ConditionalBranch
    }

    pub fn is_ret(&self) -> bool {
        let flow = self.0.flow_control();
        flow == FlowControl::Return
    }

    pub fn is_bb_terminal(&self) -> bool {
        let flow = self.0.flow_control();
        matches!(
            flow,
            FlowControl::ConditionalBranch
                | FlowControl::Return
                | FlowControl::UnconditionalBranch
                | FlowControl::IndirectBranch
                | FlowControl::Exception
                | FlowControl::Interrupt
                | FlowControl::XbeginXabortXend
        )
    }

    pub fn get_branch_target(&self) -> Option<u64> {
        // 检查是否是有目标的分支指令
        if matches!(
            self.0.flow_control(),
            FlowControl::UnconditionalBranch | FlowControl::ConditionalBranch | FlowControl::Call
        ) {
            Some(self.0.near_branch_target())
        } else {
            None
        }
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn next_ip(&self) -> u64 {
        self.0.next_ip()
    }
}

impl fmt::Display for MyInst {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "{:X}\t {}", self.0.ip(), self.stringity())?;
        Ok(())
    }
}
