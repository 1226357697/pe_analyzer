use crate::disassember::MyInst;
use std::fmt;

pub struct BB {
    rva: u32,
    insts: Vec<MyInst>,
}

impl BB {
    pub fn make(rva: u32) -> BB {
        BB {
            rva,
            insts: Vec::new(),
        }
    }

    pub fn rva(&self) -> u32 {
        self.rva
    }

    pub fn last(&self) -> Option<&MyInst> {
        self.insts.last()
    }

    pub fn add_inst(&mut self, inst: MyInst) -> &MyInst {
        self.insts.push(inst);
        self.last().unwrap()
    }

    pub fn is_complete(&self) -> bool {
        if let Some(last) = self.last() {
            return last.is_bb_terminal();
        }
        false
    }

    pub fn iter(&self) -> std::slice::Iter<'_, MyInst> {
        self.insts.iter()
    }
}

impl fmt::Display for BB {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(
            f,
            "BB at RVA: 0x{:X}, 指令数: {}",
            self.rva,
            self.insts.len()
        )?;
        for (i, inst) in self.insts.iter().enumerate() {
            write!(f, "  {}", inst)?;
        }
        Ok(())
    }
}
