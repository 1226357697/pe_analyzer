use crate::disassember::MyInst;
use std::fmt;

#[derive(Debug)]
pub struct BB {
    rva: u32,
    insts: Vec<MyInst>,
    is_complete: bool,
}

impl BB {
    pub fn make(rva: u32) -> BB {
        BB {
            rva,
            insts: Vec::new(),
            is_complete: false,
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

    pub fn set_complete(&mut self) {
        self.is_complete = true
    }

    pub fn is_complete(&self) -> bool {
        self.is_complete
    }

    pub fn iter(&self) -> std::slice::Iter<'_, MyInst> {
        self.insts.iter()
    }

    pub fn size(&self) -> usize {
        if !self.is_complete() {
            panic!("you're operating a not compete base block");
        }

        let last = self.last().unwrap();
        return last.ip() as usize + last.len() - self.rva() as usize;
    }

    pub fn contains(&self, rva: u32) -> bool {
        rva >= self.rva() && rva < self.size() as u32
    }

    pub fn split_at(&mut self, rva: u32) -> Option<BB> {
        if self.rva() <= rva && rva < self.rva() + self.size() as u32 {
            let mut new_bb = BB::make(rva);
            let idx = self.insts.iter().position(|e| e.ip() as u32 == rva)?;

            new_bb.insts = self.insts.split_off(idx);
            new_bb.set_complete();
            return Some(new_bb);
        }
        None
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
