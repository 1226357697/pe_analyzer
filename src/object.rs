pub type Rva = u32;
pub type Offset = u32;
pub type Va = u64;

#[derive(Debug, Clone, Copy)]
pub enum Model {
    None = 0,
    Win32 = 1,
    Win64 = 2,
}

#[derive(Debug, Clone, Copy)]
pub enum Bit {
    None = 0,
    Bit32 = 1,
    Bit64 = 2,
}

pub struct Object {
    pub model: Model,
    pub bit: Bit,
    pub entry_point: Rva,
    pub imagebase: Va,
}

impl Object {
    pub fn make() -> Self {
        Object {
            model: Model::None,
            bit: Bit::None,
            entry_point: 0,
            imagebase: 0,
        }
    }

    pub fn print_base_info(&self) {
        println!("Model: {:?}", self.model);
        println!("Bit: {:?}", self.bit);
        println!("Entry Point: 0x{:X}", self.entry_point);
        println!("Image Base: 0x{:X}", self.imagebase);
    }

    pub fn print_all(&self) {
        self.print_base_info();
    }
}
