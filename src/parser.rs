use anyhow::{Context, Ok, Result as AnyhowResult, bail, ensure};
use iced_x86::{
    Code::Bndstx_mib_bnd,
    FlowControl::{self, Call},
    NumberFormattingOptions,
};
use log::{debug, error, info, warn};
use pelite::{
    image,
    pe::{Pe, headers::SectionHeader},
    pe64::PeFile,
};
use std::{
    collections::{BTreeMap, HashSet, VecDeque},
    ops::Mul,
};

use crate::base_block::BB;
use crate::disassember::Disassemer;
use crate::{
    disassember::{self, MyInst},
    object::Object,
};

#[derive(Debug)]
enum EntryKind {
    None = 0,
    EntryPoint,
    TlsCallback,
    ExportFunction,
    PData,
    Call,
    FallThrough,
    Branch,
    Jmp,
}

#[derive(Debug)]
struct Entry {
    kind: EntryKind,
    rva: u32,
}

struct CodeSegment {
    name: String,
    rva: u32,
    mem_size: u32,
    offset: u32,
    size: u32,
    data: Vec<u8>,
}

impl CodeSegment {
    fn make(pe: &PeFile, s: &SectionHeader) -> CodeSegment {
        CodeSegment {
            name: s.name().ok().unwrap_or("").to_string(),
            rva: s.VirtualAddress,
            mem_size: s.VirtualSize,
            offset: s.PointerToRawData,
            size: s.SizeOfRawData,
            data: pe
                .derva_slice(
                    s.VirtualAddress,
                    s.SizeOfRawData.min(s.VirtualSize) as usize,
                )
                .unwrap_or(&[])
                .to_vec(),
        }
    }

    fn contains_rva(&self, rva: u32) -> bool {
        rva >= self.rva && rva < self.rva + self.size
    }

    fn read(&self, rva: u32, size: u32) -> Option<&[u8]> {
        if !self.contains_rva(rva) {
            return None;
        }

        let offset = (rva - self.rva) as usize;
        if offset + size as usize > self.data.len() {
            return None;
        }

        Some(&self.data[offset..offset + size as usize])
    }

    fn read_into(&self, rva: u32, buffer: &mut [u8]) -> usize {
        let offset = (rva - self.rva) as usize;
        if offset >= self.data.len() {
            return 0; // rva落在segment声明范围内，但实际数据不够长（比如.bss这类无原始数据的段）
        }

        let available = &self.data[offset..]; // 零拷贝，只是切片视图
        let copy_len = std::cmp::min(buffer.len(), available.len());
        buffer[..copy_len].copy_from_slice(&available[..copy_len]); // 唯一一次真正的内存拷贝
        copy_len
    }
}
struct ParserContext<'a> {
    pe: &'a PeFile<'a>,
    disassember: Disassemer,
    code_sections: Vec<CodeSegment>,

    seen_rvas: HashSet<u32>,
    work_list: VecDeque<Entry>,

    bb_map: BTreeMap<u32, BB>,
}

impl<'a> ParserContext<'a> {
    fn make(pe: &'a PeFile<'a>) -> ParserContext<'a> {
        ParserContext {
            pe,
            disassember: disassember::Disassemer::make(64),
            code_sections: Vec::new(),
            seen_rvas: HashSet::new(),
            work_list: VecDeque::new(),
            bb_map: BTreeMap::new(),
        }
    }

    fn read_code_bytes(&self, rva: u32, buffer: &mut [u8]) -> usize {
        let segment = match self.code_sections.iter().find(|seg| seg.contains_rva(rva)) {
            Some(seg) => seg,
            None => return 0, // 没找到segment，读到0字节
        };

        segment.read_into(rva, buffer) // 直接返回实际写入的字节数
    }
}

pub struct PEParser {
    file_map: pelite::FileMap,
}

impl PEParser {
    pub fn make(path: &str) -> AnyhowResult<Self> {
        let file_map = pelite::FileMap::open(path)?;
        PeFile::from_bytes(&file_map).context("Failed to parse PE file")?;

        Ok(PEParser { file_map })
    }

    fn parse_base_information(&self, pe: &PeFile, object: &mut Object) -> AnyhowResult<()> {
        let nt_headers = pe.nt_headers();

        match nt_headers.OptionalHeader.Magic {
            image::IMAGE_NT_OPTIONAL_HDR32_MAGIC => {
                object.model = crate::object::Model::Win32;
                object.bit = crate::object::Bit::Bit32;
            }
            image::IMAGE_NT_OPTIONAL_HDR64_MAGIC => {
                object.model = crate::object::Model::Win64;
                object.bit = crate::object::Bit::Bit64;
            }
            _ => {
                bail!("Unknown PE format");
            }
        }

        object.entry_point = nt_headers.OptionalHeader.AddressOfEntryPoint;
        object.imagebase = nt_headers.OptionalHeader.ImageBase;

        Ok(())
    }

    fn collect_known_entry(&self, ctx: &ParserContext) -> Vec<Entry> {
        let pe: &PeFile<'_> = ctx.pe;
        let mut known_entrys = Vec::<Entry>::new();
        // entry point
        known_entrys.push(Entry {
            kind: EntryKind::EntryPoint,
            rva: pe.optional_header().AddressOfEntryPoint,
        });

        // export functions
        if let Some(f) = pe.exports().ok().and_then(|e| e.functions().ok()) {
            known_entrys.extend(f.iter().map(|f| Entry {
                kind: EntryKind::ExportFunction,
                rva: *f,
            }))
        }

        // exception functions

        // tls functions
        known_entrys
    }

    fn make_bb(&self, ctx: &mut ParserContext, rva: u32) -> Option<BB> {
        let disasm = &ctx.disassember;
        let mut buffer: [u8; 16] = [0; 16];
        let mut ip = rva;

        let read_bytes = ctx.read_code_bytes(ip, &mut buffer);
        if read_bytes == 0 {
            return None;
        }

        let mut bb = BB::make(rva);

        while let Some(inst) = disasm.decode_one(&buffer, ip as u64) {
            let inst = bb.add_inst(inst);

            if inst.is_bb_terminal() {
                bb.set_complete();
                break;
            }

            ip += inst.len() as u32;
            if ctx.read_code_bytes(ip, &mut buffer) == 0 {
                break;
            }
        }
        Some(bb)
    }

    fn split_bb(&self, ctx: &mut ParserContext, start: u32, rva: u32) {
        let bb = ctx
            .bb_map
            .get_mut(&start)
            .expect(format!("can't find base block at {}", start).as_str());
        if let Some(new_bb) = bb.split_at(rva) {
            ctx.bb_map.insert(rva, new_bb);
        }
    }

    fn get_or_make_bb<'a>(&self, ctx: &'a mut ParserContext, rva: u32) -> Option<(bool, &'a BB)> {
        if ctx.bb_map.contains_key(&rva) {
            return Some((false, ctx.bb_map.get(&rva)?));
        }

        if let Some(start) = find_containing(ctx, rva) {
            let start_rva = start.0;
            self.split_bb(ctx, start_rva, rva); // 传 u32，不传引用
            return Some((false, ctx.bb_map.get(&rva)?));
        }

        let bb = self.make_bb(ctx, rva)?;
        ctx.bb_map.insert(rva, bb);
        Some((true, ctx.bb_map.get(&rva)?))
    }

    fn walk_entry(&self, ctx: &mut ParserContext, rva: u32) {
        if let Some(result) = self.get_or_make_bb(ctx, rva) {
            let created = result.0;
            let bb = result.1;
            if !bb.is_complete() {
                warn!("got a uncomplete bb at {:?}", bb.rva());
            }
            let mut tmp_entrys: Vec<Entry> = Vec::new();
            // 收集 call语义
            let call_entrys: Vec<_> = bb
                .iter()
                .filter(|i| i.is_call() && !i.is_indirct_call())
                .map(|i| Entry {
                    kind: EntryKind::Call,
                    rva: i
                        .get_branch_target()
                        .expect("this call hasn't target value") as u32,
                })
                .collect();
            tmp_entrys.extend(call_entrys);

            if let Some(last) = bb.last() {
                if last.is_branch() {
                    // 探索两个分支
                    let next_ip = last.next_ip();
                    let target_ip = last
                        .get_branch_target()
                        .expect("this branch hasn't target value");

                    tmp_entrys.push(Entry {
                        kind: EntryKind::FallThrough,
                        rva: next_ip as u32,
                    });

                    tmp_entrys.push(Entry {
                        kind: EntryKind::Branch,
                        rva: target_ip as u32,
                    });
                }

                if last.is_jmp() {
                    // 探索目标
                    let target_ip = last
                        .get_branch_target()
                        .expect("this branch hasn't target value");
                    tmp_entrys.push(Entry {
                        kind: EntryKind::Jmp,
                        rva: target_ip as u32,
                    });
                }
            }
            ctx.work_list.extend(tmp_entrys);
        }
    }

    fn parse_functions(&self, pe: &PeFile) -> AnyhowResult<()> {
        let mut ctx = ParserContext::make(pe);

        // collcect code segment
        ctx.code_sections = pe
            .section_headers()
            .iter()
            .filter(|s| (s.Characteristics & image::IMAGE_SCN_MEM_EXECUTE) != 0)
            .map(|s| CodeSegment::make(pe, s))
            .collect();

        let known_entry = self.collect_known_entry(&ctx);
        debug!("known_entry: {:X?}", known_entry);
        ctx.work_list.extend(known_entry);

        while !ctx.work_list.is_empty() {
            let e = ctx.work_list.pop_front().unwrap();
            if ctx.seen_rvas.contains(&e.rva) {
                continue;
            }
            ctx.seen_rvas.insert(e.rva);

            // parse function at rva
            debug!("Parsing function at RVA: 0x{:X}", e.rva);
            self.walk_entry(&mut ctx, e.rva);
        }

        // for item in ctx.bb_map.iter() {
        //     if !item.1.is_complete() {
        //         warn!("found a not complete bb at {:X?}", item.0);
        //     }
        // }

        Ok(())
    }

    pub fn parse(&self, object: &mut Object) -> AnyhowResult<()> {
        let pe = PeFile::from_bytes(self.file_map.as_ref())?;
        let dos_header = pe.dos_header();
        let nt_headers = pe.nt_headers();

        ensure!(
            dos_header.e_magic == image::IMAGE_DOS_SIGNATURE,
            "Invalid DOS signature"
        );
        ensure!(
            nt_headers.Signature == image::IMAGE_NT_HEADERS_SIGNATURE,
            "Invalid NT signature"
        );

        self.parse_base_information(&pe, object)?;
        self.parse_functions(&pe)?;

        Ok(())
    }
}

fn find_containing<'a>(ctx: &'a mut ParserContext, rva: u32) -> Option<(u32, &'a BB)> {
    ctx.bb_map
        .range(..=rva)
        .next_back()
        .filter(|(_, bb)| bb.contains(rva))
        .map(|(&start, bb)| (start, bb))
}
