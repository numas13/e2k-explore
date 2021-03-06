use anyhow::{bail, format_err, Context, Result};
use clap::{
    app_from_crate, crate_authors, crate_description, crate_name, crate_version, Arg, SubCommand,
};
use e2k_arch::raw::{Packed, Unpacked};
use e2k_arch::Bundle;
use goblin::{
    elf::{section_header::SHT_PROGBITS, Elf, Sym},
    Object,
};
use regex::RegexSet;
use std::error::Error;
use std::{env, fs};

const MACHINE_E2K_TYPE: u16 = 0xaf;

pub fn reset_signal_pipe_handler() -> Result<()> {
    #[cfg(target_family = "unix")]
    {
        use nix::sys::signal;

        unsafe {
            signal::signal(signal::Signal::SIGPIPE, signal::SigHandler::SigDfl)?;
        }
    }

    Ok(())
}

fn main() -> Result<()> {
    reset_signal_pipe_handler()?;

    let matches = app_from_crate!()
        .arg(
            Arg::with_name("force")
                .short("f")
                .long("force")
                .help("Suppress machine type checking"),
        )
        .subcommand(
            SubCommand::with_name("dump")
                .about("Dump ELF or binary file")
                .arg(
                    Arg::with_name("filter")
                        .short("f")
                        .long("filter")
                        .takes_value(true)
                        .multiple(true)
                        .number_of_values(1)
                        .help("Regex symbol filter"),
                )
                .arg(
                    Arg::with_name("target")
                        .short("t")
                        .long("target")
                        .help("File type")
                        .takes_value(true)
                        .possible_values(&["elf", "binary"]),
                )
                .arg(
                    Arg::with_name("section")
                        .short("x")
                        .long("section")
                        .help("Section name to dump")
                        .takes_value(true)
                        .conflicts_with("filter"),
                )
                .arg(
                    Arg::with_name("disassemble")
                        .long("disassemble")
                        .help("Try to disassemble"),
                )
                .arg(
                    Arg::with_name("file")
                        .takes_value(true)
                        .help("File to explore"),
                ),
        )
        .get_matches();

    let forced = matches.is_present("force");

    if let ("dump", Some(matches)) = matches.subcommand() {
        let disassemble = matches.is_present("disassemble");
        let path = matches.value_of("file").unwrap_or("a.out");
        let data = fs::read(&path).with_context(|| format_err!("failed to read file {}", path))?;

        let target = matches
            .value_of("target")
            .unwrap_or_else(|| detect_file(&data));

        match target {
            "elf" => {
                let elf = match Object::parse(&data)? {
                    Object::Elf(elf) => elf,
                    _ => bail!("Unsupported file type"),
                };
                if !forced && elf.header.e_machine != MACHINE_E2K_TYPE {
                    bail!("Unsupported machine type")
                }
                if let Some(name) = matches.value_of("section") {
                    dump_elf_section(disassemble, &data, &elf, name)?;
                } else {
                    let filters: Vec<_> = matches
                        .values_of("filter")
                        .map(|i| i.collect())
                        .unwrap_or_default();
                    DumpElfSyms::new(disassemble, &filters, &data, &elf)?.dump_syms()?;
                }
            }
            "binary" => dump_slice(disassemble, 0, &data)?,
            _ => unreachable!(),
        }
    }

    Ok(())
}

fn detect_file(data: &[u8]) -> &'static str {
    const ELF_MAGIC: &[u8] = &[0x7f, 0x45, 0x4c, 0x46];
    if data.len() > 4 && &data[0..4] == ELF_MAGIC {
        "elf"
    } else {
        "binary"
    }
}

fn dump_elf_section(disassemble: bool, data: &[u8], elf: &Elf, name: &str) -> Result<()> {
    let sh = elf
        .section_headers
        .iter()
        .find(|i| {
            if i.sh_name != 0 {
                &elf.shdr_strtab[i.sh_name] == name
            } else {
                false
            }
        })
        .ok_or_else(|| format_err!("section {} not found", name))?;
    let start = sh.sh_offset as usize;
    let end = start + sh.sh_size as usize;
    dump_slice(disassemble, sh.sh_offset, &data[start..end])
}

struct DumpElfSyms<'a> {
    disassemble: bool,
    filters: RegexSet,
    data: &'a [u8],
    elf: &'a Elf<'a>,
}

impl<'a> DumpElfSyms<'a> {
    fn new(disassemble: bool, filters: &[&str], data: &'a [u8], elf: &'a Elf) -> Result<Self> {
        let filters = RegexSet::new(filters)?;
        Ok(DumpElfSyms {
            disassemble,
            filters,
            data,
            elf,
        })
    }

    fn dump_syms(&self) -> Result<()> {
        for i in self.elf.syms.iter() {
            let name = match i.st_name {
                0 => None,
                _ => Some(&self.elf.strtab[i.st_name]),
            };
            self.dump_sym(name, i)?;
        }
        for i in self.elf.dynsyms.iter() {
            let name = match i.st_name {
                0 => None,
                _ => Some(&self.elf.dynstrtab[i.st_name]),
            };
            self.dump_sym(name, i)?;
        }
        Ok(())
    }

    fn dump_sym(&self, name: Option<&str>, entry: Sym) -> Result<()> {
        if entry.st_shndx == 0
            || !entry.is_function()
            || (!self.filters.is_empty() && !name.map_or(true, |i| self.filters.is_match(i)))
        {
            return Ok(());
        }
        let sh = match self.elf.section_headers.get(entry.st_shndx) {
            Some(sh) => sh,
            None => return Ok(()),
        };
        if sh.sh_type != SHT_PROGBITS {
            return Ok(());
        }
        let offset = sh.sh_offset + (entry.st_value - sh.sh_addr);
        let start = offset as usize;
        let end = start + entry.st_size as usize;
        let src = &self.data[start..end];
        match name {
            Some(name) => println!("{:016x} {}:\n", offset, name),
            None => println!("{:016x}:\n", offset),
        }
        dump_slice(self.disassemble, offset, src)
    }
}

fn dump_slice(disassemble: bool, mut addr: u64, data: &[u8]) -> Result<()> {
    let mut cur = data;
    while !cur.is_empty() {
        match Packed::from_bytes(cur)
            .map_err(|e| format_err!("failed to pre-decode bundle, error: {}", e))
        {
            Ok((packed, tail)) => {
                let src = packed.as_slice();
                DumpBundle::new(disassemble, addr, packed)?.dump();
                addr += src.len() as u64;
                cur = tail;
            }
            Err(e) => {
                print!("error: {}", e);
                break;
            }
        }
        println!();
    }
    Ok(())
}

struct DumpSlice<'a> {
    addr: u64,
    src: &'a [u8],
    offset: usize,
}

impl<'a> DumpSlice<'a> {
    fn print_word(&mut self) {
        let addr = self.addr + self.offset as u64;
        let s = &self.src[self.offset..self.offset + 4];
        print!(
            "{:08x}  {:02x} {:02x} {:02x} {:02x} ",
            addr, s[0], s[1], s[2], s[3]
        );
        self.offset += 4;
    }
}

struct DumpBundle<'a> {
    disassemble: bool,
    slice: DumpSlice<'a>,
    raw: Unpacked,
}

impl<'a> DumpBundle<'a> {
    fn new(disassemble: bool, addr: u64, packed: &'a Packed) -> Result<Self> {
        let src = packed.as_slice();
        let raw = Unpacked::unpack(packed)
            .map_err(|e| format_err!("failed to unpack bundle, error: {}", e))?;
        Ok(Self {
            disassemble,
            slice: DumpSlice {
                addr,
                src,
                offset: 0,
            },
            raw,
        })
    }

    fn dump(self) {
        let mut slice = self.slice;
        let raw = self.raw;
        if self.disassemble {
            match Bundle::from_unpacked(u8::MAX, &raw) {
                Ok(bundle) => println!("{}", bundle),
                Err(e) => {
                    eprintln!("[ERROR]: {}", e);
                    eprintln!("Caused by:");
                    for (i, e) in std::iter::successors(e.source(), |e| e.source()).enumerate() {
                        eprintln!("  {}: {}", i, e);
                    }
                    eprintln!();
                }
            }
        }
        let hs = raw.hs;
        let ss = raw.ss;
        slice.print_word();
        print!("{: >6} {:08x}", "HS", raw.hs.0);
        println!();
        if hs.ss() {
            slice.print_word();
            println!("{: >6} {:08x}", "SS", raw.ss.0);
        }
        for i in 0..6 {
            if hs.als_mask() & 1 << i != 0 {
                slice.print_word();
                print!("{: >5}{} {:08x}", "ALS", i, raw.als[i].0);
                if !hs.is_ales25() {
                    if i == 2 && hs.ales2() {
                        print!(" ALES2 bit extension");
                    } else if i == 5 && hs.ales5() {
                        print!(" ALES5 bit extension");
                    }
                }
                println!();
            }
        }
        if hs.cs0() {
            slice.print_word();
            println!("{: >6} {:08x}", "CS0", raw.cs0.0);
        }
        let offset_mid = hs.offset();
        let offset_cs1 = hs.cs1() as usize * 4;
        if slice.offset + offset_cs1 < offset_mid {
            slice.print_word();
            let ales2 = raw.ales[2].0;
            let ales5 = raw.ales[5].0;
            println!(" ALES2 {:04x}     ALES5 {:04x}", ales2, ales5);
        }
        slice.offset = offset_mid - 4;
        if hs.cs1() {
            slice.print_word();
            println!("{: >6} {:08x}", "CS1", raw.cs1.0);
        } else {
            slice.offset += 4;
        }

        let mut helper = DumpHelper::new(slice);
        for i in &[0, 1, 3, 4] {
            if hs.ales_mask() & 1 << *i != 0 {
                let ales = raw.ales[*i].0;
                helper.print(|| print!(" {: >4}{} {:04x}", "ALES", i, ales));
            }
        }

        for i in (0..4).step_by(2) {
            if ss.aas_mask() & 3 << i != 0 {
                let dst0 = raw.aas_dst[i];
                let dst1 = raw.aas_dst[i + 1];
                helper.print(|| print!(" {: >4}{} {:02x}{:02x}", "AAS", i / 2, dst0, dst1));
            }
        }
        for i in 0..4 {
            if ss.aas_mask() & 1 << i != 0 {
                let aas = raw.aas[i].0;
                helper.print(|| print!(" {: >4}{} {:04x}", "AAS", i + 2, aas));
            }
        }
        let mut slice = helper.finish();

        // align
        slice.offset = (slice.offset + 3) & !3;
        let lts_count = raw.lts_count();
        let pls_count = hs.pls_len() as usize;
        let cds_count = hs.cds_len() as usize;
        let tail_len = (lts_count + pls_count + cds_count) * 4;
        while slice.offset + tail_len < slice.src.len() {
            slice.print_word();
            println!();
        }

        for (i, lts) in raw.lts.iter().take(lts_count).enumerate().rev() {
            slice.print_word();
            println!("{: >5}{} {:08x}", "LTS", i, lts.unwrap());
        }
        for (i, pls) in raw.pls.iter().take(pls_count).enumerate().rev() {
            slice.print_word();
            println!("{: >5}{} {:08x}", "PLS", i, pls.0);
        }
        for (i, cds) in raw.cds.iter().take(cds_count).enumerate().rev() {
            slice.print_word();
            println!("{: >5}{} {:08x}", "CDS", i, cds.into_raw());
        }
    }
}

struct DumpHelper<'a> {
    next_word: bool,
    slice: DumpSlice<'a>,
}

impl<'a> DumpHelper<'a> {
    fn new(slice: DumpSlice<'a>) -> Self {
        Self {
            next_word: true,
            slice,
        }
    }

    fn print<F: FnMut()>(&mut self, mut f: F) {
        if self.next_word {
            self.slice.print_word();
            f();
        } else {
            print!("    ");
            f();
            println!();
        }
        self.next_word = !self.next_word;
    }

    fn finish(self) -> DumpSlice<'a> {
        if !self.next_word {
            println!();
        }
        self.slice
    }
}
