use anyhow::{bail, format_err, Context, Error, Result};
use clap::{
    app_from_crate, crate_authors, crate_description, crate_name, crate_version, Arg, SubCommand,
};
use e2k_arch::raw::{Bundle, Packed};
use regex::RegexSet;
use std::{env, fs};
use xmas_elf::{
    header::{HeaderPt2, Machine},
    sections::SectionData,
    symbol_table::{Entry, Type},
    ElfFile,
};

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
                .help("Suppress machine type checkung"),
        )
        .subcommand(
            SubCommand::with_name("dump")
                .about("Dump ELF file")
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
                    Arg::with_name("file")
                        .takes_value(true)
                        .help("File to explore"),
                ),
        )
        .get_matches();

    let is_forced = matches.is_present("force");

    if let ("dump", Some(matches)) = matches.subcommand() {
        let path = matches.value_of("file").unwrap_or("a.out");
        let filters: Vec<_> = matches
            .values_of("filter")
            .map(|i| i.collect())
            .unwrap_or_default();
        let vec = fs::read(&path).with_context(|| format_err!("failed to read file {}", path))?;
        let elf = ElfFile::new(&vec).map_err(Error::msg)?;

        if !is_forced {
            match elf.header.pt2 {
                HeaderPt2::Header64(pt2) => match pt2.machine.as_machine() {
                    Machine::Other(MACHINE_E2K_TYPE) => (),
                    _ => bail!("Unsupported machine type"),
                },
                HeaderPt2::Header32(_) => bail!("Unsupported ELF file"),
            }
        }

        let dump = Dump {
            filters: RegexSet::new(&filters)?,
            elf: &elf,
        };

        for section in elf.section_iter() {
            match section.get_data(&elf).map_err(Error::msg)? {
                SectionData::SymbolTable64(entries) => {
                    for entry in entries {
                        dump.dump_entry(entry)?;
                    }
                }
                SectionData::DynSymbolTable64(entries) => {
                    for entry in entries {
                        dump.dump_entry(entry)?;
                    }
                }
                _ => (),
            }
        }
    }

    Ok(())
}

struct Dump<'a> {
    filters: RegexSet,
    elf: &'a ElfFile<'a>,
}

impl<'a> Dump<'a> {
    fn dump_entry<E: Entry>(&self, entry: &E) -> Result<()> {
        if entry.shndx() > 0 {
            if let Ok(Type::Func) = entry.get_type() {
                if let Err(e) = self.dump_func(entry) {
                    println!("error: {}", e);
                }
            }
        }

        Ok(())
    }

    fn dump_func<E: Entry>(&self, entry: &E) -> Result<()> {
        let name = entry.get_name(self.elf).map_err(Error::msg)?;
        if !self.filters.is_empty() && !self.filters.is_match(name) {
            return Ok(());
        }
        let section = entry
            .get_section_header(self.elf, entry.shndx() as usize)
            .map_err(Error::msg)?;
        let sec_offset = section.offset();
        let offset = entry.value() - section.address();
        let file_offset = sec_offset + offset;
        println!("{:016x} {}:\n", file_offset, name);
        match section.get_data(self.elf) {
            Ok(SectionData::Undefined(data)) => {
                let start = offset as usize;
                let end = start + entry.size() as usize;
                let src = &data[start..end];
                self.dump_slice(file_offset, src)?;
            }
            Ok(_) => (),
            Err(e) => {
                println!("failed to read section data, error {}\n", e);
            }
        }
        Ok(())
    }

    fn dump_slice(&self, mut addr: u64, data: &[u8]) -> Result<()> {
        let mut cur = data;
        while !cur.is_empty() {
            match Packed::from_slice(cur)
                .map_err(|e| format_err!("failed to pre-decode bundle, error: {}", e))
            {
                Ok((packed, tail)) => {
                    let src = packed.as_slice();
                    match Bundle::unpack(packed) {
                        Ok(bundle) => self.dump_bundle(addr, src, &bundle),
                        Err(e) => println!("failed to unpack bundle, error: {}", e),
                    }
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

    fn dump_bundle(&self, addr: u64, src: &[u8], bundle: &Bundle) {
        fn print_word(addr: u64, offset: &mut usize, src: &[u8]) {
            let s = &src[*offset..*offset + 4];
            print!(
                "{:08x}  {:02x} {:02x} {:02x} {:02x} ",
                addr + *offset as u64,
                s[0],
                s[1],
                s[2],
                s[3]
            );
            *offset += 4;
        }

        let mut offset = 0;

        print_word(addr, &mut offset, src);
        println!("{: >6} {:08x}", "HS", bundle.hs.0);
        if bundle.hs.ss() {
            print_word(addr, &mut offset, src);
            println!("{: >6} {:08x}", "SS", bundle.ss.0);
        }
        for i in 0..6 {
            if bundle.hs.als_mask() & 1 << i != 0 {
                print_word(addr, &mut offset, src);
                println!("{: >5}{} {:08x}", "ALS", i, bundle.als[i].0);
            }
        }
        if bundle.hs.cs0() {
            print_word(addr, &mut offset, src);
            println!("{: >6} {:08x}", "CS0", bundle.cs0.0);
        }
        let offset_mid = bundle.hs.offset();
        let offset_cs1 = bundle.hs.cs1() as usize * 4;
        if offset + offset_cs1 < offset_mid {
            print_word(addr, &mut offset, src);
            let ales2 = bundle.ales[2].unwrap_or_default().0;
            let ales5 = bundle.ales[5].unwrap_or_default().0;
            println!(" ALES2 {:04x}     ALES5 {:04x}", ales2, ales5);
        }
        offset = offset_mid - 4;
        if bundle.hs.cs1() {
            print_word(addr, &mut offset, src);
            println!("{: >6} {:08x}", "CS1", bundle.cs1.0);
        } else {
            offset += 4;
        }

        struct Helper<'a>(bool, &'a mut usize, &'a [u8]);
        impl<'a> Helper<'a> {
            fn print<F: FnMut()>(&mut self, addr: u64, mut f: F) {
                if self.0 {
                    print_word(addr, self.1, self.2);
                    f();
                } else {
                    print!("    ");
                    f();
                    println!();
                }
                self.0 = !self.0;
            }
            fn finish(&self) {
                if !self.0 {
                    println!();
                }
            }
        }
        let mut helper = Helper(true, &mut offset, src);
        for i in &[0, 1, 3, 4] {
            if bundle.hs.ales_mask() & 1 << *i != 0 {
                helper.print(addr, || {
                    let ales = bundle.ales[*i].unwrap_or_default().0;
                    print!(" {: >4}{} {:04x}", "ALES", i, ales)
                });
            }
        }

        for i in (0..4).step_by(2) {
            if bundle.ss.aas_mask() & 3 << i != 0 {
                helper.print(addr, || {
                    print!(
                        " {: >4}{} {:02x}{:02x}",
                        "AAS",
                        i / 2,
                        bundle.aas_dst[i],
                        bundle.aas_dst[i + 1],
                    )
                });
            }
        }
        for i in 0..4 {
            if bundle.ss.aas_mask() & 1 << i != 0 {
                helper.print(addr, || {
                    print!(" {: >4}{} {:04x}", "AAS", i + 2, bundle.aas[i].0)
                });
            }
        }
        helper.finish();

        // align
        offset = (offset + 3) & !3;
        let lts_count = bundle.get_max_lts_index().map_or(0, |i| i + 1) as usize;
        let pls_count = bundle.hs.pls_len() as usize;
        let cds_count = bundle.hs.cds_len() as usize;
        let tail_len = (lts_count + pls_count + cds_count) * 4;
        while offset + tail_len < src.len() {
            print_word(addr, &mut offset, src);
            println!();
        }

        for (i, lts) in bundle.lts.iter().take(lts_count).enumerate().rev() {
            print_word(addr, &mut offset, src);
            println!("{: >5}{} {:08x}", "LTS", i, lts.0);
        }
        for (i, pls) in bundle.pls.iter().take(pls_count).enumerate().rev() {
            print_word(addr, &mut offset, src);
            println!("{: >5}{} {:08x}", "PLS", i, pls.0);
        }
        for (i, cds) in bundle.cds.iter().take(cds_count).enumerate().rev() {
            print_word(addr, &mut offset, src);
            println!("{: >5}{} {:08x}", "CDS", i, cds.0);
        }
    }
}
