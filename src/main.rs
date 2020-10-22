use anyhow::{bail, format_err, Context, Error, Result};
use clap::{
    app_from_crate, crate_authors, crate_description, crate_name, crate_version, Arg, SubCommand,
};
use e2k_arch::raw::Bundle;
use regex::RegexSet;
use std::{env, fmt, fs};
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
        .subcommand(
            SubCommand::with_name("dump")
                .about("Dump ELF file")
                .arg(
                    Arg::with_name("byte")
                        .short("b")
                        .long("byte")
                        .help("Display syllables as a sequence of bytes"),
                )
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

    if let ("dump", Some(matches)) = matches.subcommand() {
        let path = matches.value_of("file").unwrap_or("a.out");
        let filters: Vec<_> = matches
            .values_of("filter")
            .map(|i| i.collect())
            .unwrap_or_default();
        let vec = fs::read(&path).with_context(|| format_err!("failed to read file {}", path))?;
        let elf = ElfFile::new(&vec).map_err(Error::msg)?;

        match elf.header.pt2 {
            HeaderPt2::Header64(pt2) => match pt2.machine.as_machine() {
                Machine::Other(MACHINE_E2K_TYPE) => (),
                _ => bail!("Unsupported machine type"),
            },
            HeaderPt2::Header32(_) => bail!("Unsupported ELF file"),
        }

        let dump = Dump {
            filters: RegexSet::new(&filters)?,
            is_byte: matches.is_present("byte"),
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
    is_byte: bool,
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
        match section.get_data(self.elf) {
            Ok(SectionData::Undefined(data)) => {
                println!("function {}\n", name);
                let addr = (entry.value() - section.address()) as usize;
                self.dump_slice(&data[addr..addr + entry.size() as usize])?;
                println!();
            }
            Ok(_) => (),
            Err(e) => {
                println!("function {}", name);
                println!("failed to read section data, error {}\n", e);
            }
        }
        Ok(())
    }

    fn dump_slice(&self, data: &[u8]) -> Result<()> {
        let mut cur = data;
        while !cur.is_empty() {
            print!("  {:08x}", data.len() - cur.len());
            match Bundle::from_slice(cur)
                .map_err(|e| format_err!("failed to decode bundle, error: {}", e))
            {
                Ok((bundle, tail)) => {
                    self.dump_bundle(&bundle);
                    println!();
                    cur = tail;
                }
                Err(e) => {
                    println!("error: {}", e);
                    break;
                }
            }
        }
        Ok(())
    }

    fn dump_bundle(&self, bundle: &Bundle) {
        let print = |s, n| println!("{: >15} {}", s, Value(self.is_byte, n));
        let print_i = |s, i, n| println!("{: >14}{} {}", s, i, Value(self.is_byte, n));

        println!("{: >5} {}", "HS", Value(self.is_byte, bundle.hs.0));
        if bundle.hs.ss() {
            print("SS", bundle.ss.0)
        }
        if bundle.hs.cs0() {
            print("CS0", bundle.cs0.0)
        }
        if bundle.hs.cs1() {
            print("CS1", bundle.cs1.0)
        }
        for i in 0..6 {
            if bundle.hs.als_mask() & 1 << i != 0 {
                let als = Value(self.is_byte, bundle.als[i].0);
                print!("{: >14}{} {}", "ALS", i, als);
                if bundle.hs.ales_mask() & 1 << i != 0 {
                    print!("    ALES{} ", i);
                    if let Some(ales) = bundle.ales[i] {
                        print!("{}", Value(self.is_byte, ales.0));
                    } else {
                        print!("bit");
                    }
                }
                println!();
            }
        }
        for i in 0..4 {
            if bundle.ss.aas_mask() & 1 << i != 0 {
                let aas = Value(self.is_byte, bundle.aas[i].0);
                let dst = bundle.aas_dst[i];
                print!("{: >14}{} {}", "AAS", i + 2, aas,);
                if self.is_byte {
                    print!("  ");
                }
                println!("{: >11}{}{} {:02x}", "AAS", i / 2, i + 2, dst);
            }
        }
        for i in (0..4).rev() {
            match bundle.lts[i] {
                Some(lts) => print_i("LTS", i, lts.0),
                None => break,
            }
        }
        for i in (0..bundle.hs.pls_len() as usize).rev() {
            print_i("PLS", i, bundle.pls[i].0);
        }
        for i in (0..bundle.hs.cds_len() as usize).rev() {
            print_i("CDS", i, bundle.cds[i].0);
        }
    }
}

struct Value<T>(bool, T);

impl fmt::Display for Value<u32> {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        if self.0 {
            let b = self.1.to_le_bytes();
            write!(fmt, "{:02x} {:02x} {:02x} {:02x}", b[0], b[1], b[2], b[3])
        } else {
            write!(fmt, "{:08x}", self.1)
        }
    }
}

impl fmt::Display for Value<u16> {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        if self.0 {
            let b = self.1.to_le_bytes();
            write!(fmt, "{:02x} {:02x}", b[0], b[1])
        } else {
            write!(fmt, "{:04x}", self.1)
        }
    }
}
