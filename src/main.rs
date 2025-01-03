use std::path::{Path, PathBuf};

use clap::Parser;
use clap_num::maybe_hex;
use colored::Colorize;
use iced_x86::{Decoder, DecoderOptions, Formatter, Instruction, NasmFormatter};
use elf::ElfBytes;
use elf::endian::AnyEndian;
use elf::section::SectionHeader;

const ALIGNMENT_64: u64 = 64;
const ALIGNMENT_32: u64 = 32;
const ALIGNMENT_16: u64 = 16;

fn print_disassemble(begin: u64, code: &[u8]) {
    println!();
    let mut decoder =
        Decoder::with_ip(64, code, begin, DecoderOptions::NONE);

    let mut formatter = NasmFormatter::new();
    formatter.options_mut().set_digit_separator("_");
    formatter.options_mut().set_first_operand_char_index(10);

    let mut output = String::new();
    let mut instruction = Instruction::default();
    let mut red_64 = false;
    let mut green_32 = false;
    let mut cyan_16 = false;
    let mut prev_alignment_64 = 0;
    let mut prev_alignment_32 = 0;
    let mut prev_alignment_16 = 0;
    while decoder.can_decode() {
        decoder.decode_out(&mut instruction);
        output.clear();
        formatter.format(&instruction, &mut output);

        let ip = instruction.ip();
        
        let aligned_64 = ip / ALIGNMENT_64;
        if aligned_64 != prev_alignment_64 {
            red_64 = !red_64;
            prev_alignment_64 = aligned_64;
        }

        let aligned_32 = ip / ALIGNMENT_32;
        if aligned_32 != prev_alignment_32 {
            green_32 = !green_32;
            prev_alignment_32 = aligned_32;
        }

        let aligned_16 = ip / ALIGNMENT_16;
        if aligned_16 != prev_alignment_16 {
            cyan_16 = !cyan_16;
            prev_alignment_16 = aligned_16;
        }

        if cyan_16 {
            print!("{} ", "  ".on_cyan());
        } else {
            print!("{} ", "  ".on_white());
        }

        if green_32 {
            print!("{} ", "  ".on_green());
        } else {
            print!("{} ", "  ".on_magenta());
        }

        if red_64 {
            print!("{} ", "  ".on_red());
            print!("{}", format!("0x{ip:016X}").red());
            print!(" {}", output.red());
        } else {
            print!("{} ", "  ".on_blue());
            print!("{}", format!("0x{ip:016X}").blue());
            print!(" {}", output.blue());
        }
        let start_index: usize = (ip - begin).try_into().expect("usize = 32 bits");
        let instr_bytes = &code[start_index..start_index + instruction.len()];
        
        if output.len() < 40 {
            for _ in 0..40 - output.len() {
                print!(" ");
            }
        }
        for b in instr_bytes.iter() {
            if red_64 {
                print!("{}", format!("0x{b:02X}, ").red());
            } else {
                print!("{}", format!("0x{b:02X}, ").blue());
            }
        }
        println!();
    }
}


fn print_table(begin: u64, code: &[u8]) {
    println!();
    println!();
    for _ in 0..28 {
        print!(" ");
    }
    for i in 0..16 {
        print!("0x{i:02X} ");
    }

    let mut formatter = NasmFormatter::new();
    formatter.options_mut().set_digit_separator("_");
    formatter.options_mut().set_first_operand_char_index(10);
    let mut output = String::new();
    let mut instruction = Instruction::default();
    let mut decoder = Decoder::with_ip(64, code, begin, DecoderOptions::NONE);
    let mut prev_alignment_16 = 0;
    let mut prev_alignment_32 = 0;
    let mut prev_alignment_64 = 0;
    let mut prev_ip = 0;

    let mut red_64 = false;
    let mut green_32 = false;
    let mut cyan_16 = false;
    let mut green = true;
    while decoder.can_decode() {
        decoder.decode_out(&mut instruction);
        output.clear();
        formatter.format_mnemonic_options(&instruction, &mut output, 0);

        let ip = instruction.ip();
        let mut skip = 0;
        for (i, ip) in (ip..ip + instruction.len() as u64).enumerate() {
            let aligned_16 = ip / ALIGNMENT_16 * ALIGNMENT_16;
            if aligned_16 != prev_alignment_16 {
                cyan_16 = !cyan_16;
                prev_alignment_16 = aligned_16;
                prev_ip = 0;

                let aligned_32 = ip / ALIGNMENT_32 * ALIGNMENT_32;
                if aligned_32 != prev_alignment_32 {
                    green_32 = !green_32;
                    prev_alignment_32 = aligned_32;
                }

                println!();

                if cyan_16 {
                    print!("{} ", "  ".on_cyan());
                } else {
                    print!("{} ", "  ".on_white());
                }

                if green_32 {
                    print!("{} ", "  ".on_green());
                } else {
                    print!("{} ", "  ".on_magenta());
                }

                let aligned_64 = ip / ALIGNMENT_64 * ALIGNMENT_64;
                if aligned_64 != prev_alignment_64 {
                    red_64 = !red_64;
                    prev_alignment_64 = aligned_64;
                }


                if red_64 {
                    print!("{} ", "  ".on_red());
                    print!("{}", format!("0x{aligned_16:016X} ").red());
                } else {
                    print!("{} ", "  ".on_blue());
                    print!("{}", format!("0x{aligned_16:016X} ").blue());
                }
            }

            let begin = ip - aligned_16 - prev_ip;
            if i == 0 {
                for _ in 0..begin {
                    print!("     ");
                }
            }

            let n = if i == instruction.len() - 1 || ip - aligned_16 == 0xF{
                4
            } else {
                5
            };

            let mut j = 0;
            output
            .chars()
            .skip(skip)
            .take(n)
            .for_each(|c| {
                j += 1;
                if green { 
                    print!("{}", c.to_string().black().on_green())
                } else {
                    print!("{}", c.to_string().black().on_yellow())
                }
            });
            skip += n;
            j = n - j;
            for _ in 0..j {
                if green {
                    print!("{}", " ".on_green());
                } else {
                    print!("{}", " ".on_yellow());
                }
            }

            if i == instruction.len() - 1 {
                print!(" ");
            }
        }
        prev_ip = ip + instruction.len() as u64 - prev_alignment_16;
        green = !green;
    }
}

fn print_label() {
    println!("{} 16 byte aligned", "  ".on_cyan());
    println!("{}", "  ".on_white());
    println!();

    println!("{} 32 byte aligned", "  ".on_green());
    println!("{}", "  ".on_magenta());
    println!();

    println!("{} 64 byte aligned", "  ".on_red());
    println!("{}", "  ".on_blue());
    println!();
}

fn disassemble(begin: u64, code: &[u8]) {
    print_label();
    print_disassemble(begin, code);
    print_table(begin, code);
}

fn read_elf_file(path: &Path) -> Vec<u8> {
    let path = std::path::PathBuf::from(path);
    let file_data = std::fs::read(path).expect("Could not read file.");
    file_data
}

fn get_code_section(file_data: &[u8], begin: u64, end: u64) -> &[u8] {
    let file = ElfBytes::<AnyEndian>::minimal_parse(file_data).expect("Open file");
    let text: SectionHeader = file
        .section_header_by_name(".text")
        .expect("section table should be parseable")
        .expect("file should have a .text section");

    let begin = (begin - text.sh_addr).try_into().expect("usize = 32 bits");
    let end = (end - text.sh_addr).try_into().expect("usize = 32 bits");

    let (data, _) = file
        .section_data(&text)
        .expect("Should be able to get note section data");

    &data[begin..end]
}

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    file: PathBuf,

    #[arg(value_parser=maybe_hex::<u64>)]
    begin: u64,

    #[arg(value_parser=maybe_hex::<u64>)]
    end: u64,
}

fn main() {
    let args = Args::parse();

    println!();
    let file_data = read_elf_file(&args.file);
    let code = get_code_section(&file_data, args.begin, args.end);
    disassemble(args.begin, code);

    println!();
    println!();

    let size = code.len();
    println!("Block size: {size} bytes");
    println!();
}
