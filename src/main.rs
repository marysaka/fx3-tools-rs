#![allow(dead_code)]

#[macro_use]
extern crate nom;

use std::fs::OpenOptions;
use std::io::{Read, Write};
use std::path::PathBuf;
use std::str;
use structopt::StructOpt;

mod cyfw;
mod device;

use device::{Device, DeviceInformation, DeviceManager};

const MAX_READ_SIZE: usize = 4096;

#[derive(Debug, StructOpt)]
pub struct DeviceListCommand {}

#[derive(Debug, StructOpt)]
pub struct DeviceReadRamCommand {
    #[structopt(short, long, parse(from_os_str))]
    output: PathBuf,

    #[structopt(name = "device", short, long)]
    device_index: u32,

    #[structopt(short, long)]
    address: String,

    #[structopt(short, long)]
    size: String,
}

#[derive(Debug, StructOpt)]
pub struct DeviceWriteRamCommand {
    #[structopt(short, long, parse(from_os_str))]
    input: PathBuf,

    #[structopt(name = "device", short, long)]
    device_index: u32,

    #[structopt(short, long)]
    address: String,
}

#[derive(Debug, StructOpt)]
pub struct DeviceRunCommand {
    #[structopt(short, long, parse(from_os_str))]
    input: PathBuf,

    #[structopt(name = "device", short, long)]
    device_index: u32,
}

#[derive(Debug, StructOpt)]
pub enum DeviceBootromCommand {
    #[structopt(name = "read-ram")]
    ReadRam(DeviceReadRamCommand),
    #[structopt(name = "write-ram")]
    WriteRam(DeviceWriteRamCommand),

    #[structopt(name = "run")]
    Run(DeviceRunCommand),
}

#[derive(Debug, StructOpt)]
pub struct DeviceElgatoResetCommand {
    #[structopt(name = "device", short, long)]
    device_index: u32
}

#[derive(Debug, StructOpt)]
pub struct DeviceElgatoReadFlashCommand {
    #[structopt(short, long, parse(from_os_str))]
    output: PathBuf,

    #[structopt(name = "device", short, long)]
    device_index: u32,

    #[structopt(short, long)]
    sector: usize,

    #[structopt(short, long)]
    count: usize,
}

#[derive(Debug, StructOpt)]
pub enum DeviceElgatoCommand {
    #[structopt(name = "read-flash")]
    ReadFlash(DeviceElgatoReadFlashCommand),
    #[structopt(name = "reset")]
    Reset(DeviceElgatoResetCommand),
}



#[derive(Debug, StructOpt)]
pub enum DeviceCommand {
    #[structopt(name = "bootrom")]
    Bootrom(DeviceBootromCommand),
    #[structopt(name = "elgato")]
    Elgato(DeviceElgatoCommand),
    #[structopt(name = "list")]
    List(DeviceListCommand),
}

#[derive(Debug, StructOpt)]
pub struct FirmwareInfoCommand {
    #[structopt(short, long, parse(from_os_str))]
    input: PathBuf,
}

#[derive(Debug, StructOpt)]
pub enum FirmwareCommand {
    #[structopt(name = "info")]
    Info(FirmwareInfoCommand),
}

#[derive(Debug, StructOpt)]
pub enum Command {
    #[structopt(name = "device")]
    Device(DeviceCommand),
    #[structopt(name = "firmware")]
    Firmware(FirmwareCommand),
}

#[derive(Debug, StructOpt)]
#[structopt(name = "fx3-tools")]
pub struct ApplicationArguments {
    #[structopt(subcommand)]
    pub command: Command,
}

fn list_devices(devices: Vec<DeviceInformation>) {
    for (index, device) in devices.iter().enumerate() {
        println!(
            "- {}: \"{}\" (bus: {:03}, address: {:03}, vid: {:04x}, pid: {:04x})",
            index,
            device.firmware_name,
            device.id.bus_number,
            device.id.address,
            device.vendor_id,
            device.product_id
        );
    }
}

fn device_read_ram(device_info: &DeviceInformation, options: DeviceReadRamCommand) {
    let device = Device::open(device_info.vendor_id, device_info.product_id).unwrap();

    if !device.is_fx3_bootrom() {
        println!("This operation is only availaible on the FX3 bootrom!");

        return;
    }

    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(options.output)
        .unwrap();

    let user_address = u32::from_str_radix(options.address.trim_start_matches("0x"), 16).unwrap();
    let user_size = usize::from_str_radix(options.size.trim_start_matches("0x"), 16).unwrap();

    let data = device.read_ram(user_address, user_size).unwrap();

    file.write_all(&data).unwrap();
}

fn device_write_ram(device_info: &DeviceInformation, options: DeviceWriteRamCommand) {
    let device = Device::open(device_info.vendor_id, device_info.product_id).unwrap();

    if !device.is_fx3_bootrom() {
        println!("This operation is only availaible on the FX3 bootrom!");

        return;
    }

    let mut file = OpenOptions::new().read(true).open(options.input).unwrap();

    let mut data = Vec::new();

    file.read_to_end(&mut data).unwrap();

    let user_address = u32::from_str_radix(options.address.trim_start_matches("0x"), 16).unwrap();

    device.write_ram(user_address, &data).unwrap();
}

fn device_run(device_info: &DeviceInformation, options: DeviceRunCommand) {
    let device = Device::open(device_info.vendor_id, device_info.product_id).unwrap();

    if !device.is_fx3_bootrom() {
        println!("This operation is only availaible on the FX3 bootrom!");

        return;
    }

    let mut file = OpenOptions::new()
        .read(true)
        .open(options.input)
        .unwrap();

    let mut data = Vec::new();

    file.read_to_end(&mut data).unwrap();

    let firmware = cyfw::parser::parse(&data).unwrap().1;

    println!("Checking firmware checksum...");

    if !firmware.is_checksum_valid() {
        println!("Invalid checksum! Aborting operations.");

        return;
    }

    println!("Loading firmware into RAM...");

    for (section_index, section) in firmware.sections.iter().enumerate() {
        device.write_ram(section.address, &section.data).unwrap();

        // Check validity of what was written.
        let written_data = device.read_ram(section.address, section.data.len()).unwrap();

        if written_data != section.data {
            println!("Write failed for section {}", section_index);

            return;
        }
    }

    println!("Executing firmware entrypoint...");
    device.execute_address(firmware.entrypoint).unwrap();

    println!("All done.");
}

fn handle_device_bootrom_command(options: DeviceBootromCommand, devices: Vec<DeviceInformation>) {
    match options {
        DeviceBootromCommand::ReadRam(options) => {
            let device_info = devices.get(options.device_index as usize).unwrap();

            device_read_ram(device_info, options);
        },
        DeviceBootromCommand::WriteRam(options) => {
            let device_info = devices.get(options.device_index as usize).unwrap();

            device_write_ram(device_info, options);
        },
        DeviceBootromCommand::Run(options) => {
            let device_info = devices.get(options.device_index as usize).unwrap();

            device_run(device_info, options);
        }
    };
}

fn handle_device_elgato_read_flash_command(options: DeviceElgatoReadFlashCommand, devices: Vec<DeviceInformation>) {
    let device_info = devices.get(options.device_index as usize).unwrap();
    let device = Device::open(device_info.vendor_id, device_info.product_id).unwrap();

    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(options.output)
        .unwrap();

    device.set_elgato_firmware_flash_mode(true).unwrap();

    for sector_index in options.sector..options.sector + options.count {
        println!("Reading SPI sector {}...", sector_index);

        for page_index in 0..=0xFF {
            file.write_all(&device.read_elgato_spi_page(sector_index as u16, page_index).unwrap()).unwrap();
        }
    }

    device.set_elgato_firmware_flash_mode(false).unwrap();
}

fn handle_device_elgato_command(options: DeviceElgatoCommand, devices: Vec<DeviceInformation>) {
    match options {
        DeviceElgatoCommand::Reset(options) => {
            let device_info = devices.get(options.device_index as usize).unwrap();
            let device = Device::open(device_info.vendor_id, device_info.product_id).unwrap();

            device.reset_elgato_device().unwrap();
        },
        DeviceElgatoCommand::ReadFlash(options) => handle_device_elgato_read_flash_command(options, devices)
    };
}

fn handle_device_command(options: DeviceCommand) {
    let devices = DeviceManager::devices();

    match options {
        DeviceCommand::List(_) => list_devices(devices),
        DeviceCommand::Bootrom(options) => handle_device_bootrom_command(options, devices),
        DeviceCommand::Elgato(options) => handle_device_elgato_command(options, devices)
    };
}

fn handle_firmware_command(options: FirmwareCommand) {
    match options {
        FirmwareCommand::Info(options) => {
            let mut file = OpenOptions::new().read(true).open(options.input).unwrap();

            let mut data = Vec::new();

            file.read_to_end(&mut data).unwrap();

            let firmware = cyfw::parser::parse(&data).unwrap().1;

            println!("Cypress Firmware:");
            println!("Image Information:");

            println!("\tI2C EEPROM size: {}", firmware.get_i2c_size());
            println!("\tI2C speed: {}", firmware.get_i2c_speed());
            println!("\tSPI speed: {}", firmware.get_spi_speed());
            println!("\tEntrypoint: 0x{:x}", firmware.entrypoint);

            let checksum_validity_text;

            if firmware.is_checksum_valid() {
                checksum_validity_text = String::from("Valid");
            } else {
                checksum_validity_text =
                    format!("Invalid, expected: 0x{:x}", firmware.compute_checksum());
            }

            println!(
                "\tChecksum: 0x{:x} ({})",
                firmware.checksum, checksum_validity_text
            );

            println!("Sections:");

            for (section_index, section) in firmware.sections.iter().enumerate() {
                println!("\tSection {}:", section_index);
                println!("\t\tAddress: 0x{:x}", section.address);
                println!("\t\tSize: 0x{:x}", section.size);
            }
        }
    }
}

fn main() {
    let opt = ApplicationArguments::from_args();

    match opt.command {
        Command::Device(options) => handle_device_command(options),
        Command::Firmware(options) => handle_firmware_command(options),
    };
}
