use rusb::*;
use std::str;
use std::time::Duration;

use std::io::Cursor;
use std::io::Write;

const ELGATO_VID: u16 = 0xfd9;
const CYPRESS_VID: u16 = 0x04b4;

const DEFAULT_TIMEOUT: Duration = Duration::from_millis(5000);

const OUTPUT_REQUEST_TYPE: u8 = 0x40;
const INPUT_REQUEST_TYPE: u8 = 0xC0;

const FX3_BOOTROM_RAM_READ: u8 = 0xA0;
const FX3_BOOTROM_RAM_WRITE: u8 = 0xA0;

const MAX_READ_SIZE: usize = 2048;

// Only on firmwares
const FX3_FW_READ_NAME: u8 = 0xB0;

pub struct DeviceManager;

#[derive(Debug)]
pub struct DeviceId {
    pub bus_number: u8,
    pub address: u8,
}

#[derive(Debug)]
pub struct DeviceInformation {
    pub id: DeviceId,
    pub firmware_name: String,
    pub vendor_id: u16,
    pub product_id: u16,
}

pub struct Device<T: UsbContext> {
    pub handle: DeviceHandle<T>,
    pub vendor_id: u16,
    pub product_id: u16,
}

impl Device<GlobalContext> {
    pub fn open(vendor_id: u16, product_id: u16) -> Option<Self> {
        if let Some(handle) = rusb::open_device_with_vid_pid(vendor_id, product_id) {
            return Some(Device { handle, vendor_id, product_id });
        }

        None
    }
}

fn prepare_for_ram_request(buffer: &mut [u8]) {
    let output_len_bytes: [u8; 4] =
        u32::to_le_bytes((buffer.len() - std::mem::size_of::<u32>()) as u32);
    buffer[..output_len_bytes.len()].copy_from_slice(&output_len_bytes);
}

impl<T: UsbContext> Device<T> {
    pub fn read_firmware_name(&self) -> Result<String> {
        let mut firmware_name_raw = [0; 0x8];
        let read_size = self.handle.read_control(
            INPUT_REQUEST_TYPE,
            FX3_FW_READ_NAME,
            0,
            0,
            &mut firmware_name_raw,
            DEFAULT_TIMEOUT,
        )?;
        println!("{:?}", &firmware_name_raw[..read_size]);

        Ok(String::from(
            str::from_utf8(&firmware_name_raw[..read_size]).unwrap(),
        ))
    }

    pub fn is_fx3_bootrom(&self) -> bool {
        self.product_id == 0xf3
    }

    pub fn is_elgato_device(&self) -> bool {
        self.vendor_id == ELGATO_VID
    }

    pub fn read_ram(&self, address: u32, size: usize) -> Result<Vec<u8>> {
        if !self.is_fx3_bootrom() {
            panic!("This operation is only availaible on the FX3 bootrom!");
        }

        let mut read_position = 0;
        let mut cursor = Cursor::new(Vec::new());

        let mut buffer = Box::new([0x0; MAX_READ_SIZE]);

        while read_position < size {
            let size_to_read = usize::min(size - read_position, MAX_READ_SIZE);
            let target_address = address + read_position as u32;

            prepare_for_ram_request(&mut buffer[..]);

            let read_size = usize::min(
                self.read_ram_raw(target_address, &mut buffer[..]).unwrap(),
                size_to_read,
            );

            if read_size == 0 {
                println!(
                    "Reading at 0x{:x} failed: size was zero, aborting operation.",
                    target_address
                );
                break;
            }

            cursor.write_all(&buffer[..read_size]).unwrap();

            read_position += read_size;
        }

        Ok(cursor.into_inner())
    }

    pub fn write_ram(&self, address: u32, data: &[u8]) -> Result<usize> {
        if !self.is_fx3_bootrom() {
            panic!("This operation is only availaible on the FX3 bootrom!");
        }

        let mut write_position = 0;

        let user_size = data.len();

        while write_position < user_size {
            let size_to_write = usize::min(user_size - write_position, MAX_READ_SIZE);
            let target_address = address + write_position as u32;

            // That would execute the address.
            if size_to_write == 0 {
                break;
            }

            let write_size = usize::min(
                self.write_ram_raw(target_address, &data[write_position..write_position + size_to_write])
                    .unwrap(),
                size_to_write,
            );

            if write_size == 0 {
                println!(
                    "Writing at 0x{:x} failed: size was zero, aborting operation.",
                    target_address
                );
                break;
            }

            write_position += write_size;
        }

        Ok(write_position)
    }

    fn read_ram_raw(&self, address: u32, output: &mut [u8]) -> Result<usize> {
        let index = (address >> 16) as u16;
        let value = (address & 0xFFFF) as u16;

        self.handle.read_control(
            INPUT_REQUEST_TYPE,
            FX3_BOOTROM_RAM_READ,
            value,
            index,
            output,
            DEFAULT_TIMEOUT,
        )
    }

    fn write_ram_raw(&self, address: u32, input: &[u8]) -> Result<usize> {
        let index = (address >> 16) as u16;
        let value = (address & 0xFFFF) as u16;

        self.handle.write_control(
            OUTPUT_REQUEST_TYPE,
            FX3_BOOTROM_RAM_WRITE,
            value,
            index,
            input,
            DEFAULT_TIMEOUT,
        )
    }

    pub fn execute_address(&self, address: u32) -> Result<()> {
        self.write_ram_raw(address, &[])?;

        Ok(())
    }
}

impl DeviceManager {
    pub fn devices() -> Vec<DeviceInformation> {
        let mut result = Vec::new();

        for device in rusb::devices().unwrap().iter() {
            let device_desc = device.device_descriptor().unwrap();

            let bus_number = device.bus_number();
            let address = device.address();
            let vendor_id = device_desc.vendor_id();
            let product_id = device_desc.product_id();
            if vendor_id == CYPRESS_VID || vendor_id == ELGATO_VID {
                if let Some(device) = Device::open(vendor_id, product_id) {
                    let firmware_name: String;
                    let firmware_name_result = device.read_firmware_name();

                    if let Ok(name) = firmware_name_result {
                        firmware_name = name;
                    } else if product_id == 0xf3 {
                        firmware_name = String::from("FX3 bootrom (DFU)");
                    } else {
                        // Grab the device name via standard means.
                        let languages = device.handle.read_languages(DEFAULT_TIMEOUT).unwrap();

                        firmware_name = device.handle.read_product_string(languages[0], &device_desc, DEFAULT_TIMEOUT).unwrap();

                        // Try to retrieve version informations.
                        if device.is_elgato_device() {

                        }
                    }

                    result.push(DeviceInformation {
                        id: DeviceId {
                            bus_number,
                            address,
                        },
                        firmware_name,
                        vendor_id,
                        product_id,
                    });
                } else {
                    eprintln!(
                        "Cannot open device {:03}::{:03} ID {:04x}:{:04x}",
                        bus_number, address, vendor_id, product_id
                    );
                }
            }
        }

        result
    }
}
