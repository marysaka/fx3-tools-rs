use nom::number::streaming::{le_u32, le_u8};
use nom::IResult;
use std::convert::TryInto;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Header {
    pub image_ctl: u8,
    pub image_type: u8,
    pub sections: Vec<Section>,
    pub entrypoint: u32,
    pub checksum: u32,
}

impl Header {
    pub fn get_i2c_size(&self) -> &str {
        match (self.image_ctl >> 1) & 0x7 {
            2 => "4 KB",
            3 => "8 KB",
            4 => "16 KB",
            5 => "32 KB",
            6 => "64 KB",
            7 => "128 KB",
            _ => "Unknown",
        }
    }

    pub fn get_i2c_speed(&self) -> &str {
        match (self.image_ctl >> 4) & 0x3 {
            0b00 => "100 KHz",
            0b01 => "400 KHz",
            0b10 => "1 MHz",
            0b11 => "3.4 MHz",
            _ => unreachable!(),
        }
    }

    pub fn get_spi_speed(&self) -> &str {
        match (self.image_ctl >> 4) & 0x3 {
            0b00 => "10 MHz",
            0b01 => "20 MHz",
            0b10 => "30 MHz",
            0b11 => "40 MHz",
            _ => unreachable!(),
        }
    }

    pub fn is_checksum_valid(&self) -> bool {
        self.compute_checksum() == self.checksum
    }

    pub fn compute_checksum(&self) -> u32 {
        let mut checksum = 0u32;

        for section in &self.sections {
            for i in 0..section.data.len() / 4 {
                let dword =
                    u32::from_le_bytes(section.data[i * 4..(i + 1) * 4].try_into().unwrap());

                checksum = checksum.overflowing_add(dword).0;
            }
        }

        checksum
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Section {
    pub address: u32,
    pub size: u32,
    pub data: Vec<u8>,
}

named!(
    section<Section>,
    do_parse!(
        size: le_u32
            >> address: le_u32
            >> data: take!(size * 4)
            >> (Section {
                size: size * 4,
                address,
                data: Vec::from(data)
            })
    )
);

named!(
    header<Header>,
    do_parse!(
        tag!("CY")
            >> image_ctl: le_u8
            >> image_type: le_u8
            >> sections_res: many_till!(section, tag!(b"\0\0\0\0"))
            >> entrypoint: le_u32
            >> checksum: le_u32
            >> (Header {
                image_ctl,
                image_type,
                sections: sections_res.0,
                entrypoint,
                checksum,
            })
    )
);

pub fn parse(data: &[u8]) -> IResult<&[u8], Header> {
    header(data)
}
