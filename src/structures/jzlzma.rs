use crate::structures::common::{self, StructureError};

const JZLZMA_WRAPPED_MAGIC: u32 = 0x27051956;
const JZLZMA_WRAPPED_HEADER_SIZE: usize = 16;
#[allow(dead_code)]
const JZLZMA_RAW_HEADER_SIZE: usize = 8;

#[derive(Debug, Default, Clone)]
pub struct JzlzmaHeader {
    pub dictionary_size: usize,
    pub compressed_size: usize,
    #[allow(dead_code)]
    pub uncompressed_size: usize,
    pub data_offset: usize,
    #[allow(dead_code)]
    pub is_wrapped: bool,
}

pub fn parse_jzlzma_wrapped_header(data: &[u8]) -> Result<JzlzmaHeader, StructureError> {
    let structure = vec![
        ("compressed_size", "u32"),
        ("magic", "u32"),
        ("dictionary_size", "u32"),
        ("uncompressed_size", "u32"),
    ];

    if let Ok(hdr) = common::parse(data, &structure, "little") {
        if hdr["magic"] == JZLZMA_WRAPPED_MAGIC as usize {
            let dict_size = hdr["dictionary_size"];
            let comp_size = hdr["compressed_size"];
            if (0x1000..=0x4000000).contains(&dict_size) && comp_size > 0 {
                return Ok(JzlzmaHeader {
                    dictionary_size: dict_size,
                    compressed_size: comp_size,
                    uncompressed_size: hdr["uncompressed_size"],
                    data_offset: JZLZMA_WRAPPED_HEADER_SIZE,
                    is_wrapped: true,
                });
            }
        }
    }
    Err(StructureError)
}

#[allow(dead_code)]
pub fn parse_jzlzma_raw_header(data: &[u8]) -> Result<JzlzmaHeader, StructureError> {
    let structure = vec![("dictionary_size", "u32"), ("uncompressed_size", "u32")];

    if let Ok(hdr) = common::parse(data, &structure, "little") {
        let dict_size = hdr["dictionary_size"];
        if (0x1000..=0x4000000).contains(&dict_size) {
            return Ok(JzlzmaHeader {
                dictionary_size: dict_size,
                compressed_size: 0,
                uncompressed_size: hdr["uncompressed_size"],
                data_offset: JZLZMA_RAW_HEADER_SIZE,
                is_wrapped: false,
            });
        }
    }
    Err(StructureError)
}
