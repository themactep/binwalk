use crate::extractors::jzlzma;
use crate::signatures::common::{CONFIDENCE_HIGH, SignatureError, SignatureResult};
use crate::structures::jzlzma::parse_jzlzma_wrapped_header;

pub const DESCRIPTION: &str = "Ingenic jzlzma compressed data";

pub fn jzlzma_magic() -> Vec<Vec<u8>> {
    vec![b"\x56\x19\x05\x27".to_vec()]
}

pub fn jzlzma_parser(file_data: &[u8], offset: usize) -> Result<SignatureResult, SignatureError> {
    let header_offset = if offset >= 4 { offset - 4 } else { offset };

    if let Ok(jzlzma_header) = parse_jzlzma_wrapped_header(&file_data[header_offset..]) {
        let dry_run = jzlzma::jzlzma_decompress(file_data, header_offset, None);
        if dry_run.success {
            let mut result = SignatureResult {
                offset: header_offset,
                description: DESCRIPTION.to_string(),
                confidence: CONFIDENCE_HIGH,
                ..Default::default()
            };
            if let Some(size) = dry_run.size {
                result.size = size;
                result.description = format!(
                    "{}, wrapped, dictionary size: {} bytes, compressed size: {} bytes, total size: {} bytes",
                    result.description, jzlzma_header.dictionary_size, jzlzma_header.compressed_size, result.size
                );
            }
            return Ok(result);
        }
    }

    Err(SignatureError)
}
