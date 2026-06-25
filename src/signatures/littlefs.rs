use crate::signatures::common::{CONFIDENCE_HIGH, SignatureError, SignatureResult};
use crate::structures::littlefs::decode_tag;

/// Human readable description
pub const DESCRIPTION: &str = "littlefs filesystem";

/// littlefs magic bytes: "littlefs" (8 bytes)
pub fn littlefs_magic() -> Vec<Vec<u8>> {
    vec![b"littlefs".to_vec()]
}

/// Parse and validate a littlefs superblock
pub fn littlefs_parser(
    file_data: &[u8],
    offset: usize,
) -> Result<SignatureResult, SignatureError> {
    const MIN_BLOCK_SIZE: u32 = 128;
    const MAX_BLOCK_SIZE: u32 = 1_048_576;
    const MAX_BLOCK_COUNT: u32 = 1_048_576;
    const SB_NAME_OFFSET: usize = 8;

    let sb_start = if offset >= SB_NAME_OFFSET {
        offset - SB_NAME_OFFSET
    } else {
        return Err(SignatureError);
    };

    // Need at least 48 bytes to cover revision count + name tag + inline-struct
    let sb_data = match file_data.get(sb_start..sb_start + 48) {
        Some(d) => d,
        None => return Err(SignatureError),
    };

    // Verify magic string
    if &sb_data[SB_NAME_OFFSET..SB_NAME_OFFSET + 8] != b"littlefs" {
        return Err(SignatureError);
    }

    // Validate the name tag structure: bytes 4-7 should decode to a valid SUPERBLOCK name tag
    let name_tag_encoded = u32::from_be_bytes(
        sb_data[4..8].try_into().map_err(|_| SignatureError)?,
    );
    let name_tag_word = name_tag_encoded ^ 0xffffffff;
    let name_tag = decode_tag(name_tag_word);
    if name_tag.chunk != crate::structures::littlefs::LFS_CHUNK_SUPERBLOCK
        || name_tag.id != 0
        || name_tag.length != 8
    {
        return Err(SignatureError);
    }

    // Validate the inline-struct tag structure: bytes 16-19 should decode
    // XOR key for second tag is the decoded first tag word
    let istruct_tag_encoded = u32::from_be_bytes(
        sb_data[16..20].try_into().map_err(|_| SignatureError)?,
    );
    let istruct_tag_word = istruct_tag_encoded ^ name_tag_word;
    let istruct_tag = decode_tag(istruct_tag_word);
    if istruct_tag.chunk != crate::structures::littlefs::LFS_CHUNK_INLINESTRUCT
        || istruct_tag.id != 0
        || istruct_tag.length != 24
    {
        return Err(SignatureError);
    }

    // Parse superblock fields from the inline-struct data (bytes 20-43)
    let version =
        u32::from_le_bytes(sb_data[20..24].try_into().map_err(|_| SignatureError)?);
    let block_size =
        u32::from_le_bytes(sb_data[24..28].try_into().map_err(|_| SignatureError)?);
    let block_count =
        u32::from_le_bytes(sb_data[28..32].try_into().map_err(|_| SignatureError)?);

    let version_major = (version >> 16) as u16;
    let version_minor = (version & 0xffff) as u16;

    // Strict validation to reject false positives
    if version_major != 1 && version_major != 2 {
        return Err(SignatureError);
    }
    if block_size < MIN_BLOCK_SIZE
        || block_size > MAX_BLOCK_SIZE
        || block_count == 0
        || block_count > MAX_BLOCK_COUNT
    {
        return Err(SignatureError);
    }

    let mut result = SignatureResult {
        offset: sb_start,
        description: DESCRIPTION.to_string(),
        confidence: CONFIDENCE_HIGH,
        ..Default::default()
    };

    result.description = format!(
        "{}, version: {}.{}, block_size: {}, block_count: {}",
        DESCRIPTION, version_major, version_minor, block_size, block_count
    );

    Ok(result)
}
