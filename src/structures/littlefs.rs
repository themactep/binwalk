/// type1 constants (bits 30-28 of tag)
pub const LFS_TYPE1_NAME: u8 = 0x0;
pub const LFS_TYPE1_STRUCT: u8 = 0x2;
pub const LFS_TYPE1_CRC: u8 = 0x5;
pub const LFS_TYPE1_TAIL: u8 = 0x6;

/// Chunk values for STRUCT subtypes (type3 & 0xff)
pub const LFS_CHUNK_DIRSTRUCT: u8 = 0x00;
pub const LFS_CHUNK_INLINESTRUCT: u8 = 0x01;
pub const LFS_CHUNK_CTZSTRUCT: u8 = 0x02;

/// Chunk values for NAME file types
pub const LFS_CHUNK_DIR: u8 = 0x02;
pub const LFS_CHUNK_SUPERBLOCK: u8 = 0xff;

/// Chunk values for TAIL types
pub const LFS_CHUNK_SOFTTAIL: u8 = 0x00;
pub const LFS_CHUNK_HARDTAIL: u8 = 0x01;

/// Deleted marker for length field
pub const LFS_DELETED_LEN: u16 = 0x3ff;

/// Decoded metadata tag
#[derive(Debug, Clone, Copy)]
pub struct LfsTag {
    pub type1: u8,
    pub chunk: u8,
    pub id: u16,
    pub length: u16,
}

/// Decode a 32-bit big-endian littlefs tag word
pub fn decode_tag(tag_word: u32) -> LfsTag {
    let type3 = ((tag_word >> 20) & 0x7ff) as u16;
    let type1 = ((type3 >> 8) & 0x7) as u8;
    let chunk = (type3 & 0xff) as u8;
    let id = ((tag_word >> 10) & 0x3ff) as u16;
    let length = (tag_word & 0x3ff) as u16;

    LfsTag {
        type1,
        chunk,
        id,
        length,
    }
}

/// Parsed directory entry
#[derive(Debug, Clone)]
pub struct LfsDirEntry {
    pub name: String,
    pub is_dir: bool,
    pub is_superblock: bool,
    pub ctz_head: usize,
    pub ctz_size: usize,
    pub inline_data: Vec<u8>,
    pub dir_pair: (usize, usize),
    pub has_inline: bool,
    pub has_ctz: bool,
    pub has_dir: bool,
}

/// Parse a CTZ struct data (8 bytes: head + size, both u32 little-endian)
pub fn parse_ctz_struct(data: &[u8]) -> Option<(usize, usize)> {
    if data.len() < 8 {
        return None;
    }
    let head = u32::from_le_bytes(data[0..4].try_into().ok()?) as usize;
    let size = u32::from_le_bytes(data[4..8].try_into().ok()?) as usize;
    Some((head, size))
}

/// Parse a DIRSTRUCT/Tail data (8 bytes: two block pointers)
pub fn parse_ptr_pair(data: &[u8]) -> Option<(usize, usize)> {
    if data.len() < 8 {
        return None;
    }
    let a = u32::from_le_bytes(data[0..4].try_into().ok()?) as usize;
    let b = u32::from_le_bytes(data[4..8].try_into().ok()?) as usize;
    Some((a, b))
}

/// Read a block from the image given block address, size, and base offset
pub fn read_block(file_data: &[u8], base_offset: usize, block_addr: usize, block_size: usize) -> Option<&[u8]> {
    let start = base_offset + block_addr * block_size;
    let end = start + block_size;
    file_data.get(start..end)
}

/// Number of CTZ skip pointers in a file block at 0-indexed `block_idx`
pub fn ctz_skip_count(block_idx: usize) -> usize {
    if block_idx == 0 {
        return 0;
    }
    block_idx.trailing_zeros() as usize + 1
}

/// Read CTZ file data from the block device
pub fn read_ctz_file(
    file_data: &[u8],
    base_offset: usize,
    block_size: usize,
    head_block: usize,
    file_size: usize,
) -> Vec<u8> {
    if file_size == 0 || head_block == 0xffffffff {
        return Vec::new();
    }

    let num_blocks = file_size.div_ceil(block_size);
    if num_blocks == 0 {
        return Vec::new();
    }

    let mut block_addrs = Vec::with_capacity(num_blocks);
    let mut current_block = head_block;
    let mut current_idx = num_blocks - 1;
    block_addrs.push(current_block);

    while current_idx > 0 {
        let ptr_count = ctz_skip_count(current_idx);
        if ptr_count == 0 {
            break;
        }
        let block_data = match read_block(file_data, base_offset, current_block, block_size) {
            Some(data) => data,
            None => break,
        };
        let prev_block = match block_data.get(0..4) {
            Some(bytes) => u32::from_le_bytes(bytes.try_into().unwrap()) as usize,
            None => break,
        };
        current_idx -= 1;
        current_block = prev_block;
        block_addrs.push(current_block);
    }

    block_addrs.reverse();

    let mut result = Vec::with_capacity(file_size);
    for (i, &addr) in block_addrs.iter().enumerate() {
        let block_data = match read_block(file_data, base_offset, addr, block_size) {
            Some(data) => data,
            None => break,
        };
        let ptr_count = ctz_skip_count(i);
        let ptr_size = ptr_count * 4;
        let data_start = std::cmp::min(ptr_size, block_size);
        let data_end = if i == block_addrs.len() - 1 {
            let remaining = file_size.saturating_sub(result.len());
            std::cmp::min(data_start + remaining, block_size)
        } else {
            block_size
        };
        if data_end > data_start {
            result.extend_from_slice(&block_data[data_start..data_end]);
        }
        if result.len() >= file_size {
            break;
        }
    }

    result.truncate(file_size);
    result
}

/// Parse all tags from a metadata block's commit log
pub fn parse_metadata_tags(
    file_data: &[u8],
    base_offset: usize,
    metadata_pair: (usize, usize),
    block_size: usize,
) -> Vec<(LfsTag, Vec<u8>)> {
    let mut tags = Vec::new();
    for &block_addr in &[metadata_pair.0, metadata_pair.1] {
        if let Some(block_data) = read_block(file_data, base_offset, block_addr, block_size) {
            parse_tags_from_block(block_data, &mut tags);
        }
    }
    tags
}

/// Parse tags from a single metadata block
fn parse_tags_from_block(block_data: &[u8], tags: &mut Vec<(LfsTag, Vec<u8>)>) {
    let mut offset: usize = 4;
    let mut xor_key: u32 = 0xffffffff;

    while offset + 4 <= block_data.len() {
        let encoded = match block_data.get(offset..offset + 4) {
            Some(bytes) => u32::from_be_bytes(bytes.try_into().unwrap()),
            None => break,
        };
        let tag_word = encoded ^ xor_key;

        if tag_word == 0x00000000 || tag_word == 0xffffffff {
            break;
        }
        if (tag_word >> 31) & 0x1 != 0 {
            break;
        }

        let tag = decode_tag(tag_word);

        if tag.type1 == LFS_TYPE1_CRC {
            let crc_size = std::cmp::max(tag.length as usize, 4);
            tags.push((tag, vec![]));
            offset += 4 + crc_size;
            xor_key = 0xffffffff;
            continue;
        }

        let data = if tag.length > 0 && tag.length < LFS_DELETED_LEN {
            let data_size = tag.length as usize;
            let data_start = offset + 4;
            match block_data.get(data_start..data_start + data_size) {
                Some(d) => d.to_vec(),
                None => vec![],
            }
        } else {
            vec![]
        };

        xor_key = tag_word;
        offset += 4 + data.len();
        tags.push((tag, data));
    }
}

/// Walk a metadata pair directory and return all file/dir entries
pub fn walk_metadata_pair(
    file_data: &[u8],
    base_offset: usize,
    pair: (usize, usize),
    block_size: usize,
) -> Vec<LfsDirEntry> {
    let raw_tags = parse_metadata_tags(file_data, base_offset, pair, block_size);

    let mut name_map: std::collections::HashMap<u16, (String, u8)> = std::collections::HashMap::new();
    let mut ctz_map: std::collections::HashMap<u16, (usize, usize)> = std::collections::HashMap::new();
    let mut inline_map: std::collections::HashMap<u16, Vec<u8>> = std::collections::HashMap::new();
    let mut dir_map: std::collections::HashMap<u16, (usize, usize)> =
        std::collections::HashMap::new();

    for (tag, data) in &raw_tags {
        match tag.type1 {
            LFS_TYPE1_NAME => {
                let name = String::from_utf8_lossy(data).to_string();
                name_map.insert(tag.id, (name, tag.chunk));
            }
            LFS_TYPE1_STRUCT => {
                match tag.chunk {
                    LFS_CHUNK_CTZSTRUCT => {
                        if let Some(info) = parse_ctz_struct(data) {
                            ctz_map.insert(tag.id, info);
                        }
                    }
                    LFS_CHUNK_INLINESTRUCT => {
                        inline_map.insert(tag.id, data.clone());
                    }
                    LFS_CHUNK_DIRSTRUCT => {
                        if let Some(p) = parse_ptr_pair(data) {
                            dir_map.insert(tag.id, p);
                        }
                    }
                    _ => {}
                }
            }
            _ => {}
        }
    }

    let mut entries: Vec<LfsDirEntry> = Vec::new();
    for (id, (name, file_type)) in &name_map {
        if *file_type == LFS_CHUNK_SUPERBLOCK {
            continue;
        }
        let is_dir = *file_type == LFS_CHUNK_DIR;
        let ctz_info = ctz_map.get(id).copied().unwrap_or((0, 0));
        let inline_data = inline_map.get(id).cloned().unwrap_or_default();
        let dir_pair = dir_map.get(id).copied().unwrap_or((0, 0));

        entries.push(LfsDirEntry {
            name: name.clone(),
            is_dir,
            is_superblock: false,
            ctz_head: ctz_info.0,
            ctz_size: ctz_info.1,
            inline_data,
            dir_pair,
            has_inline: inline_map.contains_key(id),
            has_ctz: ctz_map.contains_key(id),
            has_dir: dir_map.contains_key(id),
        });
    }

    entries
}
