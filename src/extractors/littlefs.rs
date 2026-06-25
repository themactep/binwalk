use crate::extractors::common::{Chroot, ExtractionResult, Extractor, ExtractorType};
use crate::structures::littlefs::{
    read_block, read_ctz_file, walk_metadata_pair, LFS_CHUNK_HARDTAIL, LFS_CHUNK_SOFTTAIL,
    LFS_TYPE1_CRC, LFS_TYPE1_TAIL, decode_tag, parse_ptr_pair,
};
use std::collections::VecDeque;

/// Defines the internal littlefs extractor
pub fn littlefs_extractor() -> Extractor {
    Extractor {
        utility: ExtractorType::Internal(extract_littlefs),
        ..Default::default()
    }
}

/// Internal littlefs extractor
pub fn extract_littlefs(
    file_data: &[u8],
    offset: usize,
    output_directory: Option<&str>,
) -> ExtractionResult {
    let mut result = ExtractionResult {
        ..Default::default()
    };

    // We know the superblock magic "littlefs" is at offset+8 in the data
    // Parse the superblock to get config
    let superblock_data = match file_data.get(offset..offset + 40) {
        Some(d) => d,
        None => return result,
    };

    // Verify magic
    if superblock_data.get(8..16) != Some(b"littlefs") {
        return result;
    }

    // Parse the inline-struct (type 0x201, id 0) data
    // Layout after the superblock start (offset=0 in sb_start):
    //   0-3:   revision count
    //   4-7:   name tag (encoded)
    //   8-15:  "littlefs" (name data)
    //   16-19: inline-struct tag (encoded)
    //   20-23: version (u32 LE)
    //   24-27: block_size (u32 LE)
    //   28-31: block_count (u32 LE)
    //   32-35: name_max (u32 LE)
    //   36-39: file_max (u32 LE)
    //   40-43: attr_max (u32 LE)
    let block_size_val = u32::from_le_bytes(match superblock_data.get(24..28) {
        Some(d) => d.try_into().unwrap(),
        None => return result,
    });
    let block_count = u32::from_le_bytes(match superblock_data.get(28..32) {
        Some(d) => d.try_into().unwrap(),
        None => return result,
    });

    if block_size_val < 16 || block_count == 0 {
        return result;
    }

    let bs = block_size_val as usize;

    // Calculate file system size
    let fs_size = (block_size_val as u64) * (block_count as u64);
    let fs_max = if fs_size > usize::MAX as u64 {
        usize::MAX
    } else {
        fs_size as usize
    };

    result.size = Some(fs_max);

    // Extract if output directory provided
    if let Some(out_dir) = output_directory {
        let chroot = Chroot::new(Some(out_dir));
        let littlefs_dir = chroot.chrooted_path("littlefs-root");

        if !chroot.create_directory(&littlefs_dir) {
            result.success = false;
            return result;
        }

        // Walk root directory starting from metadata pair (0, 1)
        let mut file_count = 0;
        let mut dir_queue: VecDeque<(String, (usize, usize))> = VecDeque::new();
        dir_queue.push_back(("/".to_string(), (0, 1)));

        let mut visited_pairs = std::collections::HashSet::new();

        while let Some((dir_path, pair)) = dir_queue.pop_front() {
            if pair.0 == 0xffffffff || pair.1 == 0xffffffff {
                continue;
            }
            if !visited_pairs.insert(pair) {
                continue;
            }

            let entries = walk_metadata_pair(file_data, offset, pair, bs);

            for entry in &entries {
                let entry_path = if dir_path == "/" {
                    format!("{}/{}", littlefs_dir, entry.name)
                } else {
                    format!("{}{}/{}", littlefs_dir, dir_path, entry.name)
                };

                if entry.is_dir {
                    // Create directory
                    let _ = chroot.create_directory(&entry_path);
                    if entry.has_dir && entry.dir_pair != (0, 0) {
                        dir_queue.push_back((
                            format!("{}/{}", dir_path, entry.name),
                            entry.dir_pair,
                        ));
                    }
                } else if !entry.is_superblock {
                    // Extract regular file
                    let data = if entry.has_inline {
                        entry.inline_data.clone()
                    } else if entry.has_ctz && entry.ctz_head != 0xffffffff {
                        read_ctz_file(file_data, offset, bs, entry.ctz_head, entry.ctz_size)
                    } else {
                        continue;
                    };

                    if !data.is_empty() {
                        file_count += 1;
                        chroot.carve_file(&entry_path, &data, 0, data.len());
                    }
                }
            }

            // Also follow TAIL tags from this pair to traverse the directory linked-list
            let tail_tags = parse_tail_tags(file_data, offset, pair, bs);
            for tail_pair in tail_tags {
                if !visited_pairs.contains(&tail_pair) {
                    dir_queue.push_back((dir_path.clone(), tail_pair));
                }
            }
        }

        if file_count > 0 {
            result.success = true;
        }
    } else {
        // Dry run - just report detection
        result.success = true;
    }

    result
}

/// Parse TAIL tags from a metadata pair to find linked-list neighbours
fn parse_tail_tags(
    file_data: &[u8],
    base_offset: usize,
    pair: (usize, usize),
    block_size: usize,
) -> Vec<(usize, usize)> {
    let mut tails = Vec::new();

    for &block_addr in &[pair.0, pair.1] {
        let block_data = match read_block(file_data, base_offset, block_addr, block_size) {
            Some(d) => d,
            None => continue,
        };

        let mut offset: usize = 4;
        let mut xor_key: u32 = 0xffffffff;

        while offset + 4 <= block_data.len() {
            let encoded = u32::from_be_bytes(match block_data.get(offset..offset + 4) {
                Some(bytes) => bytes.try_into().unwrap(),
                None => break,
            });
            let tag_word = encoded ^ xor_key;
            if tag_word == 0x00000000 || tag_word == 0xffffffff {
                break;
            }
            if (tag_word >> 31) & 0x1 != 0 {
                break;
            }
            let tag = decode_tag(tag_word);

            if tag.type1 == LFS_TYPE1_CRC {
                offset += 4 + std::cmp::max(tag.length as usize, 4);
                xor_key = 0xffffffff;
                continue;
            }

            if tag.type1 == LFS_TYPE1_TAIL
                && (tag.chunk == LFS_CHUNK_SOFTTAIL || tag.chunk == LFS_CHUNK_HARDTAIL)
            {
                let data_start = offset + 4;
                if let Some(data) = block_data.get(data_start..data_start + tag.length as usize)
                    && let Some(tail) = parse_ptr_pair(data)
                {
                    tails.push(tail);
                }
            }

            xor_key = tag_word;
            offset += 4 + tag.length as usize;
        }
    }

    tails
}
