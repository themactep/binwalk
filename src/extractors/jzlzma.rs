use crate::extractors::common::{Chroot, ExtractionResult, Extractor, ExtractorType};
use crate::structures::jzlzma::parse_jzlzma_wrapped_header;

const K_START_POS_MODEL_INDEX: u8 = 4;
const K_END_POS_MODEL_INDEX: u8 = 14;
const K_NUM_ALIGN_BITS: u8 = 4;

pub fn jzlzma_extractor() -> Extractor {
    Extractor {
        utility: ExtractorType::Internal(jzlzma_decompress),
        ..Default::default()
    }
}

pub fn jzlzma_decompress(
    file_data: &[u8],
    offset: usize,
    output_directory: Option<&str>,
) -> ExtractionResult {
    const OUTPUT_FILE_NAME: &str = "decompressed.bin";

    let mut result = ExtractionResult {
        ..Default::default()
    };

    if let Some(data) = file_data.get(offset..) {
        if let Ok(header) = parse_jzlzma_wrapped_header(data) {
            if let Some(compressed) =
                data.get(header.data_offset..header.data_offset + header.compressed_size)
            {
                let mut decompressor = JzlzmaDecompressor::new();
                let decompressed = decompressor.decompress(compressed);

                if !decompressed.is_empty() {
                    let total_size = header.data_offset + header.compressed_size;
                    result.size = Some(total_size);
                    result.success = true;

                    if let Some(output_dir) = output_directory {
                        let chroot = Chroot::new(Some(output_dir));
                        result.success = chroot.create_file(OUTPUT_FILE_NAME, &decompressed);
                    }
                }
            }
        }
    }

    result
}

struct JzlzmaDecompressor {
    reps: [usize; 4],
    decompressed: Vec<u8>,
}

impl JzlzmaDecompressor {
    fn new() -> Self {
        JzlzmaDecompressor {
            reps: [0, 0, 0, 0],
            decompressed: Vec::new(),
        }
    }

    fn decompress(&mut self, data: &[u8]) -> Vec<u8> {
        let bits: Vec<u8> = data
            .iter()
            .flat_map(|&byte| (0..8).map(move |bit| if byte & (1 << bit) != 0 { 1 } else { 0 }))
            .collect();

        let mut pos = 0;
        self.decompressed.clear();

        loop {
            if pos >= bits.len() {
                break;
            }

            if bits[pos] == 0 {
                pos += 1;
                let byte = match read_num(&bits, &mut pos, 8) {
                    Some(v) => v as u8,
                    None => break,
                };
                self.decompressed.push(byte);
            } else {
                pos += 1;
                let mut size: usize;

                if pos >= bits.len() {
                    break;
                }

                if bits[pos] == 0 {
                    pos += 1;
                    let (decoded_size, dist) = match self.decode_match_len_dist(&bits, &mut pos) {
                        Some(v) => v,
                        None => break,
                    };
                    size = decoded_size;
                    self.reps = [dist, self.reps[0], self.reps[1], self.reps[2]];
                } else {
                    pos += 1;

                    if pos >= bits.len() {
                        break;
                    }

                    if bits[pos] == 0 {
                        pos += 1;

                        if pos >= bits.len() {
                            break;
                        }

                        if bits[pos] == 0 {
                            pos += 1;
                            size = 1;
                        } else {
                            pos += 1;
                            size = 0;
                        }
                    } else {
                        pos += 1;

                        if pos >= bits.len() {
                            break;
                        }

                        if bits[pos] == 0 {
                            pos += 1;
                            self.reps = [self.reps[1], self.reps[0], self.reps[2], self.reps[3]];
                        } else {
                            pos += 1;

                            if pos >= bits.len() {
                                break;
                            }

                            if bits[pos] == 0 {
                                pos += 1;
                                self.reps = [self.reps[2], self.reps[0], self.reps[1], self.reps[3]];
                            } else {
                                pos += 1;

                                if pos >= bits.len() {
                                    break;
                                }

                                self.reps = [self.reps[3], self.reps[0], self.reps[1], self.reps[2]];
                            }
                        }
                        size = 0;
                    }
                }

                let dist = self.reps[0];
                if size == 0 {
                    size = match self.decode_length(&bits, &mut pos) {
                        Some(v) => v,
                        None => break,
                    };
                }

                self.copy_match(dist, size);
            }
        }

        std::mem::take(&mut self.decompressed)
    }

    fn decode_match_len_dist(&mut self, bits: &[u8], pos: &mut usize) -> Option<(usize, usize)> {
        let size = self.decode_length(bits, pos)?;
        let dist = self.decode_dist(bits, pos)?;
        Some((size, dist))
    }

    fn decode_length(&self, bits: &[u8], pos: &mut usize) -> Option<usize> {
        if *pos >= bits.len() {
            return None;
        }
        if bits[*pos] == 0 {
            *pos += 1;
            return Some(read_num(bits, pos, 3)? + 2);
        }
        *pos += 1;

        if *pos >= bits.len() {
            return None;
        }
        if bits[*pos] == 0 {
            *pos += 1;
            return Some(read_num(bits, pos, 3)? + 10);
        }
        *pos += 1;

        Some(read_num(bits, pos, 8)? + 18)
    }

    fn decode_dist(&self, bits: &[u8], pos: &mut usize) -> Option<usize> {
        let pos_slot = read_num(bits, pos, 6)?;

        if pos_slot < K_START_POS_MODEL_INDEX as usize {
            return Some(pos_slot);
        }

        let num_direct_bits = (pos_slot >> 1) - 1;
        let mut dist = (2 | (pos_slot & 1)) << num_direct_bits;

        if pos_slot < K_END_POS_MODEL_INDEX as usize {
            dist += reverse_bits(read_num(bits, pos, num_direct_bits)?, num_direct_bits as u8);
        } else {
            dist += read_num(bits, pos, num_direct_bits - K_NUM_ALIGN_BITS as usize)?
                << K_NUM_ALIGN_BITS;
            dist += reverse_bits(read_num(bits, pos, K_NUM_ALIGN_BITS as usize)?, K_NUM_ALIGN_BITS);
        }

        Some(dist)
    }

    fn copy_match(&mut self, dist: usize, mut size: usize) {
        let cur_len = self.decompressed.len() as i64;
        let start = cur_len - dist as i64 - 1;

        while size > 0 {
            let end = (start + size as i64).min(cur_len);

            let current_len = self.decompressed.len() as i64;
            let eff_start = if start < 0 {
                (current_len + start).max(0) as usize
            } else {
                start as usize
            };
            let eff_end = if end < 0 {
                (current_len + end).max(0) as usize
            } else {
                end as usize
            };

            if eff_start < eff_end {
                let slice = self.decompressed[eff_start..eff_end].to_vec();
                self.decompressed.extend(&slice);
            }

            size -= (end - start) as usize;
        }
    }
}

fn reverse_bits(n: usize, bits: u8) -> usize {
    let mut rev = 0;
    for i in 0..bits {
        rev <<= 1;
        if n & (1 << i) != 0 {
            rev |= 1;
        }
    }
    rev
}

fn read_num(bits: &[u8], pos: &mut usize, count: usize) -> Option<usize> {
    if *pos + count > bits.len() {
        return None;
    }
    let mut num = 0;
    for _ in *pos..*pos + count {
        num = (num << 1) | bits[*pos] as usize;
        *pos += 1;
    }
    Some(num)
}
