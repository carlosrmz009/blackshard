//! Bounded MS-OVBA compressed-container decoding.

/// Decodes one MS-OVBA compressed container without allowing its output to
/// exceed `maximum_output`.
pub fn decompress(input: &[u8], maximum_output: usize) -> Result<Vec<u8>, &'static str> {
    if input.first() != Some(&1) {
        return Err("invalid container signature");
    }
    let mut input_offset = 1usize;
    let mut output = Vec::new();
    while input_offset < input.len() {
        let header_bytes = input
            .get(input_offset..input_offset + 2)
            .ok_or("truncated chunk header")?;
        let header = u16::from_le_bytes([header_bytes[0], header_bytes[1]]);
        if header & 0x7000 != 0x3000 {
            return Err("invalid chunk signature");
        }
        let chunk_size = ((header & 0x0fff) as usize).saturating_add(3);
        let chunk_end = input_offset
            .checked_add(chunk_size)
            .ok_or("chunk offset overflow")?
            .min(input.len());
        let compressed = header & 0x8000 != 0;
        input_offset += 2;
        let chunk_output_start = output.len();
        if !compressed {
            let raw = input
                .get(input_offset..chunk_end)
                .ok_or("invalid raw chunk")?;
            if output.len().saturating_add(raw.len()) > maximum_output {
                return Err("output limit exceeded");
            }
            output.extend_from_slice(raw);
            input_offset = chunk_end;
            continue;
        }

        while input_offset < chunk_end {
            let flags = *input.get(input_offset).ok_or("missing token flags")?;
            input_offset += 1;
            for bit in 0..8 {
                if input_offset >= chunk_end {
                    break;
                }
                if flags & (1 << bit) == 0 {
                    if output.len() >= maximum_output {
                        return Err("output limit exceeded");
                    }
                    output.push(input[input_offset]);
                    input_offset += 1;
                    continue;
                }
                let token_bytes = input
                    .get(input_offset..input_offset + 2)
                    .ok_or("truncated copy token")?;
                let token = u16::from_le_bytes([token_bytes[0], token_bytes[1]]);
                input_offset += 2;
                let produced = output
                    .len()
                    .checked_sub(chunk_output_start)
                    .ok_or("invalid output position")?;
                if produced == 0 {
                    return Err("copy token precedes literal output");
                }
                let offset_bits = (usize::BITS - (produced.saturating_sub(1)).leading_zeros())
                    .clamp(4, 12) as u16;
                let length_bits = 16 - offset_bits;
                let length_mask = (1u16 << length_bits) - 1;
                let length = usize::from(token & length_mask) + 3;
                let distance = usize::from(token >> length_bits) + 1;
                if distance > produced
                    || output.len().saturating_add(length) > maximum_output
                    || output.len().saturating_add(length) > chunk_output_start.saturating_add(4096)
                {
                    return Err("invalid copy token");
                }
                for _ in 0..length {
                    let source = output
                        .len()
                        .checked_sub(distance)
                        .ok_or("copy offset underflow")?;
                    let value = *output.get(source).ok_or("copy offset outside output")?;
                    output.push(value);
                }
            }
        }
        input_offset = chunk_end;
    }
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn microsoft_uncompressed_example() {
        let encoded =
            hex::decode("0119b000616263646566676800696a6b6c6d6e6f70007172737475762e").unwrap();
        assert_eq!(
            decompress(&encoded, 4096).unwrap(),
            b"abcdefghijklmnopqrstuv."
        );
    }

    #[test]
    fn microsoft_compressed_example() {
        let encoded = hex::decode(
            "012fb000236161616263646582660070616768696a013808616b6c00206d6e6f700671027004007273747576107778797a002c",
        )
        .unwrap();
        assert_eq!(
            decompress(&encoded, 4096).unwrap(),
            b"#aaabcdefaaaaghijaaaaaklaaamnopqaaaaaaaaaaaarstuvwxyzaaa"
        );
    }
}
