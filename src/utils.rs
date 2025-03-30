use anyhow::{Result, bail};

// Protocol::LengthEncodedString
// https://dev.mysql.com/doc/dev/mysql-server/8.4.3/page_protocol_basic_dt_strings.html#sect_protocol_basic_dt_string_le
pub fn decode_lenenc_string(pkt: &[u8], pos: usize) -> Result<(String, usize)> {
    let mut pos = pos;

    let head = pkt[pos];
    pos += 1;

    let val = String::from_utf8(pkt[pos..(pos + head as usize)].to_vec())?;
    let len = val.len();
    Ok((val, len + 1))
}

// Protocol::LengthEncodedInteger
// https://dev.mysql.com/doc/dev/mysql-server/8.4.3/page_protocol_basic_dt_integers.html#sect_protocol_basic_dt_int_le
pub fn decode_lenenc_integer(pkt: &[u8], pos: usize) -> Result<(u64, usize)> {
    let mut pos = pos;

    let head = pkt[pos];
    pos += 1;

    Ok(match head {
        // 1-byte integer
        0x00..=0xfa => (head as u64, 1),
        // 0xfc + 2-byte integer
        0xfc => (u16::from_le_bytes([pkt[pos], pkt[pos + 1]]) as u64, 3),
        // 0xfd + 3-byte integer
        0xfd => (
            u32::from_le_bytes([pkt[pos], pkt[pos + 1], pkt[pos + 2], 0]) as u64,
            4,
        ),
        // 0xfe + 8-byte integer
        0xfe => (
            u64::from_le_bytes([
                pkt[pos],
                pkt[pos + 1],
                pkt[pos + 2],
                pkt[pos + 3],
                pkt[pos + 4],
                pkt[pos + 5],
                pkt[pos + 6],
                pkt[pos + 7],
            ]),
            9,
        ),
        _ => bail!("unknown byte: {}", head),
    })
}
