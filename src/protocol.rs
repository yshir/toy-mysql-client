use std::cmp::max;

use anyhow::{Result, bail};
use sha1::{Digest, Sha1};

// Protocol::HandshakeV10
// https://dev.mysql.com/doc/dev/mysql-server/8.4.3/page_protocol_connection_phase_packets_protocol_handshake_v10.html
#[derive(Debug)]
pub struct HandshakeV10 {
    pub protocol_version: u8,
    pub server_version: String,
    pub thread_id: u32,
    pub auth_plugin_data_part_1: Vec<u8>,
    pub filler: u8,
    pub capability_flags_1: u16,
    pub character_set: u8,
    pub status_flags: u16,
    pub capability_flags_2: u16,
    pub auth_plugin_data_len: u8,
    pub reserved: [u8; 10],
    pub auth_plugin_data_part_2: Vec<u8>,
    pub auth_plugin_name: String,
}

impl HandshakeV10 {
    pub fn decode(pkt: Vec<u8>) -> Result<Self> {
        let mut pos = 0;

        let protocol_version = pkt[pos];
        if protocol_version != 10 {
            bail!("invalid protocol version: {}", protocol_version);
        }
        pos += 1;

        let server_version = {
            let mut buf = vec![];
            loop {
                let val = pkt[pos];
                pos += 1;
                if val == 0 {
                    break;
                }
                buf.push(val);
            }
            String::from_utf8(buf)?
        };

        let thread_id = u32::from_le_bytes([pkt[pos], pkt[pos + 1], pkt[pos + 2], pkt[pos + 3]]);
        pos += 4;

        let auth_plugin_data_part_1 = {
            let buf = &pkt[pos..(pos + 8)];
            pos += 8;
            buf.to_vec()
        };

        let filler = pkt[pos];
        pos += 1;

        let capability_flags_1 = u16::from_le_bytes([pkt[pos], pkt[pos + 1]]);
        pos += 2;

        let character_set = pkt[pos];
        pos += 1;

        let status_flags = u16::from_le_bytes([pkt[pos], pkt[pos + 1]]);
        pos += 2;

        let capability_flags_2 = u16::from_le_bytes([pkt[pos], pkt[pos + 1]]);
        pos += 2;

        let auth_plugin_data_len = pkt[pos];
        pos += 1;

        let reserved = [0u8; 10];
        pos += 10;

        let auth_plugin_data_part_2 = {
            let len = max(auth_plugin_data_len - 8, 13) as usize;
            let buf = &pkt[pos..(pos + len - 1)];
            pos += len;
            buf.to_vec()
        };

        let auth_plugin_name = {
            let mut buf = vec![];
            loop {
                let val = pkt[pos];
                pos += 1;
                if val == 0 {
                    break;
                }
                buf.push(val);
            }
            String::from_utf8(buf)?
        };

        Ok(Self {
            protocol_version,
            server_version,
            thread_id,
            auth_plugin_data_part_1,
            filler,
            capability_flags_1,
            character_set,
            status_flags,
            capability_flags_2,
            auth_plugin_data_len,
            reserved,
            auth_plugin_data_part_2,
            auth_plugin_name,
        })
    }

    pub fn auth_plugin_data(&self) -> Vec<u8> {
        [
            self.auth_plugin_data_part_1.clone(),
            self.auth_plugin_data_part_2.clone(),
        ]
        .concat()
    }
}

// Protocol::HandshakeResponse41
// https://dev.mysql.com/doc/dev/mysql-server/8.4.3/page_protocol_connection_phase_packets_protocol_handshake_response.html
#[derive(Debug)]
pub struct HandshakeResponse41 {
    pub client_flag: u32,
    pub max_packet_size: u32,
    pub character_set: u8,
    pub filler: [u8; 23],
    pub username: String,
    pub auth_response: Vec<u8>,
    pub database: String,
    pub client_plugin_name: String,
}

impl HandshakeResponse41 {
    #[allow(clippy::too_many_arguments)]
    pub fn new(username: &str, password: &str, database: &str, auth_plugin_data: Vec<u8>) -> Self {
        // Native Authentication
        // SHA1( password ) XOR SHA1( "20-bytes random data from server" <concat> SHA1( SHA1( password ) ) )
        // https://dev.mysql.com/doc/dev/mysql-server/8.4.3/page_protocol_connection_phase_authentication_methods_native_password_authentication.html
        let auth_response = {
            let mut sha1 = Sha1::new();

            let hash1 = {
                sha1.update(password);
                sha1.finalize_reset()
            };
            let hash2 = {
                sha1.update(hash1);
                sha1.finalize_reset()
            };
            let hash3 = {
                sha1.update(auth_plugin_data);
                sha1.update(hash2);
                sha1.finalize_reset()
            };

            hash1
                .iter()
                .zip(hash3)
                .map(|(a, b)| a ^ b)
                .collect::<Vec<_>>()
        };

        Self {
            client_flag: 0x19bfa28d,
            max_packet_size: 16777216, // 2 ^ 24
            character_set: 8,
            filler: [0; 23],
            username: String::from(username),
            auth_response,
            database: String::from(database),
            client_plugin_name: String::from("mysql_native_password"),
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut pkt = vec![];

        pkt.append(&mut self.client_flag.to_le_bytes().to_vec());
        pkt.append(&mut self.max_packet_size.to_le_bytes().to_vec());
        pkt.push(self.character_set);
        pkt.append(&mut self.filler.to_vec());
        pkt.append(&mut self.username.as_bytes().to_vec());
        pkt.push(0);
        pkt.push(self.auth_response.len() as u8);
        pkt.append(&mut self.auth_response.to_vec());
        pkt.append(&mut self.database.as_bytes().to_vec());
        pkt.push(0);
        pkt.append(&mut self.client_plugin_name.as_bytes().to_vec());
        pkt.push(0);

        let mut attribute_pkt = {
            let mut buf = vec![];
            let attributes = vec![
                ["_pid", "246"],
                ["_platform", "aarch64"],
                ["_os", "Linux"],
                ["_client_name", "libmysql"],
                ["os_user", "root"],
                ["_client_version", "8.3.0"],
                ["program_name", "mysql"],
            ];
            attributes.iter().for_each(|[k, v]| {
                buf.push(k.len() as u8);
                buf.append(&mut k.as_bytes().to_vec());
                buf.push(v.len() as u8);
                buf.append(&mut v.as_bytes().to_vec());
            });
            buf
        };
        pkt.push(attribute_pkt.len() as u8);
        pkt.append(&mut attribute_pkt);

        pkt
    }
}

// Generic Response Packets
// https://dev.mysql.com/doc/dev/mysql-server/8.4.3/page_protocol_basic_response_packets.html
pub enum ResponsePacket {
    Ok(OkPacket),
    Err(ErrPacket),
    // EofPacket,
}

impl ResponsePacket {
    pub fn decode(pkt: Vec<u8>) -> Result<Self> {
        let header = pkt[0];
        Ok(match header {
            0x00 | 0xfe => Self::Ok(OkPacket::decode(pkt)?),
            0xff => Self::Err(ErrPacket::decode(pkt)?),
            _ => bail!("unknown header: {}", header),
        })
    }
}

// OK_Packet
// https://dev.mysql.com/doc/dev/mysql-server/8.4.3/page_protocol_basic_ok_packet.html
#[derive(Debug)]
pub struct OkPacket {
    pub header: u8,
    pub affected_rows: u64,
    pub last_insert_id: u64,
}

impl OkPacket {
    pub fn decode(pkt: Vec<u8>) -> Result<Self> {
        let mut pos = 0;

        let header = pkt[pos];
        if header != 0x00 && header != 0xfe {
            bail!("not ok packet");
        }
        pos += 1;

        let (affected_rows, consumed) = decode_length_encoded_integer(&pkt, pos)?;
        pos += consumed;

        let (last_insert_id, _) = decode_length_encoded_integer(&pkt, pos)?;

        Ok(Self {
            header,
            affected_rows,
            last_insert_id,
        })
    }
}

// ERR_Packet
// https://dev.mysql.com/doc/dev/mysql-server/8.4.3/page_protocol_basic_err_packet.html
#[derive(Debug)]
pub struct ErrPacket {
    pub header: u8,
    pub error_code: u16,
    pub sql_state_marker: String,
    pub sql_state: String,
    pub error_message: String,
}

impl ErrPacket {
    pub fn decode(pkt: Vec<u8>) -> Result<Self> {
        let mut pos = 0;

        let header = pkt[pos];
        if header != 0xff {
            bail!("not err packet");
        }
        pos += 1;

        let error_code = u16::from_le_bytes([pkt[pos], pkt[pos + 1]]);
        pos += 2;

        let sql_state_marker = String::from_utf8(pkt[pos..(pos + 1)].to_vec())?;
        pos += 1;

        let sql_state = String::from_utf8(pkt[pos..(pos + 5)].to_vec())?;
        pos += 5;

        let error_message = String::from_utf8(pkt[pos..].to_vec())?;

        Ok(Self {
            header,
            error_code,
            sql_state_marker,
            sql_state,
            error_message,
        })
    }
}

// Protocol::LengthEncodedInteger
// https://dev.mysql.com/doc/dev/mysql-server/8.4.3/page_protocol_basic_dt_integers.html#sect_protocol_basic_dt_int_le
fn decode_length_encoded_integer(pkt: &[u8], pos: usize) -> Result<(u64, usize)> {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_handshake_v10() {
        let pkt = vec![
            0xa, 0x38, 0x2e, 0x33, 0x2e, 0x30, 0x0, 0x8, 0x0, 0x0, 0x0, 0x9, 0x12, 0x1, 0x3f, 0x41,
            0x22, 0x33, 0x36, 0x0, 0xff, 0xff, 0xff, 0x2, 0x0, 0xff, 0xdf, 0x15, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x15, 0x2, 0x25, 0xd, 0x44, 0xc, 0xc, 0x2c, 0x4f,
            0x5b, 0x6a, 0x55, 0x0, 0x6d, 0x79, 0x73, 0x71, 0x6c, 0x5f, 0x6e, 0x61, 0x74, 0x69,
            0x76, 0x65, 0x5f, 0x70, 0x61, 0x73, 0x73, 0x77, 0x6f, 0x72, 0x64, 0x0,
        ];
        let handshake = HandshakeV10::decode(pkt).unwrap();
        assert_eq!(handshake.protocol_version, 10);
        assert_eq!(handshake.server_version, "8.3.0");
        assert_eq!(handshake.thread_id, 8);
        assert_eq!(
            handshake.auth_plugin_data_part_1,
            vec![0x9, 0x12, 0x1, 0x3f, 0x41, 0x22, 0x33, 0x36]
        );
        assert_eq!(handshake.capability_flags_1, 0xffff);
        assert_eq!(handshake.character_set, 0xff);
        assert_eq!(handshake.status_flags, 0x0002);
        assert_eq!(handshake.capability_flags_2, 0xdfff);
        assert_eq!(handshake.auth_plugin_data_len, 21);
        assert_eq!(handshake.reserved, [0; 10]);
        assert_eq!(
            handshake.auth_plugin_data_part_2,
            vec![
                0x15, 0x2, 0x25, 0xd, 0x44, 0xc, 0xc, 0x2c, 0x4f, 0x5b, 0x6a, 0x55
            ]
        );
        assert_eq!(handshake.auth_plugin_name, "mysql_native_password");
    }

    #[test]
    fn test_handshake_response_41() {
        let response = HandshakeResponse41::new(
            "root",
            "root",
            "test",
            vec![
                0x9, 0x12, 0x1, 0x3f, 0x41, 0x22, 0x33, 0x36, 0x15, 0x2, 0x25, 0xd, 0x44, 0xc, 0xc,
                0x2c, 0x4f, 0x5b, 0x6a, 0x55,
            ],
        );
        assert_eq!(response.client_flag, 0x19bfa28d);
        assert_eq!(response.max_packet_size, 16777216);
        assert_eq!(response.character_set, 8);
        assert_eq!(response.filler, [0; 23]);
        assert_eq!(response.username, "root");
        assert_eq!(
            response.auth_response,
            vec![
                0xd5, 0xd2, 0xff, 0x2c, 0x94, 0x92, 0x95, 0x6f, 0x7f, 0xfa, 0x6c, 0x59, 0x21, 0x84,
                0xf1, 0x7e, 0xdf, 0xbe, 0x4b, 0x40,
            ]
        );
        assert_eq!(response.database, "test");
        assert_eq!(response.client_plugin_name, "mysql_native_password");

        let encoded = response.encode();
        assert_eq!(
            encoded,
            vec![
                0x8d, 0xa2, 0xbf, 0x19, 0x0, 0x0, 0x0, 0x1, 0x8, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
                0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
                0x72, 0x6f, 0x6f, 0x74, 0x0, 0x14, 0xd5, 0xd2, 0xff, 0x2c, 0x94, 0x92, 0x95, 0x6f,
                0x7f, 0xfa, 0x6c, 0x59, 0x21, 0x84, 0xf1, 0x7e, 0xdf, 0xbe, 0x4b, 0x40, 0x74, 0x65,
                0x73, 0x74, 0x0, 0x6d, 0x79, 0x73, 0x71, 0x6c, 0x5f, 0x6e, 0x61, 0x74, 0x69, 0x76,
                0x65, 0x5f, 0x70, 0x61, 0x73, 0x73, 0x77, 0x6f, 0x72, 0x64, 0x0, 0x71, 0x4, 0x5f,
                0x70, 0x69, 0x64, 0x3, 0x32, 0x34, 0x36, 0x9, 0x5f, 0x70, 0x6c, 0x61, 0x74, 0x66,
                0x6f, 0x72, 0x6d, 0x7, 0x61, 0x61, 0x72, 0x63, 0x68, 0x36, 0x34, 0x3, 0x5f, 0x6f,
                0x73, 0x5, 0x4c, 0x69, 0x6e, 0x75, 0x78, 0xc, 0x5f, 0x63, 0x6c, 0x69, 0x65, 0x6e,
                0x74, 0x5f, 0x6e, 0x61, 0x6d, 0x65, 0x8, 0x6c, 0x69, 0x62, 0x6d, 0x79, 0x73, 0x71,
                0x6c, 0x7, 0x6f, 0x73, 0x5f, 0x75, 0x73, 0x65, 0x72, 0x4, 0x72, 0x6f, 0x6f, 0x74,
                0xf, 0x5f, 0x63, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x5f, 0x76, 0x65, 0x72, 0x73, 0x69,
                0x6f, 0x6e, 0x5, 0x38, 0x2e, 0x33, 0x2e, 0x30, 0xc, 0x70, 0x72, 0x6f, 0x67, 0x72,
                0x61, 0x6d, 0x5f, 0x6e, 0x61, 0x6d, 0x65, 0x5, 0x6d, 0x79, 0x73, 0x71, 0x6c,
            ]
        );
    }
}
