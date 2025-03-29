use std::cmp::max;

use anyhow::{Result, bail};
use sha1::{Digest, Sha1};

// Protocol::HandshakeV10
// https://dev.mysql.com/doc/dev/mysql-server/8.4.3/page_protocol_connection_phase_packets_protocol_handshake_v10.html
#[derive(Debug)]
#[allow(dead_code)]
pub struct HandshakeV10 {
    protocol_version: u8,
    server_version: String,
    thread_id: u32,
    auth_plugin_data_part_1: Vec<u8>,
    filler: u8,
    capability_flags_1: u16,
    character_set: u8,
    status_flags: u16,
    capability_flags_2: u16,
    auth_plugin_data_len: u8,
    reserved: [u8; 10],
    auth_plugin_data_part_2: Vec<u8>,
    auth_plugin_name: String,
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
