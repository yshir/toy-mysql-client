use std::{
    io::{BufReader, BufWriter, Read, Write},
    net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream},
    str::FromStr,
};

use anyhow::{Result, bail};

use crate::protocol::{HandshakeResponse41, HandshakeV10, OkPacket, ResponsePacket};

#[derive(Debug)]
pub struct Connection {
    username: String,
    password: String,
    database: String,
    stream: TcpStream,
    sequence: u8,
}

impl Connection {
    pub fn new(
        host: &str,
        port: u16,
        username: &str,
        password: &str,
        database: &str,
    ) -> Result<Self> {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::from_str(host)?), port);
        let stream = TcpStream::connect(addr)?;
        Ok(Self {
            stream,
            sequence: 0,
            username: String::from(username),
            password: String::from(password),
            database: String::from(database),
        })
    }

    pub fn handshake(&mut self) -> Result<()> {
        let handshake: HandshakeV10 = self.read_handshake()?;
        println!("dbg: read_handshake done");
        self.write_handshake_response(&handshake)?;
        println!("dbg: write_handshake_response done");
        self.read_ok_packet()?;
        println!("dbg: read_ok_packet done");
        println!("dbg: handshake done");
        Ok(())
    }

    pub fn read_handshake(&mut self) -> Result<HandshakeV10> {
        let payload = self.read_packet()?;
        let handshake = HandshakeV10::decode(payload)?;
        Ok(handshake)
    }

    pub fn read_ok_packet(&mut self) -> Result<OkPacket> {
        let payload = self.read_packet()?;
        let response = ResponsePacket::decode(payload)?;
        Ok(match response {
            ResponsePacket::Ok(pkt) => pkt,
            ResponsePacket::Err(pkt) => bail!("unexpected err packet: {:?}", pkt),
        })
    }

    pub fn write_handshake_response(&mut self, handshake: &HandshakeV10) -> Result<()> {
        let response = HandshakeResponse41::new(
            &self.username,
            &self.password,
            &self.database,
            handshake.auth_plugin_data(),
        );
        self.write_packet(response.encode())?;
        Ok(())
    }

    fn read_packet(&mut self) -> Result<Vec<u8>> {
        let mut buf = [0; 4];
        let mut reader = BufReader::new(&self.stream);
        reader.read_exact(&mut buf)?;
        let packet_len = u32::from_le_bytes([buf[0], buf[1], buf[2], 0]);
        let packet_seq = buf[3];
        if packet_seq != self.sequence {
            bail!("invalid sequence: {}", packet_seq);
        }
        self.sequence += 1;
        let mut buf = vec![0; packet_len as usize];
        reader.read_exact(&mut buf)?;
        Ok(buf)
    }

    fn write_packet(&mut self, payload: Vec<u8>) -> Result<()> {
        let mut writer = BufWriter::new(&self.stream);
        let packet_len = payload.len();
        let packet_seq = self.sequence;
        self.sequence += 1;
        let mut header = [0; 4];
        header[0] = packet_len as u8;
        header[1] = (packet_len >> 8) as u8;
        header[2] = (packet_len >> 16) as u8;
        header[3] = packet_seq;
        let packet = [header.to_vec(), payload].concat();
        writer.write_all(&packet)?;
        writer.flush()?;
        Ok(())
    }
}
