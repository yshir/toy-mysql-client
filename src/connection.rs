use std::{
    io::{BufReader, BufWriter, Read, Write},
    net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream},
    str::FromStr,
};

use anyhow::{Result, bail};
use log::debug;

use crate::handshake::{HandshakeResponse41, HandshakeV10};

#[derive(Debug, Clone)]
pub struct ConnectionOptions {
    pub username: String,
    pub password: String,
    pub database: String,
    pub host: String,
    pub port: u16,
}

#[derive(Debug)]
pub struct Connection {
    options: ConnectionOptions,
    reader: BufReader<TcpStream>,
    writer: BufWriter<TcpStream>,
    sequence: u8,
}

impl Connection {
    pub fn new(options: ConnectionOptions) -> Result<Self> {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::from_str(&options.host)?), options.port);
        let stream = TcpStream::connect(addr)?;
        let reader = BufReader::new(stream.try_clone()?);
        let writer = BufWriter::new(stream);
        let mut conn = Self {
            options,
            reader,
            writer,
            sequence: 0,
        };
        conn.handshake()?;
        Ok(conn)
    }

    fn handshake(&mut self) -> Result<()> {
        debug!("handshake start");
        self.sequence = 0;
        let handshake = HandshakeV10::decode(self.read_packet()?)?;
        let response = HandshakeResponse41::new(
            &self.options.username,
            &self.options.password,
            &self.options.database,
            handshake.auth_plugin_data(),
        );
        self.write_packet(&response.encode())?;
        debug!("handshake done");

        Ok(())
    }

    fn read_packet(&mut self) -> Result<Vec<u8>> {
        let mut buf = [0; 4];
        self.reader.read_exact(&mut buf)?;
        let packet_len = u32::from_le_bytes([buf[0], buf[1], buf[2], 0]);
        let packet_seq = buf[3];
        if packet_seq != self.sequence {
            bail!("invalid sequence: {}", packet_seq);
        }
        self.sequence += 1;
        let mut buf = vec![0; packet_len as usize];
        self.reader.read_exact(&mut buf)?;
        debug!("read_packet: {:02?}", &buf);
        Ok(buf)
    }

    fn write_packet(&mut self, payload: &[u8]) -> Result<()> {
        let packet_len = payload.len();
        let packet_seq = self.sequence;
        self.sequence += 1;
        let mut header = [0; 4];
        header[0] = packet_len as u8;
        header[1] = (packet_len >> 8) as u8;
        header[2] = (packet_len >> 16) as u8;
        header[3] = packet_seq;
        let buf = [header.to_vec(), payload.to_vec()].concat();
        debug!("write_packet: {:02?}", &buf);
        self.writer.write_all(&buf)?;
        self.writer.flush()?;
        Ok(())
    }
}
