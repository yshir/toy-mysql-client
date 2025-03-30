use anyhow::{Result, bail};

use crate::utils::{decode_lenenc_integer, decode_lenenc_string};

// COM_QUERY
// https://dev.mysql.com/doc/dev/mysql-server/8.4.3/page_protocol_com_query.html
#[derive(Debug)]
pub struct ComQuery {
    pub command: u8,
    pub parameter_count: u64,
    pub parameter_set_count: u64,
    pub query: String,
}

impl ComQuery {
    pub fn new(query: &str) -> Self {
        Self {
            command: 0x03,
            parameter_count: 0,
            parameter_set_count: 1,
            query: String::from(query),
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut pkt = vec![];

        pkt.push(self.command);
        pkt.push(self.parameter_count as u8);
        pkt.push(self.parameter_set_count as u8);
        pkt.append(&mut self.query.as_bytes().to_vec());

        pkt
    }
}

// Protocol::ColumnDefinition41
// https://dev.mysql.com/doc/dev/mysql-server/8.4.3/page_protocol_com_query_response_text_resultset_column_definition.html
#[derive(Debug)]
#[allow(dead_code)]
pub struct ColumnDefinition41 {
    pub catalog: String,
    pub schema: String,
    pub table: String,
    pub org_table: String,
    pub name: String,
    pub org_name: String,
    pub length_of_fixed_length_fields: u64,
    pub character_set: u16,
    pub column_length: u32,
    pub type_: u8,
    pub flags: u16,
    pub decimals: u8,
}

impl ColumnDefinition41 {
    pub fn decode(pkt: Vec<u8>) -> Result<Self> {
        let mut pos = 0;

        let (catalog, consumed) = decode_lenenc_string(&pkt, pos)?;
        pos += consumed;

        let (schema, consumed) = decode_lenenc_string(&pkt, pos)?;
        pos += consumed;

        let (table, consumed) = decode_lenenc_string(&pkt, pos)?;
        pos += consumed;

        let (org_table, consumed) = decode_lenenc_string(&pkt, pos)?;
        pos += consumed;

        let (name, consumed) = decode_lenenc_string(&pkt, pos)?;
        pos += consumed;

        let (org_name, consumed) = decode_lenenc_string(&pkt, pos)?;
        pos += consumed;

        let (length_of_fixed_length_fields, consumed) = decode_lenenc_integer(&pkt, pos)?;
        pos += consumed;

        let character_set = u16::from_le_bytes([pkt[pos], pkt[pos + 1]]);
        pos += 2;

        let column_length =
            u32::from_le_bytes([pkt[pos], pkt[pos + 1], pkt[pos + 2], pkt[pos + 3]]);
        pos += 4;

        let type_ = pkt[pos];
        pos += 1;

        let flags = u16::from_le_bytes([pkt[pos], pkt[pos + 1]]);
        pos += 2;

        let decimals = pkt[pos];
        // pos += 1;

        Ok(Self {
            catalog,
            schema,
            table,
            org_table,
            name,
            org_name,
            length_of_fixed_length_fields,
            character_set,
            column_length,
            type_,
            flags,
            decimals,
        })
    }
}

// ProtocolText::ResultsetRow
// https://dev.mysql.com/doc/dev/mysql-server/8.4.3/page_protocol_com_query_response_text_resultset_row.html
#[derive(Debug)]
#[allow(dead_code)]
pub struct ResultsetRow(pub Vec<String>);

impl ResultsetRow {
    pub fn decode(pkt: Vec<u8>) -> Result<Self> {
        let mut buf = vec![];
        let mut pos = 0;
        while pos < pkt.len() {
            let (s, consumed) = decode_lenenc_string(&pkt, pos)?;
            pos += consumed;
            buf.push(s);
        }
        Ok(Self(buf))
    }
}

// ERR_Packet
// https://dev.mysql.com/doc/dev/mysql-server/8.4.3/page_protocol_basic_err_packet.html
#[derive(Debug)]
#[allow(dead_code)]
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

    pub fn human_readable_text(&self) -> String {
        format!(
            "ERROR {} ({}): {}",
            self.error_code, self.sql_state, self.error_message
        )
    }
}
