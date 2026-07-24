use serde::{Deserialize, Serialize};
use std::io::{Read, Write};

#[derive(Serialize, Deserialize, Debug)]
pub enum ParseRequest {
    ScanPath(String),
    ScanHandle(u64), // casted from Windows HANDLE
}

#[derive(Serialize, Deserialize, Debug)]
pub enum ParseResult {
    Clean,
    Suspicious,
    Malicious,
    Error(String),
}

pub fn write_message<W: Write, T: Serialize>(writer: &mut W, msg: &T) -> std::io::Result<()> {
    let data = serde_json::to_vec(msg)?;
    let len = data.len() as u32;
    writer.write_all(&len.to_le_bytes())?;
    writer.write_all(&data)?;
    writer.flush()?;
    Ok(())
}

pub fn read_message<R: Read, T: for<'a> Deserialize<'a>>(reader: &mut R) -> std::io::Result<T> {
    let mut len_buf = [0u8; 4];
    reader.read_exact(&mut len_buf)?;
    let len = u32::from_le_bytes(len_buf) as usize;
    if len > 1024 * 1024 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "Message too large",
        ));
    }
    let mut data = vec![0; len];
    reader.read_exact(&mut data)?;
    serde_json::from_slice(&data).map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
}
