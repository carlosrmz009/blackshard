//! Native reader for ClamAV `.cvd` / `.cld` definition containers.
//!
//! A CVD is a 512 byte ASCII header followed by a gzip compressed `ustar` archive. A CLD carries
//! the same header but stores the archive uncompressed. Reading both natively removes the need to
//! ship `freshclam.exe` and `sigtool.exe` alongside the agent purely to unpack definitions.
//!
//! Every container carries ClamAV's RSA signature over the MD5 of its archive, and
//! [`verify_signature`] checks it against ClamAV's published public key. Together with the body MD5
//! check in the downloader, that authenticates the container end to end, so a compromised mirror or
//! intercepted connection cannot substitute its own definitions.

use std::fs::{self, File};
use std::io::{self, BufReader, Read};
use std::path::{Component, Path};

use flate2::read::GzDecoder;
use num_bigint::BigUint;

/// Length of the fixed size ASCII header that introduces every container.
pub const HEADER_LEN: usize = 512;

const HEADER_MAGIC: &str = "ClamAV-VDB:";
const TAR_BLOCK: usize = 512;

/// Upper bound on a single extracted database file.
const MAX_ENTRY_BYTES: u64 = 2 * 1024 * 1024 * 1024;

/// Upper bound on the number of entries accepted from one container.
const MAX_ENTRIES: usize = 4096;

/// ClamAV's container signing key: modulus and public exponent, in decimal. These are the values
/// every ClamAV install verifies `.cvd` files against (`CLI_NSTR` / `CLI_ESTR` in libclamav).
const CLAMAV_MODULUS: &str = "118640995551645342603070001658453189751527774412027743746599405743243142607464144767361060640655844749760788890022283424922762488917565551002467771109669598189410434699034532232228621591089508178591428456220796841621637175567590476666928698770143328137383952820383197532047771780196576957695822641224262693037";
const CLAMAV_EXPONENT: u32 = 100_001_027;

/// The digit alphabet of ClamAV's signature encoding: base 64, but in this order, and with the
/// *first* character as the least significant digit.
const SIGNATURE_ALPHABET: &[u8; 64] =
    b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/";

#[derive(Debug)]
pub enum CvdError {
    Io(io::Error),
    Malformed(String),
}

impl std::fmt::Display for CvdError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "{error}"),
            Self::Malformed(detail) => write!(formatter, "{detail}"),
        }
    }
}

impl std::error::Error for CvdError {}

impl From<io::Error> for CvdError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

fn malformed(detail: impl Into<String>) -> CvdError {
    CvdError::Malformed(detail.into())
}

/// The colon delimited metadata that introduces a container.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CvdHeader {
    pub build_time: String,
    pub version: u64,
    pub signature_count: u64,
    pub functionality_level: u32,
    pub md5: String,
    /// ClamAV's RSA signature over `md5`, in its own base 64 encoding.
    pub signature: String,
    pub builder: String,
}

impl CvdHeader {
    /// Parses the fixed size header block.
    ///
    /// The layout is `ClamAV-VDB:` followed by nine colon separated fields: build time, version,
    /// signature count, required functionality level, MD5 of the archive, the RSA signature, the
    /// builder name and the build timestamp in seconds.
    pub fn parse(block: &[u8]) -> Result<Self, CvdError> {
        if block.len() < HEADER_LEN {
            return Err(malformed("the container header is shorter than 512 bytes"));
        }
        let text = std::str::from_utf8(&block[..HEADER_LEN])
            .map_err(|_| malformed("the container header is not valid ASCII"))?;
        let text = text.trim_end_matches('\0').trim_end();
        let Some(body) = text.strip_prefix(HEADER_MAGIC) else {
            return Err(malformed("the container is missing its ClamAV-VDB header"));
        };

        let fields: Vec<&str> = body.split(':').collect();
        if fields.len() < 7 {
            return Err(malformed(format!(
                "the container header declared {} fields, expected at least 7",
                fields.len()
            )));
        }

        let version = fields[1]
            .trim()
            .parse::<u64>()
            .map_err(|_| malformed("the container version is not a number"))?;
        let signature_count = fields[2]
            .trim()
            .parse::<u64>()
            .map_err(|_| malformed("the container signature count is not a number"))?;
        let functionality_level = fields[3]
            .trim()
            .parse::<u32>()
            .map_err(|_| malformed("the container functionality level is not a number"))?;

        let md5 = fields[4].trim().to_owned();
        if md5.len() != 32 || !md5.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(malformed("the container MD5 field is malformed"));
        }

        Ok(Self {
            build_time: fields[0].trim().to_owned(),
            version,
            signature_count,
            functionality_level,
            md5,
            signature: fields[5].trim().to_owned(),
            builder: fields[6].trim().to_owned(),
        })
    }
}

/// Checks that ClamAV signed this header's archive digest.
///
/// The signature decodes to an integer which, raised to ClamAV's public exponent modulo its public
/// key, must equal the 16 byte MD5 recorded in the header. The downloader separately confirms that
/// the archive body hashes to that MD5, so the two checks together authenticate the whole file.
///
/// This is ClamAV's legacy scheme: unpadded RSA over MD5. It is what `.cvd` files carry, and it is
/// adequate against substitution by a network attacker, who would need a second preimage of a
/// genuinely signed digest. Routing definitions through blackshard's own Ed25519 feed would retire
/// it.
pub fn verify_signature(header: &CvdHeader) -> Result<(), CvdError> {
    let modulus = BigUint::parse_bytes(CLAMAV_MODULUS.as_bytes(), 10)
        .expect("the ClamAV modulus constant is valid decimal");

    let mut signature = BigUint::default();
    for (position, symbol) in header.signature.bytes().enumerate() {
        let digit = SIGNATURE_ALPHABET
            .iter()
            .position(|candidate| *candidate == symbol)
            .ok_or_else(|| malformed("the container signature contains an invalid character"))?;
        signature += BigUint::from(digit) << (6 * position);
    }
    if signature == BigUint::default() || signature >= modulus {
        return Err(malformed("the container signature is out of range"));
    }

    let digest = signature
        .modpow(&BigUint::from(CLAMAV_EXPONENT), &modulus)
        .to_bytes_be();
    if digest.len() > 16 {
        return Err(malformed(
            "the container signature does not match its digest",
        ));
    }
    let mut padded = [0u8; 16];
    padded[16 - digest.len()..].copy_from_slice(&digest);

    if hex::encode(padded).eq_ignore_ascii_case(&header.md5) {
        Ok(())
    } else {
        Err(malformed(
            "the container signature does not match its digest",
        ))
    }
}

/// Reads only the header of a container, leaving the body untouched.
pub fn read_header(path: &Path) -> Result<CvdHeader, CvdError> {
    let mut block = [0u8; HEADER_LEN];
    File::open(path)?.read_exact(&mut block)?;
    CvdHeader::parse(&block)
}

/// Extracts every database file from `container` into `destination`.
///
/// Returns the container header together with the names that were written. Entries are flattened
/// to their base name: ClamAV containers are flat by construction, and refusing nested paths keeps
/// a hostile archive from escaping `destination`.
pub fn extract(container: &Path, destination: &Path) -> Result<(CvdHeader, Vec<String>), CvdError> {
    let mut file = BufReader::new(File::open(container)?);
    let mut block = [0u8; HEADER_LEN];
    file.read_exact(&mut block)?;
    let header = CvdHeader::parse(&block)?;

    fs::create_dir_all(destination)?;

    let compressed = container
        .extension()
        .and_then(|value| value.to_str())
        .is_none_or(|extension| !extension.eq_ignore_ascii_case("cld"));

    if compressed {
        unpack_tar(&mut GzDecoder::new(file), destination)
    } else {
        unpack_tar(&mut file, destination)
    }
    .map(|names| (header, names))
}

/// Minimal `ustar` reader covering the subset of the format ClamAV containers actually use.
fn unpack_tar<R: Read>(reader: &mut R, destination: &Path) -> Result<Vec<String>, CvdError> {
    let mut written = Vec::new();
    let mut block = [0u8; TAR_BLOCK];

    loop {
        if written.len() > MAX_ENTRIES {
            return Err(malformed(format!(
                "the container holds more than {MAX_ENTRIES} entries"
            )));
        }

        match read_full(reader, &mut block)? {
            0 => break,
            TAR_BLOCK => {}
            _ => return Err(malformed("the container archive ended mid header")),
        }

        // Two consecutive zero blocks terminate a tar archive.
        if block.iter().all(|byte| *byte == 0) {
            break;
        }

        let name = tar_string(&block[0..100])?;
        let size = tar_octal(&block[124..136])?;
        let type_flag = block[156];

        if size > MAX_ENTRY_BYTES {
            return Err(malformed(format!(
                "container entry {name} declares an implausible size of {size} bytes"
            )));
        }

        let padded = size.div_ceil(TAR_BLOCK as u64) * TAR_BLOCK as u64;

        // Regular files are `0` or the historical NUL. Everything else (directories, links,
        // PAX/GNU metadata) is skipped rather than interpreted.
        let is_regular = type_flag == b'0' || type_flag == 0;
        let Some(base) = safe_entry_name(&name) else {
            skip(reader, padded)?;
            continue;
        };

        if !is_regular {
            skip(reader, padded)?;
            continue;
        }

        let target = destination.join(&base);
        let mut output = File::create(&target)?;
        let mut remaining = size;
        let mut buffer = [0u8; 64 * 1024];
        while remaining > 0 {
            let want = remaining.min(buffer.len() as u64) as usize;
            let read = read_full(reader, &mut buffer[..want])?;
            if read != want {
                return Err(malformed(format!(
                    "container entry {base} ended before its declared size"
                )));
            }
            io::Write::write_all(&mut output, &buffer[..read])?;
            remaining -= read as u64;
        }
        skip(reader, padded - size)?;
        written.push(base);
    }

    Ok(written)
}

/// Rejects anything that is not a plain file name, defeating `../` traversal and absolute paths.
fn safe_entry_name(name: &str) -> Option<String> {
    let name = name.trim();
    if name.is_empty() {
        return None;
    }
    let path = Path::new(name);
    let mut components = path.components();
    let (Some(Component::Normal(single)), None) = (components.next(), components.next()) else {
        return None;
    };
    let single = single.to_str()?;
    if single == "." || single == ".." || single.contains('\\') {
        return None;
    }
    Some(single.to_owned())
}

fn tar_string(field: &[u8]) -> Result<String, CvdError> {
    let end = field
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(field.len());
    std::str::from_utf8(&field[..end])
        .map(|value| value.trim().to_owned())
        .map_err(|_| malformed("a container entry name is not valid UTF-8"))
}

fn tar_octal(field: &[u8]) -> Result<u64, CvdError> {
    let text = tar_string(field)?;
    let text = text.trim();
    if text.is_empty() {
        return Ok(0);
    }
    u64::from_str_radix(text, 8).map_err(|_| {
        malformed(format!(
            "a container entry has a malformed size field: {text}"
        ))
    })
}

/// Reads until `buffer` is full or the stream ends, returning how many bytes were read.
fn read_full<R: Read>(reader: &mut R, buffer: &mut [u8]) -> io::Result<usize> {
    let mut filled = 0;
    while filled < buffer.len() {
        match reader.read(&mut buffer[filled..]) {
            Ok(0) => break,
            Ok(count) => filled += count,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
    Ok(filled)
}

fn skip<R: Read>(reader: &mut R, mut count: u64) -> Result<(), CvdError> {
    let mut buffer = [0u8; 8 * 1024];
    while count > 0 {
        let want = count.min(buffer.len() as u64) as usize;
        let read = read_full(reader, &mut buffer[..want])?;
        if read == 0 {
            return Err(malformed("the container archive ended unexpectedly"));
        }
        count -= read as u64;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::write::GzEncoder;
    use flate2::Compression;
    use std::io::Write;

    fn header_block(md5: &str) -> Vec<u8> {
        let text = format!(
            "ClamAV-VDB:16 Sep 2026 09-00 +0000:27000:2000000:90:{md5}:{}:blackshard:1758009600",
            "a".repeat(40)
        );
        let mut block = text.into_bytes();
        block.resize(HEADER_LEN, b' ');
        block
    }

    fn tar_entry(name: &str, body: &[u8], type_flag: u8) -> Vec<u8> {
        let mut block = vec![0u8; TAR_BLOCK];
        block[..name.len()].copy_from_slice(name.as_bytes());
        let size = format!("{:011o}\0", body.len());
        block[124..124 + size.len()].copy_from_slice(size.as_bytes());
        block[156] = type_flag;
        let mut out = block;
        out.extend_from_slice(body);
        let padding = body.len().div_ceil(TAR_BLOCK) * TAR_BLOCK - body.len();
        out.extend(std::iter::repeat_n(0u8, padding));
        out
    }

    fn build_cvd(entries: &[(&str, &[u8], u8)], compressed: bool) -> Vec<u8> {
        let mut archive = Vec::new();
        for (name, body, flag) in entries {
            archive.extend_from_slice(&tar_entry(name, body, *flag));
        }
        archive.extend(std::iter::repeat_n(0u8, TAR_BLOCK * 2));

        let body = if compressed {
            let mut encoder = GzEncoder::new(Vec::new(), Compression::fast());
            encoder.write_all(&archive).unwrap();
            encoder.finish().unwrap()
        } else {
            archive
        };

        let mut out = header_block(&"0".repeat(32));
        out.extend_from_slice(&body);
        out
    }

    /// Headers exactly as `database.clamav.net` served them, captured for these tests.
    const REAL_MAIN_HEADER: &str = "ClamAV-VDB:16 Dec 2025 23-18 +0000:63:3287027:90:9c353a6b32555186a45a61c6441f38c0:gI9w3cezaElJbedEoiykyQeX1f6j9Xbs3a+cf9U/kH5QScGMe2mRz1K2JlYOrqfBuOUMbiKmvkVvAquOsMeDp/ejLVDx5WulC6klZVhLOfBHda29OjaLZwEGR9GPIHDr0mXriv7pivuMH60/loxpASIJHLOszyj95pxVK+EaTCh:tomjudge:1765927102";
    const REAL_DAILY_HEADER: &str = "ClamAV-VDB:26 Sep 2026 06-24 +0000:28135:355678:90:f028011319ac371fc1d722bc77ce109d:dmZwAflr3ZUqHZNTqxgww2flmNvgqjHZFB2gI20Unm5Uvz6hM0SeuN4NCTPr+Jdwa7k6P3LJDH7vHrxzFq6hhN+EXuqpswsXEk/6bawtiAj2/m5rKm9jTRozA4SiZZTXaslHTJqKmpwunwss42/e7n02TPYjMQlHBC7x5JuYtaf:svc.clamav-publisher:1790403853";

    fn real(header: &str) -> CvdHeader {
        let mut block = header.as_bytes().to_vec();
        block.resize(HEADER_LEN, b' ');
        CvdHeader::parse(&block).unwrap()
    }

    #[test]
    fn genuine_clamav_signatures_verify() {
        for header in [REAL_MAIN_HEADER, REAL_DAILY_HEADER] {
            verify_signature(&real(header)).unwrap();
        }
    }

    #[test]
    fn a_signature_is_bound_to_its_own_digest() {
        // Swapping the digests between two genuinely signed headers must fail both ways.
        let mut main = real(REAL_MAIN_HEADER);
        let daily = real(REAL_DAILY_HEADER);
        main.md5 = daily.md5.clone();
        assert!(verify_signature(&main).is_err());

        let mut altered = real(REAL_DAILY_HEADER);
        altered.md5.replace_range(0..1, "0");
        assert!(verify_signature(&altered).is_err());
    }

    #[test]
    fn malformed_signatures_are_rejected() {
        for signature in ["", "not base64 at all!", "aaaa"] {
            let mut header = real(REAL_MAIN_HEADER);
            header.signature = signature.to_owned();
            assert!(verify_signature(&header).is_err(), "{signature:?}");
        }
        let mut tampered = real(REAL_MAIN_HEADER);
        tampered.signature.replace_range(10..11, "Z");
        assert!(verify_signature(&tampered).is_err());
    }

    #[test]
    fn parses_a_well_formed_header() {
        let header = CvdHeader::parse(&header_block(&"b".repeat(32))).unwrap();
        assert_eq!(header.version, 27_000);
        assert_eq!(header.signature_count, 2_000_000);
        assert_eq!(header.functionality_level, 90);
        assert_eq!(header.builder, "blackshard");
        assert_eq!(header.md5, "b".repeat(32));
    }

    #[test]
    fn rejects_a_container_without_the_magic_prefix() {
        let mut block = vec![b' '; HEADER_LEN];
        block[..5].copy_from_slice(b"NOTAV");
        assert!(CvdHeader::parse(&block).is_err());
    }

    #[test]
    fn rejects_a_header_with_a_malformed_digest() {
        let block = header_block("nothexadecimal");
        assert!(CvdHeader::parse(&block).is_err());
    }

    #[test]
    fn extracts_compressed_and_uncompressed_containers() {
        for (compressed, extension) in [(true, "cvd"), (false, "cld")] {
            let directory = tempfile::tempdir().unwrap();
            let container = directory.path().join(format!("daily.{extension}"));
            fs::write(
                &container,
                build_cvd(
                    &[
                        ("daily.hsb", b"aa:1:Test.One" as &[u8], b'0'),
                        ("daily.msb", b"512:bb:Test.Two", b'0'),
                    ],
                    compressed,
                ),
            )
            .unwrap();

            let out = directory.path().join("out");
            let (header, names) = extract(&container, &out).unwrap();
            assert_eq!(header.version, 27_000);
            assert_eq!(names, vec!["daily.hsb", "daily.msb"]);
            assert_eq!(
                fs::read_to_string(out.join("daily.hsb")).unwrap(),
                "aa:1:Test.One"
            );
        }
    }

    #[test]
    fn refuses_path_traversal_entries() {
        let directory = tempfile::tempdir().unwrap();
        let container = directory.path().join("evil.cvd");
        fs::write(
            &container,
            build_cvd(
                &[
                    ("../escaped.hsb", b"aa:1:Escaped" as &[u8], b'0'),
                    ("/absolute.hsb", b"bb:1:Absolute", b'0'),
                    ("nested/inner.hsb", b"cc:1:Nested", b'0'),
                    ("kept.hsb", b"dd:1:Kept", b'0'),
                ],
                true,
            ),
        )
        .unwrap();

        let out = directory.path().join("out");
        let (_, names) = extract(&container, &out).unwrap();
        assert_eq!(names, vec!["kept.hsb"]);
        assert!(!directory.path().join("escaped.hsb").exists());
    }

    #[test]
    fn skips_directory_entries_without_writing_them() {
        let directory = tempfile::tempdir().unwrap();
        let container = directory.path().join("daily.cvd");
        fs::write(
            &container,
            build_cvd(
                &[
                    ("somedir", b"" as &[u8], b'5'),
                    ("daily.hsb", b"aa:1:Test.One", b'0'),
                ],
                true,
            ),
        )
        .unwrap();

        let out = directory.path().join("out");
        let (_, names) = extract(&container, &out).unwrap();
        assert_eq!(names, vec!["daily.hsb"]);
        assert!(!out.join("somedir").exists());
    }
}
