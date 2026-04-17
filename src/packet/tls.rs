use rand::Rng;

const TPL_HEX: &str = "1603010200010001fc030341d5b549d9cd1adfa7296c8418d157dc7b624c842824ff493b9375bb48d34f2b20bf018bcc90a7c89a230094815ad0c15b736e38c01209d72d282cb5e2105328150024130213031301c02cc030c02bc02fcca9cca8c024c028c023c027009f009e006b006700ff0100018f0000000b00090000066d63692e6972000b000403000102000a00160014001d0017001e0019001801000101010201030104002300000010000e000c02683208687474702f312e310016000000170000000d002a0028040305030603080708080809080a080b080408050806040105010601030303010302040205020602002b00050403040303002d00020101003300260024001d0020435bacc4d05f9d41fef44ab3ad55616c36e0613473e2338770efdaa98693d217001500d5";

const TEMPLATE_SNI: &[u8] = b"mci.ir";

pub const CLIENT_HELLO_SIZE: usize = 517;

fn template_bytes() -> Vec<u8> {
    hex::decode(TPL_HEX).expect("invalid template hex")
}

mod hex {
    pub fn decode(s: &str) -> Result<Vec<u8>, String> {
        if s.len() % 2 != 0 {
            return Err("odd length".into());
        }
        (0..s.len())
            .step_by(2)
            .map(|i| {
                u8::from_str_radix(&s[i..i + 2], 16).map_err(|e| e.to_string())
            })
            .collect()
    }
}

pub fn build_client_hello(sni: &str) -> Vec<u8> {
    assert!(sni.len() <= 219, "SNI too long (max 219 bytes)");

    let tpl = template_bytes();
    let sni_bytes = sni.as_bytes();
    let tpl_sni_len = TEMPLATE_SNI.len();

    let static1 = &tpl[..11];
    let static3 = &tpl[76..120];
    let static4 = &tpl[127 + tpl_sni_len..262 + tpl_sni_len];

    let mut rng = rand::rng();
    let mut random = [0u8; 32];
    let mut sess_id = [0u8; 32];
    let mut key_share = [0u8; 32];
    rng.fill_bytes(&mut random);
    rng.fill_bytes(&mut sess_id);
    rng.fill_bytes(&mut key_share);

    let pad_len = 219 - sni_bytes.len();

    let mut out = Vec::with_capacity(CLIENT_HELLO_SIZE);

    out.extend_from_slice(static1);
    out.extend_from_slice(&random);
    out.push(0x20);
    out.extend_from_slice(&sess_id);
    out.extend_from_slice(static3);

    let sni_ext_len = (sni_bytes.len() + 5) as u16;
    let sni_list_len = (sni_bytes.len() + 3) as u16;
    let sni_len = sni_bytes.len() as u16;
    out.extend_from_slice(&sni_ext_len.to_be_bytes());
    out.extend_from_slice(&sni_list_len.to_be_bytes());
    out.push(0x00);
    out.extend_from_slice(&sni_len.to_be_bytes());
    out.extend_from_slice(sni_bytes);

    out.extend_from_slice(static4);
    out.extend_from_slice(&key_share);

    out.extend_from_slice(&[0x00, 0x15]);
    out.extend_from_slice(&(pad_len as u16).to_be_bytes());
    out.extend_from_slice(&vec![0x00; pad_len]);

    assert_eq!(out.len(), CLIENT_HELLO_SIZE, "ClientHello size mismatch: got {}", out.len());
    out
}

pub fn parse_sni(client_hello: &[u8]) -> Option<String> {
    if client_hello.len() < CLIENT_HELLO_SIZE {
        return None;
    }
    let sni_len = u16::from_be_bytes([client_hello[125], client_hello[126]]) as usize;
    if 127 + sni_len > client_hello.len() {
        return None;
    }
    String::from_utf8(client_hello[127..127 + sni_len].to_vec()).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_client_hello_size() {
        let ch = build_client_hello("example.com");
        assert_eq!(ch.len(), CLIENT_HELLO_SIZE);
    }

    #[test]
    fn test_client_hello_sni() {
        let ch = build_client_hello("security.vercel.com");
        let sni = parse_sni(&ch).unwrap();
        assert_eq!(sni, "security.vercel.com");
    }

    #[test]
    fn test_client_hello_short_sni() {
        let ch = build_client_hello("a.b");
        assert_eq!(ch.len(), CLIENT_HELLO_SIZE);
        let sni = parse_sni(&ch).unwrap();
        assert_eq!(sni, "a.b");
    }

    #[test]
    fn test_client_hello_max_sni() {
        let sni = "a".repeat(219);
        let ch = build_client_hello(&sni);
        assert_eq!(ch.len(), CLIENT_HELLO_SIZE);
        let parsed = parse_sni(&ch).unwrap();
        assert_eq!(parsed, sni);
    }

    #[test]
    fn test_tls_record_header() {
        let ch = build_client_hello("test.com");
        assert_eq!(ch[0], 0x16);
        assert_eq!(ch[1], 0x03);
        assert_eq!(ch[2], 0x01);
    }
}
