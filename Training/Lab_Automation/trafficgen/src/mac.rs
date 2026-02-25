use rand::Rng;

pub struct MacAddress {
    pub address: String,
    pub vendor: &'static str,
}

const OUI_DATABASE: &[(&str, [u8; 3])] = &[
    ("Dell", [0x00, 0x14, 0x22]),
    ("Dell", [0x24, 0xB6, 0xFD]),
    ("HP", [0x00, 0x1A, 0x4B]),
    ("HP", [0x3C, 0xD9, 0x2B]),
    ("HPE", [0x94, 0x57, 0xA5]),
    ("Intel", [0x00, 0x1B, 0x21]),
    ("Intel", [0x68, 0x05, 0xCA]),
    ("Intel", [0xA4, 0xBF, 0x01]),
    ("Lenovo", [0x00, 0x06, 0x1B]),
    ("Lenovo", [0x50, 0x7B, 0x9D]),
    ("Realtek", [0x00, 0xE0, 0x4C]),
    ("Realtek", [0x00, 0x0A, 0xCD]),
    ("Cisco", [0x00, 0x1A, 0xA1]),
    ("Cisco", [0x00, 0x26, 0x0B]),
    ("Cisco", [0xF4, 0xCF, 0xE2]),
    ("Apple", [0x00, 0x1F, 0xF3]),
    ("Apple", [0xA8, 0x51, 0xAB]),
    ("Apple", [0xDC, 0xA4, 0xCA]),
    ("Samsung", [0x00, 0x16, 0x32]),
    ("Samsung", [0x78, 0x47, 0x1D]),
    ("Samsung", [0xAC, 0x5A, 0x14]),
    ("TP-Link", [0x00, 0x27, 0x19]),
    ("TP-Link", [0x50, 0xC7, 0xBF]),
    ("ASUS", [0x00, 0x1A, 0x92]),
    ("ASUS", [0x2C, 0x56, 0xDC]),
    ("Netgear", [0x00, 0x1E, 0x2A]),
    ("Netgear", [0xA0, 0x04, 0x60]),
    ("D-Link", [0x00, 0x1C, 0xF0]),
    ("D-Link", [0xB8, 0xA3, 0x86]),
    ("Juniper", [0x00, 0x26, 0x88]),
    ("Juniper", [0xF0, 0x1C, 0x2D]),
    ("Aruba", [0x00, 0x0B, 0x86]),
    ("Aruba", [0x24, 0xDE, 0xC6]),
    ("Ubiquiti", [0x04, 0x18, 0xD6]),
    ("Ubiquiti", [0xFC, 0xEC, 0xDA]),
    ("Microsoft", [0x00, 0x15, 0x5D]),
    ("Microsoft", [0x00, 0x50, 0xF2]),
    ("VMware", [0x00, 0x0C, 0x29]),
    ("VMware", [0x00, 0x50, 0x56]),
    ("Broadcom", [0x00, 0x10, 0x18]),
    ("Broadcom", [0xD8, 0x38, 0xFC]),
    ("Qualcomm", [0x00, 0x03, 0x7F]),
    ("Qualcomm", [0x9C, 0xFC, 0x01]),
    ("Huawei", [0x00, 0x18, 0x82]),
    ("Huawei", [0xE0, 0x24, 0x7F]),
    ("Supermicro", [0x00, 0x25, 0x90]),
    ("Supermicro", [0xAC, 0x1F, 0x6B]),
    ("Mellanox", [0x00, 0x02, 0xC9]),
    ("Arista", [0x00, 0x1C, 0x73]),
    ("Fortinet", [0x00, 0x09, 0x0F]),
];

pub fn generate_mac() -> MacAddress {
    let mut rng = rand::thread_rng();
    let idx = rng.gen_range(0..OUI_DATABASE.len());
    let (vendor, oui) = OUI_DATABASE[idx];

    let b3: u8 = rng.gen();
    let b4: u8 = rng.gen();
    let b5: u8 = rng.gen();

    let address = format!(
        "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
        oui[0], oui[1], oui[2], b3, b4, b5
    );

    MacAddress { address, vendor }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_mac_format() {
        let mac = generate_mac();
        assert_eq!(mac.address.len(), 17);
        let parts: Vec<&str> = mac.address.split(':').collect();
        assert_eq!(parts.len(), 6);
        for part in &parts {
            assert_eq!(part.len(), 2);
            assert!(u8::from_str_radix(part, 16).is_ok());
        }
    }

    #[test]
    fn test_generate_mac_uses_real_vendor() {
        let mac = generate_mac();
        assert!(!mac.vendor.is_empty());
        let oui_str: String = mac.address[..8].to_uppercase();
        let found = OUI_DATABASE.iter().any(|(name, bytes)| {
            let formatted = format!("{:02X}:{:02X}:{:02X}", bytes[0], bytes[1], bytes[2]);
            formatted == oui_str && *name == mac.vendor
        });
        assert!(
            found,
            "MAC {} with vendor {} not in OUI database",
            mac.address, mac.vendor
        );
    }

    #[test]
    fn test_generate_mac_not_locally_administered() {
        for _ in 0..20 {
            let mac = generate_mac();
            let first_byte = u8::from_str_radix(&mac.address[..2], 16).unwrap();
            assert_eq!(
                first_byte & 0x02,
                0,
                "Locally administered bit is set on {}",
                mac.address
            );
        }
    }

    #[test]
    fn test_generate_mac_randomness() {
        let macs: Vec<MacAddress> = (0..10).map(|_| generate_mac()).collect();
        let first = &macs[0].address;
        let all_same = macs.iter().all(|m| m.address == *first);
        assert!(!all_same, "All 10 generated MACs were identical");
    }
}
