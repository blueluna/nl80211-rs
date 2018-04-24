use std::fmt;

/// HardwareAddress is an eight octet identifier used for example as the
/// MAC address for Ethernet (802.3), Bluetooth or Wi-Fi (802.11)
#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug)]
pub struct HardwareAddress {
    value: [u8; 6],
}

impl HardwareAddress {
	pub fn bytes(&self) -> [u8; 6] {
		self.value.clone()
	}
}

impl fmt::Display for HardwareAddress {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		write!(f, "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
			self.value[0], self.value[1], self.value[2],
			self.value[3], self.value[4], self.value[5])
	}
}

impl<'a> From<&'a [u8]> for HardwareAddress {
	fn from(value: &'a [u8]) -> HardwareAddress {
		HardwareAddress {
			value: [value[0], value[1], value[2], value[3], value[4], value[5]]
		}
	}
}

impl From<[u8; 6]> for HardwareAddress {
	fn from(value: [u8; 6]) -> HardwareAddress {
		HardwareAddress {
			value: [value[0], value[1], value[2], value[3], value[4], value[5]]
		}
	}
}
