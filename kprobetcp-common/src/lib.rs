#![no_std]

#[repr(u8)]
#[derive(Debug, Clone, Copy)]
pub enum HttpMethod {
    UNKNOWN = 0,
    GET = 1,
    POST = 2,
    PUT = 3,
    DELETE = 4,
    PATCH = 5,
}

impl TryFrom<u8> for HttpMethod {
    type Error = ();
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(HttpMethod::UNKNOWN),
            1 => Ok(HttpMethod::GET),
            2 => Ok(HttpMethod::POST),
            3 => Ok(HttpMethod::PUT),
            4 => Ok(HttpMethod::DELETE),
            5 => Ok(HttpMethod::PATCH),
            _=> Err(())
        }
    }
}

#[repr(C)]
pub struct HttpEvent {
    pub method: u8,
    pub saddr: u32,
    pub daddr: u32,
    pub sport: u16,
    pub dport: u16,
    pub is_request: u8,
    pub _pad: [u8; 3],   //  // 1 = request, 0 = response
    pub data: [u8; 496], // 496 + 12 bytes header = 508 < 512
    pub timestamp: u64, 
}
