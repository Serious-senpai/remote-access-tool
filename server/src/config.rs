pub const SSH_ID_STRING: &str = "SSH-2.0-remote-access-tool machine";

pub const KEX_ALGORITHMS: &str = "curve25519-sha256";
pub const SERVER_HOST_KEY_ALGORITHMS: &str = "rsa-sha2-512";
pub const ENCRYPTION_ALGORITHMS_CLIENT_TO_SERVER: &str = "chacha20-poly1305@openssh.com";
pub const ENCRYPTION_ALGORITHMS_SERVER_TO_CLIENT: &str = "chacha20-poly1305@openssh.com";
pub const MAC_ALGORITHMS_CLIENT_TO_SERVER: &str = "hmac-sha2-512";
pub const MAC_ALGORITHMS_SERVER_TO_CLIENT: &str = "hmac-sha2-512";
pub const COMPRESSION_ALGORITHMS_CLIENT_TO_SERVER: &str = "none";
pub const COMPRESSION_ALGORITHMS_SERVER_TO_CLIENT: &str = "none";
pub const LANGUAGES_CLIENT_TO_SERVER: &str = "";
pub const LANGUAGES_SERVER_TO_CLIENT: &str = "";
