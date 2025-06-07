use std::env::consts::OS;
use std::sync::LazyLock;

pub static SSH_ID_STRING: LazyLock<String> =
    LazyLock::new(|| format!("SSH-2.0-remote-access-tool {}", OS));

pub const LANGUAGES_CLIENT_TO_SERVER: &str = "";
pub const LANGUAGES_SERVER_TO_CLIENT: &str = "";
pub const ACK_CHUNKS_COUNT: usize = 10;
