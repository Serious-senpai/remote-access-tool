use std::error::Error;

use rsa::pkcs1v15::{Signature, VerifyingKey};
use rsa::sha2::Sha512;
use rsa::signature::Verifier;
use rsa::traits::PublicKeyParts;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use packets::SSHPacket;
use payloads::format::PayloadFormat;
use payloads::kex_ecdh_init::KexEcdhInit;
use payloads::kex_ecdh_reply::KexEcdhReply;
use payloads::kexinit::KexInit;
use sshkey::Ed25519KeyPair;

mod config;
mod errors;
mod packets;
mod payloads;
mod sshkey;
mod utils;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let mut stream = TcpStream::connect("localhost:22").await?;

    /*
    All implementations MUST be able to process packets with an
    uncompressed payload length of 32768 bytes or less and a total packet
    size of 35000 bytes or less (including 'packet_length',
    'padding_length', 'payload', 'random padding', and 'mac').  The
    maximum of 35000 bytes is an arbitrarily chosen value that is larger
    than the uncompressed length noted above.  Implementations SHOULD
    support longer packets, where they might be needed.  For example, if
    an implementation wants to send a very large number of certificates,
    the larger packets MAY be sent if the identification string indicates
    that the other party is able to process them.  However,
    implementations SHOULD check that the packet length is reasonable in
    order for the implementation to avoid denial of service and/or buffer
    overflow attacks.
    */

    stream.readable().await?;
    let server_id_string = {
        /*
        The server MAY send other lines of data before sending the version
        string.  Each line SHOULD be terminated by a Carriage Return and Line
        Feed.  Such lines MUST NOT begin with "SSH-", and SHOULD be encoded
        in ISO-10646 UTF-8 [RFC3629] (language is not specified).  Clients
        MUST be able to process such lines.  Such lines MAY be silently
        ignored, or MAY be displayed to the client user.  If they are
        displayed, control character filtering, as discussed in [SSH-ARCH],
        SHOULD be used.  The primary use of this feature is to allow TCP
        wrappers to display an error message before disconnecting.
        */
        let mut buf = vec![];
        loop {
            let byte = stream.read_u8().await?;
            buf.push(byte);
            if byte == b'\n' {
                let line = String::from_utf8(buf)?;
                print!("{}", line);
                if line.starts_with("SSH-") {
                    // Remove the CRLF (i.e. \r\n) characters
                    break Ok::<String, Box<dyn Error>>(String::from(
                        line.trim_end_matches("\r\n"),
                    ));
                }

                buf = vec![];
            }
        }?
    };

    stream.writable().await?;
    stream.write(config::SSH_ID_STRING.as_bytes()).await?;
    stream.write(b"\r\n").await?;

    let server_kexinit_packet = SSHPacket::from_stream(&mut stream).await?;
    KexInit::from_packet(&server_kexinit_packet).await?;

    let client_kexinit = KexInit::new();
    let client_kexinit_packet = client_kexinit.to_packet().await?;

    client_kexinit_packet.to_stream(&mut stream).await?;

    let key_pair = Ed25519KeyPair::new();

    let kex_ecdh_init = KexEcdhInit::new(key_pair.public_key.clone());
    let packet = kex_ecdh_init.to_packet().await?;

    packet.to_stream(&mut stream).await?;

    let packet = SSHPacket::from_stream(&mut stream).await?;
    let kex_ecdh_reply = KexEcdhReply::from_packet(&packet).await?;

    println!(
        "Host public key is e = {}, n = {}",
        kex_ecdh_reply.server_host_key.e(),
        kex_ecdh_reply.server_host_key.n(),
    );

    let shared_secret = Ed25519KeyPair::x25519(
        key_pair.private_seed.clone(),
        kex_ecdh_reply.public_key.clone(),
    );

    let exhash = kex_ecdh_reply
        .exchange_hash(
            config::SSH_ID_STRING.as_bytes(),
            server_id_string.as_bytes(),
            &client_kexinit_packet.payload,
            &server_kexinit_packet.payload,
            &key_pair.public_key,
            &shared_secret,
        )
        .await?;

    let verify_key = VerifyingKey::<Sha512>::new(kex_ecdh_reply.server_host_key.clone());
    let signature = Signature::try_from(kex_ecdh_reply.signature.as_slice())?;

    verify_key.verify(&exhash, &signature)?;

    Ok(())
}
