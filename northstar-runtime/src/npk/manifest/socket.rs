use serde::{Deserialize, Serialize};
use validator::Validate;

/// Socket type
#[derive(Clone, Eq, PartialEq, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Type {
    /// Stream socket
    Stream,
    /// Datagram socket
    Datagram,
    /// Seqpacket socket
    SeqPacket,
}

/// Listening socket.
#[derive(Clone, Eq, PartialEq, Debug, Serialize, Deserialize, Validate)]
#[serde(deny_unknown_fields)]
pub struct Socket {
    /// Socket type.
    r#type: Type,
    ///p Socket permissions.
    mode: u32,
    /// User.
    #[validate(range(min = 1, message = "uid must be greater than 0"))]
    uid: Option<u32>,
    /// Group.
    #[validate(range(min = 1, message = "gid must be greater than 0"))]
    gid: Option<u32>,
}

#[test]
fn parse() -> anyhow::Result<()> {
    let input = r#"type: stream
mode: 0o777
uid: 1000
gid: 100"#;
    serde_yaml::from_str::<Socket>(input)?;

    let input = r#"type: stream
mode: 0
uid: 1000
gid: 100"#;
    serde_yaml::from_str::<Socket>(input)
        .map(drop)
        .map_err(Into::into)
}
