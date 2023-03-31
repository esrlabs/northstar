use std::fmt::{self, Display};

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

impl Display for Type {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Type::Stream => write!(f, "stream"),
            Type::Datagram => write!(f, "datagram"),
            Type::SeqPacket => write!(f, "seqpacket"),
        }
    }
}

/// Listening socket.
#[derive(Clone, Eq, PartialEq, Debug, Serialize, Deserialize, Validate)]
#[serde(deny_unknown_fields)]
pub struct Socket {
    /// Socket type.
    pub r#type: Type,
    ///p Socket permissions.
    pub mode: u32,
    /// User.
    #[validate(range(min = 1, message = "uid must be greater than 0"))]
    pub uid: Option<u32>,
    /// Group.
    #[validate(range(min = 1, message = "gid must be greater than 0"))]
    pub gid: Option<u32>,
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
