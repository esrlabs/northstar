use super::model;
use std::io::ErrorKind;
use tokio::io::{self, AsyncRead, AsyncWrite};
use tokio_util::codec::{Decoder, Encoder, LinesCodec};

/// Newline delimited json
pub type Framed<T> = tokio_util::codec::Framed<T, Codec>;

/// Framed wrapper
pub fn framed<T>(inner: T) -> Framed<T>
where
    T: AsyncRead + AsyncWrite,
{
    tokio_util::codec::Framed::new(inner, Codec::default())
}

/// Framed wrapper with a defined maximum line length
pub fn framed_with_max_length<T>(inner: T, max_length: usize) -> Framed<T>
where
    T: AsyncRead + AsyncWrite,
{
    tokio_util::codec::Framed::new(inner, Codec::new_with_max_length(max_length))
}

/// Newline delimited json
#[derive(Default)]
pub struct Codec {
    inner: LinesCodec,
}

impl Codec {
    /// Returns a Codec with a maximum line length limit.
    ///
    /// If this is set, calls to Codec::decode will return a
    /// io::Error when a line exceeds the length limit. Subsequent calls
    /// will discard up to limit bytes from that line until a newline character
    /// is reached, returning None until the line over the limit has been fully
    /// discarded. After that point, calls to decode will function as normal.
    pub fn new_with_max_length(max_length: usize) -> Codec {
        Codec {
            inner: LinesCodec::new_with_max_length(max_length),
        }
    }
}

impl Decoder for Codec {
    type Item = model::Message;
    type Error = io::Error;

    fn decode(&mut self, src: &mut bytes::BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        self.inner
            .decode(src)
            .map_err(|e| io::Error::new(ErrorKind::Other, e))? // See LinesCodecError.
            .as_deref()
            .map(serde_json::from_str)
            .transpose()
            .map_err(|e| io::Error::new(ErrorKind::InvalidData, e))
    }
}

impl Encoder<model::Message> for Codec {
    type Error = io::Error;

    fn encode(
        &mut self,
        item: model::Message,
        dst: &mut bytes::BytesMut,
    ) -> Result<(), Self::Error> {
        self.inner
            .encode(serde_json::to_string(&item)?.as_str(), dst)
            .map_err(|e| io::Error::new(ErrorKind::Other, e))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::model::{Message, Notification, Request, Response};
    use bytes::BytesMut;
    use proptest::{prelude::Just, prop_oneof, proptest, strategy::Strategy};

    proptest! {
        #[test]
        fn encoding_a_message_then_decoding_it_yields_the_same_message(initial_message in mk_message()) {
            // Pre-condition.
            let mut message_as_bytes = BytesMut::default();

            // Action.
            let mut codec = Codec::default();

            codec.encode(initial_message.clone(), &mut message_as_bytes)?;
            let message = codec.decode(&mut message_as_bytes)?;

            // Post-condition.
            assert_eq!(message, Some(initial_message));
        }
    }

    fn mk_message() -> impl Strategy<Value = Message> {
        prop_oneof![
            Just(Message::Request {
                request: Request::List
            }),
            Just(Message::Request {
                request: Request::Shutdown
            }),
            Just(Message::Request {
                request: Request::Mount(vec!())
            }),
            Just(Message::Response {
                response: Response::Ok
            }),
            Just(Message::Notification {
                notification: Notification::Shutdown
            }),
        ]
    }
}
