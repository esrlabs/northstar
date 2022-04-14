use super::model;
use std::io::ErrorKind;
use tokio::io::{self, AsyncRead, AsyncWrite};
use tokio_util::codec::{Decoder, Encoder};

/// Newline delimited json codec for api::Message that on top implements AsyncRead and Write
pub struct Framed<T> {
    inner: tokio_util::codec::Framed<T, Codec>,
}

impl<T: AsyncRead + AsyncWrite> Framed<T> {
    /// Provides a [`Stream`] and [`Sink`] interface for reading and writing to this
    /// I/O object, using [`Decoder`] and [`Encoder`] to read and write the raw data.
    pub fn new(inner: T) -> Framed<T> {
        Framed {
            inner: tokio_util::codec::Framed::new(inner, Codec::default()),
        }
    }

    /// Provides a [`Stream`] and [`Sink`] interface for reading and writing to this
    /// I/O object, using [`Decoder`] and [`Encoder`] to read and write the raw data,
    /// with a specific read buffer initial capacity.
    /// [`split`]: https://docs.rs/futures/0.3/futures/stream/trait.StreamExt.html#method.split
    pub fn with_capacity(inner: T, capacity: usize) -> Framed<T> {
        Framed {
            inner: tokio_util::codec::Framed::with_capacity(inner, Codec::default(), capacity),
        }
    }
}

impl<T> std::ops::Deref for Framed<T> {
    type Target = tokio_util::codec::Framed<T, Codec>;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl<T> std::ops::DerefMut for Framed<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}

/// Newline delimited json
#[derive(Default)]
pub struct Codec {
    inner: tokio_util::codec::LinesCodec,
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
                request: Request::Containers
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
