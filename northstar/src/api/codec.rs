use super::model;
use futures::StreamExt;
use std::{io::ErrorKind, time::Duration};
use tokio::{
    io::{self, AsyncRead, AsyncWrite},
    time::Instant,
};
use tokio_util::codec::{Decoder, Encoder};

/// Newline delimited json codec for api::Message that on top implements AsyncRead and Write
pub struct Framed<T> {
    inner: tokio_util::codec::Framed<T, Codec>,
    rate_limitter: Option<TimeWindowCounter>,
}

impl<T: AsyncRead + AsyncWrite + Unpin> Framed<T> {
    /// Provides a [`Stream`] and [`Sink`] interface for reading and writing to this
    /// I/O object, using [`Decoder`] and [`Encoder`] to read and write the raw data.
    pub fn new(inner: T) -> Framed<T> {
        Framed {
            inner: tokio_util::codec::Framed::new(inner, Codec::default()),
            rate_limitter: None,
        }
    }

    /// Provides a [`Stream`] and [`Sink`] interface for reading and writing to this
    /// I/O object, using [`Decoder`] and [`Encoder`] to read and write the raw data,
    /// with a specific read buffer initial capacity.
    /// [`split`]: https://docs.rs/futures/0.3/futures/stream/trait.StreamExt.html#method.split
    pub fn with_capacity(inner: T, capacity: usize) -> Framed<T> {
        Framed {
            inner: tokio_util::codec::Framed::with_capacity(inner, Codec::default(), capacity),
            rate_limitter: None,
        }
    }

    /// Limit the incoming message rate to a maximum inside a time duration
    pub fn limit_incoming_rate(&mut self, rate: usize, duration: Duration) {
        self.rate_limitter = Some(TimeWindowCounter::new(rate, duration));
    }

    /// Returns the next decoded frame
    pub async fn next(&mut self) -> Option<Result<<Codec as Decoder>::Item, io::Error>> {
        if let Some(remaining) = self.rate_limitter.as_mut().and_then(|r| r.expires()) {
            tokio::time::sleep(remaining).await;
        }
        let item = self.inner.next().await;
        if let Some(limitter) = self.rate_limitter.as_mut() {
            limitter.tick();
        }
        item
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

/// Tracks time points in a fixed window until _now_ and calculates necessary delays for new points
/// to limit their number in the window to a maximum.
struct TimeWindowCounter {
    max_amount: usize,
    window: Duration,
    points: Vec<Instant>,
}

impl TimeWindowCounter {
    /// Create a new window from a maximun number of points and a fixed duration
    fn new(max_amount: usize, window: Duration) -> Self {
        Self {
            max_amount,
            window,
            points: Vec::new(),
        }
    }

    /// Adds a new time point for _now_ to the window
    fn tick(&mut self) {
        self.points.push(Instant::now());
    }

    /// If the window is full, returns the delay till a new `tick` is possible
    fn expires(&mut self) -> Option<Duration> {
        let now = Instant::now();
        self.points.retain(|t| now - *t < self.window);

        // The point that once out of the window would allow a new point insertion
        let pivot = self.points.iter().rev().nth(self.max_amount - 1);

        // Return the point's remaining time in the window
        pivot.map(|t| *t + self.window - now)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::model::{Message, Notification, Request, Response};
    use bytes::BytesMut;
    use proptest::{prelude::Just, prop_oneof, proptest, strategy::Strategy};
    use tokio_test::{assert_pending, assert_ready};

    #[tokio::test(start_paused = true)]
    async fn limited_stream_test() -> std::io::Result<()> {
        let mut buffer = encode_messages([
            Message::Request {
                request: Request::Containers,
            },
            Message::Request {
                request: Request::Repositories,
            },
            Message::Request {
                request: Request::Shutdown,
            },
        ])?;

        let cursor = std::io::Cursor::new(buffer.as_mut());
        let mut stream = Framed::with_capacity(cursor, 2);
        stream.limit_incoming_rate(2, Duration::from_secs(1));

        {
            let mut fut = tokio_test::task::spawn(stream.next());
            let msg = assert_ready!(fut.poll());
            assert!(matches!(
                msg,
                Some(Ok(model::Message::Request {
                    request: Request::Containers
                }))
            ));
        }

        {
            let mut fut = tokio_test::task::spawn(stream.next());
            let msg = assert_ready!(fut.poll());
            assert!(matches!(
                msg,
                Some(Ok(model::Message::Request {
                    request: Request::Repositories
                }))
            ));
        }

        {
            let mut fut = tokio_test::task::spawn(stream.next());
            assert_pending!(fut.poll());
            tokio::time::advance(Duration::from_secs(1)).await;
            let msg = assert_ready!(fut.poll());
            assert!(matches!(
                msg,
                Some(Ok(model::Message::Request {
                    request: Request::Shutdown
                }))
            ));
        }

        tokio::time::resume();
        assert!(stream.next().await.is_none());

        Ok(())
    }

    #[tokio::test(start_paused = true)]
    async fn time_window_counter_test() {
        let mut tw = TimeWindowCounter::new(2, Duration::from_secs(1));
        assert_eq!(tw.expires(), None);
        tw.tick();
        assert_eq!(tw.expires(), None);
        tw.tick();
        assert_eq!(tw.expires(), Some(Duration::from_secs(1)));
        tokio::time::advance(Duration::from_secs(1)).await;
        assert_eq!(tw.expires(), None);
    }

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

    fn encode_messages<M>(messages: M) -> std::io::Result<BytesMut>
    where
        M: IntoIterator<Item = Message>,
    {
        let mut codec = Codec::default();
        let mut buffer = BytesMut::new();
        for message in messages {
            codec.encode(message, &mut buffer)?;
        }
        Ok(buffer)
    }
}
