// Copyright (c) 2020 ESRLabs
//
//   Licensed under the Apache License, Version 2.0 (the "License");
//   you may not use this file except in compliance with the License.
//   You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
//   Unless required by applicable law or agreed to in writing, software
//   distributed under the License is distributed on an "AS IS" BASIS,
//   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//   See the License for the specific language governing permissions and
//   limitations under the License.

use super::model;
use bytes::{Buf, BufMut};
use futures::Stream;
use std::{
    cmp::min,
    io::ErrorKind,
    pin::Pin,
    task::{self, Poll},
};
use task::Context;
use tokio::io::{self, AsyncRead, AsyncWrite};
use tokio_util::codec::{Decoder, Encoder};

/// Newline delimited json codec for api::Message that on top implementes AsyncRead and Write
pub struct Framed<T> {
    framed: tokio_util::codec::Framed<T, Codec>,
}

pub fn framed<T: AsyncRead + AsyncWrite>(io: T) -> Framed<T> {
    Framed {
        framed: tokio_util::codec::Framed::new(io, Codec {}),
    }
}

/// Newline delimited json
struct Codec;

impl Decoder for Codec {
    type Item = model::Message;
    type Error = io::Error;

    fn decode(&mut self, src: &mut bytes::BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        if let Some(position) = src.iter().position(|b| *b == b'\n') {
            let buf = src.split_to(position);
            // Consume the newline
            src.advance(1);
            match serde_json::from_slice::<model::Message>(&buf) {
                Ok(message) => Ok(Some(message)),
                Err(e) => Err(io::Error::new(ErrorKind::InvalidData, e)),
            }
        } else {
            Ok(None)
        }
    }
}

impl Encoder<model::Message> for Codec {
    type Error = io::Error;

    fn encode(
        &mut self,
        item: model::Message,
        dst: &mut bytes::BytesMut,
    ) -> Result<(), Self::Error> {
        dst.extend_from_slice(serde_json::to_string(&item)?.as_bytes());
        dst.reserve(1);
        dst.put_u8(b'\n');
        Ok(())
    }
}

impl<T: Unpin + AsyncRead + AsyncWrite> AsyncWrite for Framed<T> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        let t: &mut T = self.framed.get_mut();
        AsyncWrite::poll_write(Pin::new(t), cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        let t: &mut T = self.framed.get_mut();
        AsyncWrite::poll_flush(Pin::new(t), cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), io::Error>> {
        let t: &mut T = self.framed.get_mut();
        AsyncWrite::poll_shutdown(Pin::new(t), cx)
    }
}

impl<T: Unpin + AsyncRead + AsyncWrite> AsyncRead for Framed<T> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut io::ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.framed.read_buffer().is_empty() {
            let t: &mut T = self.framed.get_mut();
            AsyncRead::poll_read(Pin::new(t), cx, buf)
        } else {
            let n = min(buf.remaining(), self.framed.read_buffer().len());
            buf.put_slice(&self.framed.read_buffer_mut().split_to(n));
            Poll::Ready(Ok(()))
        }
    }
}

impl<T: Unpin + AsyncWrite + AsyncRead> Stream for Framed<T> {
    type Item = Result<model::Message, io::Error>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let framed = Pin::new(&mut self.framed);
        framed.poll_next(cx)
    }
}

impl<T: Unpin + AsyncRead + AsyncWrite> futures::sink::Sink<model::Message> for Framed<T> {
    type Error = io::Error;

    fn poll_ready(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Pin::new(&mut self.framed).poll_ready(cx)
    }

    fn start_send(mut self: Pin<&mut Self>, item: model::Message) -> Result<(), Self::Error> {
        Pin::new(&mut self.framed).start_send(item)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Pin::new(&mut self.framed).poll_flush(cx)
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Pin::new(&mut self.framed).poll_close(cx)
    }
}
