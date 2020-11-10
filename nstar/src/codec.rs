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

use anyhow::Error;
use bytes::{Buf, BufMut, Bytes};
use north::api::{self};
use tokio_util::codec;

pub(crate) enum Message {
    Message(api::Message),
    Raw(Bytes),
}

/// A tokio_util Codec for the north api protocol
#[derive(Default)]
pub(crate) struct Codec {
    len: Option<usize>,
}

impl codec::Encoder<Message> for Codec {
    type Error = Error;

    fn encode(&mut self, message: Message, dst: &mut bytes::BytesMut) -> Result<(), Self::Error> {
        match message {
            Message::Message(message) => {
                let message = serde_json::to_vec(&message)?;
                dst.reserve(4 + message.len());
                dst.put_u32(message.len() as u32);
                dst.put_slice(&message);
            }
            Message::Raw(slice) => {
                dst.extend_from_slice(&slice);
            }
        }
        Ok(())
    }
}

impl codec::Decoder for Codec {
    type Item = api::Message;
    type Error = Error;

    fn decode(&mut self, src: &mut bytes::BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        if self.len.is_none() {
            if src.remaining() >= 4 {
                let len = src.get_u32() as usize;
                self.len = Some(len);
            } else {
                return Ok(None);
            }
        }

        if let Some(len) = self.len {
            if src.remaining() >= len {
                let message: api::Message = serde_json::from_slice(&src[..len])?;
                src.advance(len);
                self.len.take();
                return Ok(Some(message));
            }
        }
        Ok(None)
    }
}
