use std::{collections::VecDeque, io, pin::Pin};

use futures::{SinkExt, StreamExt};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    time::{self, Sleep},
};

use crate::api::{codec::Framed, model::Message};

/// Tracks time points in a fixed window until _now_ and calculates necessary delays for new points
/// to limit their number in the window to a maximum.
pub struct Throttle<I> {
    max_amount: usize,
    window: time::Duration,
    points: VecDeque<time::Instant>,
    delay: Pin<Box<Sleep>>,
    framed: Framed<I>,
}

impl<I: AsyncRead + AsyncWrite + Unpin> Throttle<I> {
    /// Create a new window from a maximun number of points and a fixed duration
    pub fn new(framed: Framed<I>, max_amount: usize, window: time::Duration) -> Self {
        Self {
            max_amount,
            window,
            points: VecDeque::new(),
            delay: Box::pin(time::sleep(time::Duration::from_secs(0))),
            framed,
        }
    }

    /// Yield next message
    pub async fn next(&mut self) -> Option<io::Result<Message>> {
        self.delay.as_mut().await;

        let now = time::Instant::now();
        while let Some(t) = self.points.front() {
            if now - *t < self.window {
                break;
            } else {
                self.points.pop_front();
            }
        }

        if self.points.len() >= self.max_amount {
            if let Some(delay) = self.points.front().map(|t| self.window - (now - *t)) {
                self.delay = Box::pin(time::sleep(delay));
                self.delay.as_mut().await;
            }
        }

        match self.framed.next().await {
            Some(Ok(msg)) => {
                self.points.push_back(time::Instant::now());
                Some(Ok(msg))
            }
            Some(Err(e)) => Some(Err(e)),
            None => None,
        }
    }

    /// Send `message`
    pub async fn send(&mut self, message: Message) -> io::Result<()> {
        self.framed.send(message).await
    }
}

impl<I> std::ops::Deref for Throttle<I> {
    type Target = Framed<I>;

    fn deref(&self) -> &Self::Target {
        &self.framed
    }
}

impl<I> std::ops::DerefMut for Throttle<I> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.framed
    }
}
