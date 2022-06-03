use tokio::time;

/// Tracks time points in a fixed window until _now_ and calculates necessary delays for new points
/// to limit their number in the window to a maximum.
pub struct Throttle {
    max_amount: usize,
    window: time::Duration,
    points: Vec<time::Instant>,
}

impl Throttle {
    /// Create a new window from a maximun number of points and a fixed duration
    pub fn new(max_amount: usize, window: time::Duration) -> Self {
        Self {
            max_amount,
            window,
            points: Vec::new(),
        }
    }

    /// Adds a new time point for _now_ to the window
    pub fn tick(&mut self) {
        self.points.push(time::Instant::now());
    }

    /// If the window is full, returns the delay till a new `tick` is possible
    pub fn expires(&mut self) -> Option<time::Duration> {
        let now = time::Instant::now();
        self.points.retain(|t| now - *t < self.window);

        // The point that once out of the window would allow a new point insertion
        let pivot = self.points.iter().rev().nth(self.max_amount - 1);

        // Return the point's remaining time in the window
        pivot.map(|t| *t + self.window - now)
    }
}

#[tokio::test(start_paused = true)]
async fn time_window_counter_test() {
    let mut tw = Throttle::new(2, time::Duration::from_secs(1));
    assert_eq!(tw.expires(), None);
    tw.tick();
    assert_eq!(tw.expires(), None);
    tw.tick();
    assert_eq!(tw.expires(), Some(time::Duration::from_secs(1)));
    tokio::time::advance(time::Duration::from_secs(1)).await;
    assert_eq!(tw.expires(), None);
}
