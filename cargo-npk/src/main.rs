use std::env;

use anyhow::Result;

fn main() -> Result<()> {
    cargo_npk::npk(env::args())
}
