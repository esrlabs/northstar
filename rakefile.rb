REGISTRY = `pwd`.strip + '/target/north/registry'
KEY = `pwd`.strip + '/examples/keys/north.key'

def cross_targets
  %w[
    aarch64-linux-android
    aarch64-unknown-linux-gnu
    aarch64-unknown-linux-musl
    x86_64-unknown-linux-gnu
  ]
end

def cross_packages
  %w[
    cpueater
    crashing
    datarw
    ferris
    hello
    memeater
    minijail
    north
    test_container
  ]
end

desc 'Check'
task :check do
  sh 'cargo +nightly fmt -- --color=always --check'
  sh 'cargo clippy'
  sh 'cargo check'
  sh 'cargo test'

  cross_targets.each do |target|
    cross_packages.each do |package|
      sh "cross build --target #{target} -p #{package}"
    end
  end
end

desc 'Check and insteall local development setup'
task :setup do
  def which(command)
    system("which #{command} > /dev/null 2>&1")
  end

  raise 'Rust is required' unless which('rustc')
  raise 'Cargo is required' unless which('cargo')
  raise 'Docker is required' unless which('docker')

  unless which('mksquashfs')
    system 'sudo apt install squashfs-tools' if OS.linux?
    system 'brew install squashfs' if OS.mac?
  end
  'cargo install --version 0.2.1 cross' unless which('cross')
end

namespace :test do
  desc 'Prepare integration test run'
  task :prepare do
    require 'tmpdir'
    mkdir_p REGISTRY unless Dir.exist?(REGISTRY)
    `./examples/build_examples.sh`
    `cargo build -p north`
    `cargo build -p nstar`
    `cargo build --release -p test_container`
  end

  desc 'Run integration tests'
  task :run => :prepare do
    puts `cargo test -p north_tests -- --test-threads 1 --ignored`
  end

  desc 'Test coverage'
  task :coverage do
    raise 'Test coverage runs on Linux only!' unless OS.linux?

    sh 'cargo clean'
    rust_flags = ['-Zprofile',
                  '-Ccodegen-units=1',
                  '-Copt-level=0',
                  '-Clink-dead-code',
                  '-Coverflow-checks=off'].join(' ')
    sh({ 'CARGO_INCREMENTAL' => '0', 'RUSTFLAGS' => rust_flags }, 'cargo +nightly build', verbose: false)
    sh({ 'CARGO_INCREMENTAL' => '0', 'RUSTFLAGS' => rust_flags }, 'cargo +nightly test', verbose: false)
    cov_dir = 'target/debug/coverage'
    sh "mkdir #{cov_dir}"
    sh "grcov ./target/debug/ -s north/src/ -t html --llvm --branch --ignore-not-existing -o ./#{cov_dir}/north"
    info "Code coverage report for north in: ./#{cov_dir}/north/index.html"
  end
end

desc 'Format code with nightly cargo fmt'
task :rustfmt do
  sh 'cargo +nightly fmt'
end

# os detection
module OS
  def self.windows?
    (/cygwin|mswin|mingw|bccwin|wince|emx/ =~ RUBY_PLATFORM) != nil
  end

  def self.mac?
    (/darwin/ =~ RUBY_PLATFORM) != nil
  end

  def self.unix?
    !OS.windows?
  end

  def self.linux?
    OS.unix? && !OS.mac?
  end
end
