REPOSITORY = `pwd`.strip + '/target/northstar/repository'
KEY = `pwd`.strip + '/examples/keys/northstar.key'

directory REPOSITORY

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
    memeater
    minijail
    northstar
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

namespace :examples do
  desc 'Build example containers'
  task :build => REPOSITORY do
    sh './examples/build_examples.sh'
  end

  desc 'Clean examples'
  task :clean do
    rm_rf Dir.glob("#{REPOSITORY}/*.npk")
  end

  desc 'list examples repository'
  task :list do
    Dir.glob("#{REPOSITORY}/*.npk").each do |npk|
      system "cargo run -q --bin sextant -- inspect --short #{npk}"
    end
  end
end

namespace :test do
  task :prepare => 'examples:build' do
    `cargo build -p northstar`
  end

  desc 'Run integration tests'
  task :run => :prepare do
    puts `cargo test -p northstar_tests -- --test-threads 1 --ignored`
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
    sh "grcov ./target/debug/ -s northstar/src/ -t html --llvm --branch --ignore-not-existing -o ./#{cov_dir}/northstar"
    info "Code coverage report for northstar in: ./#{cov_dir}/northstar/index.html"
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
