# frozen_string_literal: true

LEVEL_WARN = 1
LEVEL_INFO = 2
LEVEL_DEBUG = 3
LEVEL_TRACE = 4
VERBOSITY = LEVEL_DEBUG

def debug(content)
  require 'colored'
  puts("DEBUG: #{content}") unless VERBOSITY < LEVEL_DEBUG
end

def info(content)
  require 'colored'
  puts("#{'INFO'.green}: #{content}") unless VERBOSITY < LEVEL_INFO
end

def warn(content)
  require 'colored'
  puts("#{'WARN'.yellow}: #{content}") unless VERBOSITY < LEVEL_WARN
end

def installed?(existence_check)
  sh(existence_check, :verbose => false) do |ok, _res|
    ok
  end
end

def check_program(existence_check, warning)
  abort warning unless installed?(existence_check)
end

def check_gem(gem)
  puts "checking: #{gem}..."
  check_program("gem list -i #{gem}",
                "#{gem} is required. Please install it using \"gem install #{gem}\".")
end

required_gems = %w[colored
                   fileutils
                   rbnacl
                   yaml
                   rubyzip]

desc 'checking local environment'
task :check_environment do
  check_program('cargo --version', 'Rust is required. Please install Rust')
  required_gems.each { |gem| check_gem(gem) }
end

desc 'setup build environment'
task :setup_environment do
  required_gems.each do |gem|
    sh "gem install #{gem}" unless installed?("gem list -i #{gem}")
  end
end

namespace :north do
  desc 'Build North'
  task :build do
    sh 'cargo build --bin north'
  end
end

task :clean do
  sh 'cargo clean'
end

desc 'Check'
task :check do
  sh 'cargo +nightly fmt -- --color=always --check'
  supported_targets = %w[x86_64-unknown-linux-gnu x86_64-apple-darwin]
  supported_targets_with_android = %w[x86_64-unknown-linux-gnu x86_64-apple-darwin aarch64-linux-android]
  # check if targets are installed
  installed = `rustup target list --installed`.split("\n")
  supported_targets.each do |target|
    unless installed.include?(target)
      raise "missing \"#{target}\", install with \"rustup target add #{target}\""
    end
  end
  supported_targets.each do |target|
    sh "cargo clippy --target #{target}"
  end
  sh 'cargo test'
end

desc 'Format code with nightly cargo fmt'
task :format do
  sh 'cargo +nightly fmt'
end

desc 'Test coverage'
task :coverage do
  sh 'cargo clean'
  rust_flags = ['-Zprofile',
                '-Ccodegen-units=1',
                '-Copt-level=0',
                '-Clink-dead-code',
                '-Coverflow-checks=off'].join(' ')
  sh({ 'CARGO_INCREMENTAL' => '0', 'RUSTFLAGS' => rust_flags }, 'cargo +nightly build', :verbose => false)
  sh({ 'CARGO_INCREMENTAL' => '0', 'RUSTFLAGS' => rust_flags }, 'cargo +nightly test', :verbose => false)
  cov_dir = 'target/debug/coverage'
  sh "mkdir #{cov_dir}"
  sh "grcov ./target/debug/ -s north_common/src/ -t html --llvm --branch --ignore-not-existing -o ./#{cov_dir}/north"
  info "Code coverage report for north in: ./#{cov_dir}/north/index.html"
end
