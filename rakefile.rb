# frozen_string_literal: true

LEVEL_WARN = 1
LEVEL_INFO = 2
LEVEL_DEBUG = 3
LEVEL_TRACE = 4
VERBOSITY = LEVEL_DEBUG

EXAMPLE_DIR = `pwd`.strip + '/examples'

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

namespace :build do
  desc 'Build North runtime'
  task :north do
    sh 'cargo build --release --bin north'
  end

  desc 'Build everything'
  task :all do
    sh 'cargo build --release --bin north'
    sh 'cargo build --release --bin dcon'
    sh 'cargo build --release --bin sextant'
  end

  desc 'Build example'
  task :example do
    require 'os'
    require './tooling.rb'
    targets = %w[aarch64-linux-android x86_64-unknown-linux-gnu]
    if OS.mac?
      targets << 'x86_64-apple-darwin'
    else
      warn "Cannot update container binaries for target x86_64-apple-darwin on #{RUBY_PLATFORM}"
    end

    apps = %w[cpueater hello]
    # TODO: add missing examples [crashing datarw memeater]
    # Compile the container binaries for each target and copy into the container sources
    # if the container source directory exists
    CONTAINER_SOURCES = "#{EXAMPLE_DIR}/res/container"
    targets.each do |target_arch|
      apps.each do |app|
        app_dir = "#{EXAMPLE_DIR}/res/container/#{app}"
        cd app_dir do
          sh "cross build --release --bin #{app} --target #{target_arch}"
        end
        target_dir = "#{app_dir}/root-#{target_arch}"
        mkdir_p target_dir unless Dir.exist?(target_dir)
        cp "#{app_dir}/target/#{target_arch}/release/#{app}", target_dir
      end
    end

    KEY_DIRECTORY = "#{EXAMPLE_DIR}/keys"
    REGISTRY = `pwd`.strip + '/target/north/registry'
    mkdir_p REGISTRY unless Dir.exist?(REGISTRY)
    create_containers(REGISTRY, CONTAINER_SOURCES, KEY_DIRECTORY, 'north')
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
