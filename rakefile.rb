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
  info "Checking for #{gem}..."
  check_program("gem list -i #{gem}",
                "#{gem} is required. Please install it using \"gem install #{gem}\".")
end

required_gems = %w[colored
                   fileutils
                   rbnacl
                   yaml
                   rubyzip]

desc 'Check local environment'
task :check_environment do
  # TODO: This looks incomplete
  check_program('cargo --version', 'Rust is required. Please install Rust')
  required_gems.each { |gem| check_gem(gem) }
end

desc 'Setup build environment'
task :setup_environment do
  require 'os'

  required_gems.each do |gem|
    sh "gem install #{gem}" unless installed?("gem list -i #{gem}")
  end
  sh 'cargo install --path dcon'
  sh 'cargo install --version 0.2.0 cross'
  if OS.linux?
    system 'sudo apt install squashfs-tools'
  elsif OS.mac?
    system 'brew install squashfs'
  end
  sh "cd docker && docker build -t north/aarch64-linux-android:0.2.0 -f Dockerfile.aarch64-linux-android ."
  sh "cd docker && docker build -t north/aarch64-unknown-linux-gnu:0.2.0 -f Dockerfile.aarch64-unknown-linux-gnu ."
  sh "cd docker && docker build -t north/x86_64-unknown-linux-gnu:0.2.0 -f Dockerfile.x86_64-unknown-linux-gnu ."
end

namespace :build do
  desc 'Build North runtime'
  task :north do
    sh 'cargo build --release --bin north'
  end

  desc 'Build everything'
  task :all do
    sh 'cargo build --release'
  end

  desc 'Build examples'
  task :examples do
    require 'os'
    require './tooling.rb'
    targets = %w[
      aarch64-linux-android
      aarch64-unknown-linux-gnu
      x86_64-unknown-linux-gnu
    ]
    targets << 'x86_64-apple-darwin' if OS.mac?

    apps = %w[cpueater hello crashing datarw memeater]
    CONTAINER_SOURCES = "#{EXAMPLE_DIR}/container"
    targets.each do |target_arch|
      apps.each do |app|
        app_dir = "#{EXAMPLE_DIR}/container/#{app}"
        sh "cross build --release --bin #{app} --target #{target_arch}"
        target_dir = "#{app_dir}/root-#{target_arch}"
        mkdir_p target_dir unless Dir.exist?(target_dir)
        cp "target/#{target_arch}/release/#{app}", target_dir
      end
    end

    KEY_DIRECTORY = "#{EXAMPLE_DIR}/keys"
    REGISTRY = `pwd`.strip + '/target/north/registry'
    mkdir_p REGISTRY unless Dir.exist?(REGISTRY)
    pack_containers(REGISTRY, CONTAINER_SOURCES, KEY_DIRECTORY, 'north', 'squashfs', 1000, 1000)

    targets.each do |target_arch|
      apps.each do |app|
        app_dir = "#{EXAMPLE_DIR}/container/#{app}"
        target_dir = "#{app_dir}/root-#{target_arch}"
        rm "#{target_dir}/#{app}"
        rmdir target_dir
      end
    end
  end
end

task :clean do
  sh 'cargo clean'
end

desc 'Check'
task :check do
  require 'os'
  check_program("docker info >/dev/null", "Docker is needed to run the check task")
  sh 'cargo +nightly fmt -- --color=always --check'
  targets = %w[
    aarch64-linux-android
    aarch64-unknown-linux-gnu
    x86_64-unknown-linux-gnu
  ]
  targets << 'x86_64-apple-darwin' if OS.mac?

  targets.each do |target|
    sh "cross check --target #{target}"
    sh "cross clippy --target #{target}"
    sh 'cross test'
  end
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
