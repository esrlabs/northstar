# frozen_string_literal: true

LEVEL_WARN = 1
LEVEL_INFO = 2
LEVEL_DEBUG = 3
LEVEL_TRACE = 4
VERBOSITY = LEVEL_DEBUG

EXAMPLE_DIR = `pwd`.strip + '/examples'
KEY_DIRECTORY = "#{EXAMPLE_DIR}/keys"
KEY_ID = 'north'

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
  is_installed = installed?(existence_check)
  puts warning unless is_installed
  is_installed
end

def supported_targets
  %w[aarch64-linux-android
     aarch64-unknown-linux-gnu
     x86_64-unknown-linux-gnu]
end

desc 'Check local environment'
task :check_environment do
  bundler_installed = check_program('bundle --version', 'ruby bundler is required. Please install with `gem install bundler`')
  check_program('rustup --version', 'Rustup is required. Please install first!')
  check_program('cargo --version', 'Rust is required. Please install Rust')
  check_program('cross --version', 'cross is required. Please install it first')
  check_program('docker --version', 'docker is required. Please install docker')
  if bundler_installed
    sh 'bundle check'
  else
    abort 'install bundler first'
  end
  require 'set'
  targets = `rustup target list`.lines.map(&:chomp)
  installed = Set[]
  targets.each do |t|
    installed.add t.sub!(/(.*)\s.*$/, '\\1') if t =~ /\(installed\)/
  end
  supported_targets.each do |needed|
    puts "target #{needed} needs to be installed" unless installed.include? needed
  end
  puts 'installed targets:'
  installed.each { |t| puts t }
end

desc 'Setup build environment'
task :setup_environment do
  sh 'bundle install'
  sh 'cargo install --path dcon'
  sh 'cargo install --version 0.2.0 cross'
  require 'os'
  if OS.linux?
    system 'sudo apt install squashfs-tools'
  elsif OS.mac?
    system 'brew install squashfs'
  end
  cd 'docker' do
    supported_targets.each do |t|
      sh "docker build -t north/#{t}:0.2.0 -f Dockerfile.#{t} ."
    end
  end
end

namespace :build do
  desc 'Build North runtime'
  task :north do
    sh 'cargo build --release --bin north'
  end

  desc 'Build dcon control client'
  task :north do
    sh 'cargo build --release --bin dcon'
  end

  desc 'Build everything'
  task :all do
    sh 'cargo build --release'
  end
end

def all_targets
  require 'os'
  targets = %w[
    aarch64-linux-android
    aarch64-unknown-linux-gnu
    x86_64-unknown-linux-gnu
  ]
  targets << 'x86_64-apple-darwin' if OS.mac?
  targets
end

def all_apps
  # %w[hello] # for testing
  %w[cpueater hello crashing datarw memeater resource_a]
end

namespace :examples do
  registry = `pwd`.strip + '/target/north/registry'

  desc 'Build examples'
  task :build do
    require './tooling.rb'

    mkdir_p registry unless Dir.exist?(registry)

    package_config = PackageConfig.new(1000, 1000, KEY_DIRECTORY, KEY_ID, 'squashfs')
    all_apps.each do |app|
      app_dir = "#{EXAMPLE_DIR}/container/#{app}"
      manifest = YAML.load_file("#{app_dir}/manifest.yaml")
      all_targets.each do |target_arch|
        target_dir = "#{app_dir}/root-#{target_arch}"
        mkdir_p target_dir unless Dir.exist?(target_dir)
        unless manifest['init'].nil? # is resource container?
          sh "cross build --release --bin #{app} --target #{target_arch}"
          cp "target/#{target_arch}/release/#{app}", target_dir
        end
        create_arch_package(target_arch, target_dir, app_dir, registry, package_config)
      end
    end
  end

  desc 'Clean example builds'
  task :clean do
    all_targets.each do |target_arch|
      all_apps.each do |app|
        app_dir = "#{EXAMPLE_DIR}/container/#{app}"
        manifest = YAML.load_file("#{app_dir}/manifest.yaml")
        next if manifest['init'].nil? # skip resource containers

        app_dir = "#{EXAMPLE_DIR}/container/#{app}"
        target_dir = "#{app_dir}/root-#{target_arch}"
        rm_rf target_dir
      end
    end
  end

  desc 'Execute runtime with examples'
  task :run do
    sh 'cargo run --bin north --release -- --config north.toml'
  end

  desc 'Clean example registry'
  task :drop do
    rm_rf registry
  end
end

task :clean do
  sh 'cargo clean'
end

desc 'Check'
task :check do
  check_program('docker info >/dev/null', 'Docker is needed to run the check task')
  sh 'cargo +nightly fmt -- --color=always --check'

  all_targets.each do |target|
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
