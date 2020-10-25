# frozen_string_literal: true

LEVEL_WARN = 1
LEVEL_INFO = 2
LEVEL_DEBUG = 3
LEVEL_TRACE = 4
VERBOSITY = LEVEL_DEBUG

EXAMPLE_DIR = `pwd`.strip + '/examples'
KEY_DIRECTORY = "#{EXAMPLE_DIR}/keys"
KEY_ID = 'north'
KEY_FILE = "#{KEY_DIRECTORY}/#{KEY_ID}.key"
SEXTANT = `pwd`.strip + '/target/release/sextant'

def debug(content)
  puts("DEBUG: #{content}") unless VERBOSITY < LEVEL_DEBUG
end

def info(content)
  puts("INFO: #{content}") unless VERBOSITY < LEVEL_INFO
end

def warn(content)
  puts("WARN: #{content}") unless VERBOSITY < LEVEL_WARN
end

def installed?(existence_check)
  sh(existence_check, verbose: false) do |ok, _res|
    ok
  end
end

def check_program(existence_check, warning)
  is_installed = installed?(existence_check)
  puts warning unless is_installed
  is_installed
end

def development_target
  'x86_64-unknown-linux-gnu'
end

def supported_targets
  %w[aarch64-linux-android
     aarch64-unknown-linux-gnu
     aarch64-unknown-linux-musl
     x86_64-unknown-linux-gnu]
end

desc 'Check local environment'
task :check_environment do
  check_program('rustup --version', 'Rustup is required. Please install first!')
  check_program('cargo --version', 'Rust is required. Please install Rust')
  check_program('cross --version', 'cross is required. Please install it first')
  check_program('docker --version', 'docker is required. Please install docker')
  require 'set'
  targets = `rustup target list`.lines.map(&:chomp)
  installed = Set[]
  targets.each do |t|
    installed.add t.sub!(/(.*)\s.*$/, '\\1') if t =~ /\(installed\)/
  end
  supported_targets.each do |needed|
    puts "target #{needed} should be installed" unless installed.include? needed
  end
  puts 'installed targets:'
  installed.each { |t| puts t }
end

desc 'Setup build environment'
task :setup_environment do
  sh 'cargo install --path nstar'
  sh 'cargo install --version 0.2.1 cross'
  if OS.linux?
    system 'sudo apt install squashfs-tools'
  elsif OS.mac?
    system 'brew install squashfs'
  end
  cd 'docker' do
    supported_targets.each do |t|
      sh "docker build -t esrlabs/#{t}:0.2.1 -f Dockerfile.#{t} ."
    end
  end
end

namespace :build do
  desc 'Build North runtime'
  task :north do
    sh 'cargo build --release --bin north'
  end

  desc 'Build sextant tool'
  task :sextant do
    sh 'cargo build --release --bin sextant'
  end

  desc 'Release-Build everything'
  task :all do
    sh 'cargo build --release'
  end

  task :all_debug do
    sh 'cargo build'
  end
end

def runtime_targets
  targets = %w[
    aarch64-linux-android
    aarch64-unknown-linux-gnu
    aarch64-unknown-linux-musl
    x86_64-unknown-linux-gnu
  ]

  # Building for x86_64-apple-darwin is not possible via cross
  targets << 'x86_64-apple-darwin' if OS.mac?

  targets
end

def examples
  %w[
    cpueater
    crashing
    datarw
    hello
    memeater
    resource/ferris
    resource/ferris_says_hello
    resource/hello_message
  ]
end

def create_arch_package_sextant(container_src, out_dir, target_arch)
  sh "./target/release/sextant pack '\
      '-d #{container_src} -o #{out_dir} -k #{KEY_FILE} -p #{target_arch}"
end

file SEXTANT do
  sh 'cargo build --release --bin sextant'
end

namespace :examples do
  registry = `pwd`.strip + '/target/north/registry'
  run_dir = `pwd`.strip + '/target/north/run'

  desc 'Build examples'
  task :build => SEXTANT do
    sh './examples/build_examples.sh'
  end

  desc 'Clean example builds'
  task :clean do
    runtime_targets.each do |target_arch|
      examples.each do |dir|
        dir = "#{EXAMPLE_DIR}/container/#{dir}"
        next unless File.exist?("#{dir}/Cargo.toml") # skip non rust projects

        target_dir = "#{dir}/root-#{target_arch}"
        rm_rf target_dir
      end
    end
  end

  desc 'Execute runtime with examples (use with sudo on linux)'
  task run: 'build:north' do
    if OS.mac?
      sh './target/release/north --config north.toml'
    else
      sh 'sudo ./target/release/north --config north.toml'
    end
  end

  desc 'Clean example registry'
  task :drop do
    rm_rf registry
    rm_rf run_dir
  end

  def write_header(columns)
    puts "| #{columns.map { |_, g| g[:label].ljust(g[:width]) }.join(' | ')} |"
  end

  def write_divider(columns)
    puts "+-#{columns.map { |_, g| '-' * g[:width] }.join('-+-')}-+"
  end

  def write_line(h, columns)
    str = h.keys.map { |k| h[k].ljust(columns[k][:width]) }.join(' | ')
    puts "| #{str} |"
  end

  def table(col_labels, arr)
    @columns = col_labels.each_with_object({}) do |(col, label), h|
      h[col] = { label: label,
                 width: [arr.map { |g| g[col].size }.max, label.size].max }
    end

    write_divider(@columns)
    write_header(@columns)
    write_divider(@columns)
    arr.each { |h| write_line(h, @columns) }
    write_divider(@columns)
  end

  desc 'Show registry'
  task :registry do
    col_labels = { name: 'Name', arch: 'Arch', version: 'Version' }

    pkgs = Dir["#{registry}/*.npk"]
    abort 'registry empty' if pkgs.empty?

    registry_info = []
    pkgs.each do |pkg|
      file_name = File.basename(pkg, '.*')
      begin
        m = file_name.match(/(?<name>^.*)-(?<version>\d+\.\d+\.\d+)/i)
        captured = m.named_captures

        name = captured['name']
        supported_targets.each do |arch|
          if name.end_with?(arch)
            registry_info << { name: name.chomp(arch).chomp('-'), arch: arch, version: captured['version'] }
          end
        end
      rescue
        puts "Problems parsing file name #{file_name}"
      end
    end
    sorted = registry_info.sort_by { |entry| entry[:name] }
    table(col_labels, sorted)
  end
end

namespace :test_container do
  desc 'Build test container'
  task :build do
    require 'pathname'
    target_arch = 'x86_64-unknown-linux-gnu'
    dir = `pwd`.strip + '/tests/test_container'
    registry = `pwd`.strip + '/target/north/registry'
    key_directory = `pwd`.strip + '/target/north/keys'

    mkdir_p registry unless Dir.exist?(registry)
    mkdir_p key_directory unless Dir.exist?(key_directory)
    Dir["#{KEY_DIRECTORY}/*.pub"].each { |key| cp key, key_directory }

    target_dir = "#{dir}/root-#{target_arch}"
    mkdir_p target_dir unless Dir.exist?(target_dir)
    name = Pathname.new(dir).basename
    sh "cross build --release --bin #{name} --target #{target_arch}"
    cp "target/#{target_arch}/release/#{name}", target_dir

    tmp_dir = `mktemp -d`.strip
    root_dir="#{tmp_dir}/root"

    FileUtils.mkdir_p root_dir

    # copy manifest and root to tmp
    FileUtils.cp "#{dir}/manifest.yaml", tmp_dir
    FileUtils.cp_r "#{target_dir}/.", root_dir
    sh "tree #{tmp_dir}"
    create_arch_package_sextant(tmp_dir, registry, target_arch)
  end
end

task :clean => ['examples:drop'] do
  sh 'cargo clean'
end

desc 'Check'
task :check do
  check_program('docker info >/dev/null', 'Docker is needed to run the check task')
  sh 'cargo +nightly fmt -- --color=always --check'
  sh 'cargo +nightly clippy'
  sh 'cargo +nightly check'
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
  sh({ 'CARGO_INCREMENTAL' => '0', 'RUSTFLAGS' => rust_flags }, 'cargo +nightly build', verbose: false)
  sh({ 'CARGO_INCREMENTAL' => '0', 'RUSTFLAGS' => rust_flags }, 'cargo +nightly test', verbose: false)
  cov_dir = 'target/debug/coverage'
  sh "mkdir #{cov_dir}"
  sh "grcov ./target/debug/ -s north/src/ -t html --llvm --branch --ignore-not-existing -o ./#{cov_dir}/north"
  info "Code coverage report for north in: ./#{cov_dir}/north/index.html"
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
