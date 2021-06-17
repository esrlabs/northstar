REPOSITORY = `pwd`.strip + '/target/northstar/repository'

directory REPOSITORY

def targets
  %w[
    aarch64-linux-android
    aarch64-unknown-linux-gnu
    aarch64-unknown-linux-musl
    x86_64-unknown-linux-gnu
  ]
end

desc 'Check'
task :check do
  sh 'cargo +nightly fmt -- --color=always --check'
  sh 'cargo clippy'
  sh 'cargo test --all-features'

  targets.each do |target|
    sh "cross build --target #{target}"
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

  system 'sudo apt install squashfs-tools' unless which('mksquashfs')
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

desc 'Format code with nightly cargo fmt'
task :rustfmt do
  sh 'cargo +nightly fmt'
end

desc 'Display mount info for process with id'
task :mountinfo, [:id] do |t,args|
  process_id = args[:id]
  pid = `ps axf | grep #{process_id} | grep -v grep | grep -v rake | awk '{print $1}'`.strip
  raise "no running process with id #{process_id} found" if pid == ''

  # pid = `ps axf | grep #{process_id} | grep -v grep | awk '{print $1}'`.strip
  puts "========= /proc/#{pid} ========"
  output = `cat /proc/#{pid}/mountinfo`
  puts output
  puts '========= findmnt ========'
  found = `findmnt | grep #{process_id}`
  puts found
end
