#!/usr/bin/env ruby

require 'mkmf'

begin
  require 'os'
rescue LoadError
  puts "Please install the OS gem by running 'gem install OS'"
  exit
end

# Install ruby gems

# Check rust installation
find_executable 'cargo' or raise 'Cannot find cargo. Please visit https://rustup.rs'
find_executable 'rustc' or raise 'Cannot find rustc. Please visit https://rustup.rs'

system 'cargo install --path dcon'
system 'cargo install cross'
system 'rustup target add aarch64-linux-android'
system 'rustup target add x86_64-apple-darwin'
system 'rustup target add x86_64-unknown-linux-gnu'

if OS.linux?
  system 'sudo apt install squashfs-tools'
elsif OS.mac?
  system 'brew install squashfs'
end
