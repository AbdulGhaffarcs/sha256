#!/bin/bash
export PATH="/root/.cargo/bin:$PATH"

rm -rf /tmp/rust_build
mkdir -p /tmp/rust_build
cd /tmp/rust_build

cargo new --lib rust_engine
cd rust_engine

cat > Cargo.toml << 'TOML'
[package]
name = "rust_engine"
version = "0.1.0"
edition = "2021"

[lib]
crate-type = ["cdylib"]
TOML

cat > src/lib.rs << 'RUST'
use std::ffi::CStr;
use std::os::raw::c_char;

#[no_mangle]
pub extern "C" fn count_pattern(pattern: *const c_char, text: *const c_char) -> i32 {
    if pattern.is_null() || text.is_null() { return -1; }
    let p = unsafe { CStr::from_ptr(pattern).to_string_lossy().into_owned() };
    let t = unsafe { CStr::from_ptr(text).to_string_lossy().into_owned() };
    t.matches(p.as_str()).count() as i32
}

#[no_mangle]
pub extern "C" fn count_pattern_ci(pattern: *const c_char, text: *const c_char) -> i32 {
    if pattern.is_null() || text.is_null() { return -1; }
    let p = unsafe { CStr::from_ptr(pattern).to_string_lossy().to_lowercase() };
    let t = unsafe { CStr::from_ptr(text).to_string_lossy().to_lowercase() };
    t.matches(p.as_str()).count() as i32
}

#[no_mangle]
pub extern "C" fn count_lines_with_pattern(pattern: *const c_char, text: *const c_char) -> i32 {
    if pattern.is_null() || text.is_null() { return -1; }
    let p = unsafe { CStr::from_ptr(pattern).to_string_lossy().to_lowercase() };
    let t = unsafe { CStr::from_ptr(text).to_string_lossy().into_owned() };
    t.lines().filter(|line| line.to_lowercase().contains(p.as_str())).count() as i32
}
RUST

cargo build --release
cp target/release/librust_engine.so /app/engine.so
cd /
rm -rf /tmp/rust_build

# Create salt file
echo "7" > /app/salt.txt

cat > /app/analyze.rb << 'RUBY'
require 'fiddle'
require 'fiddle/import'

module RustLib
  extend Fiddle::Importer
  dlload '/app/engine.so'
  extern 'int count_pattern(char*, char*)'
  extern 'int count_pattern_ci(char*, char*)'
  extern 'int count_lines_with_pattern(char*, char*)'
end

syslog_path = ENV['SYSLOG_PATH'] || '/var/log/syslog'
log_data = File.exist?(syslog_path) ? File.read(syslog_path) : ''
salt = File.read('/app/salt.txt').strip.to_i

exact_raw = RustLib.count_pattern('ERROR', log_data)
ci        = RustLib.count_pattern_ci('error', log_data)
lines     = RustLib.count_lines_with_pattern('error', log_data)
checksum  = exact_raw ^ ci ^ lines

result_line = "exact=#{exact_raw + salt} ci=#{ci} lines=#{lines} checksum=#{checksum}"
puts result_line

timestamp = Time.now.to_i
File.open('/app/analyze.log', 'a') { |f| f.puts "#{timestamp} | #{result_line}" }
RUBY