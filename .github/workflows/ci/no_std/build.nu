#!/usr/bin/env nu
# ci/no_std/build.nu
# Read combined JSON {core, alloc} from stdin; use $env.TARGET; run cargo build --release.

def main [] {
  let data = ($in | decode base64 | decode | from json) 
  let rows = ([$data.core, $data.alloc] | flatten)

  for row in $rows {
    let pkg  = $row.pkg
    let args = $row.args
    print $">> build: ($pkg) @ ($env.TARGET) [($args | str join ' ')]"
    ^cargo build --release -p $pkg --target $env.TARGET ...$args
  }
}
