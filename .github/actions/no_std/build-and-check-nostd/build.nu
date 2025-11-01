#!/usr/bin/env nu
# ci/no_std/build.nu
# Read combined JSON {core, alloc} from stdin; use $env.TARGET; run cargo build --release.

def main [kind: string] {
  let data = ($in | decode base64 | decode | from json) 
  let rows = match $kind {
    'core' => $data.core,
    'alloc' => $data.alloc,
    _ => { print "Unknown kind: $kind"; exit 1 }
  }

  if ($rows | is-empty) {
    print $'No no_std rows of kind ({$kind}). Failing for visibility.'; exit 0
  }

  for row in $rows {
    let pkg  = $row.pkg
    let args = $row.args
    print $">> build: ($pkg) @ ($env.TARGET) [($args | str join ' ')]"
    ^cargo build --release -p $pkg --target $env.TARGET ...$args
  }
}
