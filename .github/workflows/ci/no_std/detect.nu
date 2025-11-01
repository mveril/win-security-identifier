#!/usr/bin/env nu
# ci/no_std/detect.nu
# Read cargo metadata JSON from stdin; write a single JSON object:
# { core: [{pkg, args: [..]}], alloc: [{pkg, args: [..]}] }

use ./lib.nu *

def main [] {
  let meta = ((if ($in | is-empty) {
    ^cargo metadata --no-deps --format-version=1
  } else { $in }) | from json)
  let pkgs = (liblike-members $meta)

  mut core  = []
  mut alloc = []

  for p in $pkgs {
    let extras = (feature-extras $p.features)           # list<string> sans default/std/alloc

    # CORE
    let core_args = if ($extras | is-empty) {
      ["--no-default-features"]
    } else {
      ["--no-default-features", "--features", ($extras | str join ',')]
    }
    $core = ($core | append { pkg: $p.name, args: $core_args })

    # ALLOC
    let keys = (if ($p.features == null) { [] } else { $p.features | columns })
    if ($keys | any {|f| $f == 'alloc'}) {
      let alloc_args = if ($extras | is-empty) {
        ["--no-default-features", "--features", "alloc"]
      } else {
        let extra = ($extras | str join ',')
        ["--no-default-features", "--features", $"alloc,($extra)"]
      }
      $alloc = ($alloc | append { pkg: $p.name, args: $alloc_args })
    }
  }

  { core: $core, alloc: $alloc } | to json --raw
}
