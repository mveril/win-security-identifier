#!/usr/bin/env nu
# ci/no_std/check.nu
# Read combined JSON {core, alloc} from stdin; use $env.TARGET; run cargo check --locked.

def main []: {
  let data = $in  | from json
  let rows = ([$data.core, $data.alloc] | flatten)

  if ($rows | is-empty) {
    print 'No no_std rows. Failing for visibility.'; exit 1
  }

  for row in $rows {
    let pkg  = $row.pkg
    let args = $row.args  # list<string>
    print $">> check: ($pkg) @ ($env.TARGET) [($args | str join ' ')]"
    ^cargo check --locked -p $pkg --target $env.TARGET ...$args
  }
}
