# ci/no_std/lib.nu
# Exported helpers for no_std detection.

export def feature-extras [feat_map?: record]: nothing -> list<string> {
  let keys = (if ($feat_map == null) { [] } else { $feat_map | columns })
  $keys
  | where {|k| $k != 'default' and $k != 'std' and $k != 'alloc'}
  | sort
}

export def is-proc-macro-only [pkg: record]: nothing -> bool {
  let targets = ($pkg.targets | default [])
  if ($targets | is-empty) { return false }
  $targets
  | all {|t| ($t.kind | default [] | any {|k| $k == 'proc-macro'}) }
}

# Return workspace, non-proc-macro-only packages as compact records
export def liblike-members [meta: record]: nothing -> list<record> {
  let members = $meta.workspace_members
  $meta.packages
  | where {|p| $members | any {|m| $m == $p.id}}
  | where {|p| not (is-proc-macro-only $p)}
  | select id name features targets
  | sort-by name
}
