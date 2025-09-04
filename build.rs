use version_check::supports_feature;

fn main() {
    // Detect ptr_metadata (trait presence)
    check_feature(
        "ptr_metadata",
        "core::ptr::Pointee",
        "has_ptr_metadata",
        true,
    );

    // Detect Layout::for_value_raw (expression presence)
    check_feature(
        "layout_for_ptr",
        "std::alloc::Layout::for_value_raw::<[u8]>(std::ptr::null())",
        "has_layout_for_ptr",
        false,
    );
}

fn check_feature(feature_name: &str, probe_expr: &str, cfg_str: &str, is_trait: bool) {
    let support_by_feature = emit_need_feature(feature_name);

    let ac = autocfg::new();
    let support_by_default = if is_trait {
        ac.probe_trait(probe_expr)
    } else {
        ac.probe_expression(probe_expr)
    };

    autocfg::emit_possibility(cfg_str);
    if support_by_default || support_by_feature {
        autocfg::emit(cfg_str);
    }
}

fn emit_need_feature(feature: &str) -> bool {
    let cfg_str = format!("needs_{feature}_feature");
    autocfg::emit_possibility(&cfg_str);
    let support_this_feature = supports_feature(feature).unwrap_or(false);
    if support_this_feature {
        autocfg::emit(&cfg_str);
    }
    support_this_feature
}
