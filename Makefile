check:
	cargo clean
	cargo fmt -- --check
	cargo clean
	cargo clippy --all-targets --all-features -- -D warnings
