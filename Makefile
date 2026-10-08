# hc-auth-server makefile

.PHONY: all test

all: test

test:
	cargo fmt --all -- --check
	cargo clippy --locked --workspace --all-targets -- -D warnings
	RUSTFLAGS="-D warnings" cargo test --locked --workspace --all-features
