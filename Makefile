.PHONY: build release check clean test run publish publish-dry

build:
	cargo build

release:
	cargo build --release

check:
	cargo check

clean:
	cargo clean

test:
	cargo test

run:
	cargo run

publish:
	@./scripts/publish.sh

publish-dry:
	@./scripts/publish.sh --dry-run
