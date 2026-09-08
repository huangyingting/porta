SHELL := /bin/bash

CARGO ?= $(HOME)/.cargo/bin/cargo
RUSTUP ?= $(HOME)/.cargo/bin/rustup
RUST_MANIFEST := rust/Cargo.toml
RUST_TARGET := rust/target
WINDOWS_TARGET := x86_64-pc-windows-gnu
WINTUN_VERSION := 0.14.1
WINTUN_ZIP := bin/wintun-$(WINTUN_VERSION).zip
WINTUN_SHA256 := 07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51

.PHONY: all build build-rust-server build-rust-clients build-windows android android-debug \
	check-version clean test test-automation test-rust test-rust-server test-rust-client \
	test-rust-interop test-live-vpn test-windows-cross test-native-firewall test-server-web \
	verify-wintun vet

all: build

check-version:
	./scripts/check-version.sh HEAD

test: test-rust test-automation test-server-web

test-rust:
	$(CARGO) fmt --manifest-path $(RUST_MANIFEST) --all -- --check
	$(CARGO) test --manifest-path $(RUST_MANIFEST) --workspace --all-targets --locked
	$(CARGO) clippy --manifest-path $(RUST_MANIFEST) --workspace --all-targets --locked -- -D warnings

test-rust-server:
	$(CARGO) test --manifest-path $(RUST_MANIFEST) --package porta-server-rust --all-targets --locked

test-rust-client:
	$(CARGO) test --manifest-path $(RUST_MANIFEST) \
		--package porta-client-rust \
		--package porta-keygen \
		--package porta-windows-package \
		--all-targets --locked

test-windows-cross:
	$(RUSTUP) target add $(WINDOWS_TARGET)
	$(CARGO) check --manifest-path $(RUST_MANIFEST) \
		--package porta-client-rust \
		--package porta-windows \
		--target $(WINDOWS_TARGET) \
		--all-targets --locked

test-automation:
	python3 scripts/test_automation.py

test-server-web:
	@if command -v node >/dev/null 2>&1; then \
		node --check rust/porta-server/assets/portal-client.js; \
		node --check rust/porta-server/assets/portal-join.js; \
		node --check rust/porta-windows/frontend/app.js; \
	else \
		echo "node is not installed; skipping browser script checks"; \
	fi

test-rust-interop:
	PORTA_BENCH_QUICK=1 ./experiments/server-benchmark/run.sh

test-live-vpn:
	./scripts/test-live-vpn.sh

test-native-firewall:
	./scripts/test-server-firewall.sh
	./scripts/test-rust-client-network.sh

vet:
	$(CARGO) clippy --manifest-path $(RUST_MANIFEST) --workspace --all-targets --locked -- -D warnings

build: build-rust-server build-rust-clients

build-rust-server:
	mkdir -p bin
	$(CARGO) build --manifest-path $(RUST_MANIFEST) --package porta-server-rust --release --locked
	cp $(RUST_TARGET)/release/porta-server bin/porta-server

build-rust-clients:
	mkdir -p bin
	$(CARGO) build --manifest-path $(RUST_MANIFEST) \
		--package porta-client-rust \
		--package porta-keygen \
		--release --locked
	cp $(RUST_TARGET)/release/porta-client bin/porta-client
	cp $(RUST_TARGET)/release/porta-keygen bin/porta-keygen

$(WINTUN_ZIP):
	mkdir -p bin
	curl -fsSL --proto '=https' --tlsv1.2 \
		-o $(WINTUN_ZIP).tmp \
		https://www.wintun.net/builds/wintun-$(WINTUN_VERSION).zip
	echo "$(WINTUN_SHA256)  $(WINTUN_ZIP).tmp" | sha256sum -c -
	mv $(WINTUN_ZIP).tmp $(WINTUN_ZIP)

verify-wintun: $(WINTUN_ZIP)
	echo "$(WINTUN_SHA256)  $(WINTUN_ZIP)" | sha256sum -c -

build-windows:
	command -v x86_64-w64-mingw32-gcc >/dev/null
	$(RUSTUP) target add $(WINDOWS_TARGET)
	$(CARGO) build --manifest-path $(RUST_MANIFEST) \
		--package porta-client-rust \
		--package porta-windows \
		--target $(WINDOWS_TARGET) \
		--release --locked

android-debug:
	cd android && ./gradlew testDebugUnitTest assembleDebug

android:
	cd android && ./gradlew testReleaseUnitTest assembleRelease

clean:
	$(CARGO) clean --manifest-path $(RUST_MANIFEST)
	rm -f bin/porta-server bin/porta-client bin/porta-keygen
	rm -f bin/porta-client-windows-amd64.zip $(WINTUN_ZIP) $(WINTUN_ZIP).tmp
	cd android && ./gradlew clean
