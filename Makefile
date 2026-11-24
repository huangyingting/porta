SHELL := /bin/bash

CARGO ?= $(HOME)/.cargo/bin/cargo
RUSTUP ?= $(HOME)/.cargo/bin/rustup
RUST_MANIFEST := rust/Cargo.toml
RUST_TARGET := rust/target
WINDOWS_TARGET := x86_64-pc-windows-gnu
WINTUN_VERSION := 0.14.1
WINTUN_ZIP := bin/wintun-$(WINTUN_VERSION).zip
WINTUN_SHA256 := 07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51

.PHONY: all build build-rust-server build-rust-clients build-windows build-linux-desktop build-masque-probe build-apple android android-debug \
	check-version check-dependencies lint-scripts fuzz clean test test-automation test-rust test-rust-server test-rust-client \
	test-rust-interop test-live-vpn test-cascade test-transport-relay test-tpm-attestation test-split-tunnel test-subnet-router test-exit-selection test-dns-resolver test-admin-identity test-gateway-failover test-ipv6 test-graceful-restart test-client-daemon test-peer-to-peer test-standard-masque test-apple-ffi test-apple test-service-user test-windows-cross test-native-firewall test-server-web \
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

# Coverage-guided fuzzing of the wire parsers; needs nightly and cargo-fuzz.
FUZZ_SECONDS ?= 30
FUZZ_TARGETS := capsules ip_packets device_proof peer_messages packet_frames durations
fuzz:
	cd rust/fuzz && $(CARGO) +nightly metadata --locked --format-version 1 >/dev/null && \
	for target in $(FUZZ_TARGETS); do \
		$(CARGO) +nightly fuzz run $$target -- \
			-max_total_time=$(FUZZ_SECONDS) -rss_limit_mb=2048 || exit 1; \
	done

# Needs cargo-deny (cargo install cargo-deny --locked).
check-dependencies:
	cd rust && $(CARGO) deny --all-features check

lint-scripts:
	shellcheck -S warning scripts/*.sh

test-automation:
	python3 scripts/test_automation.py

test-server-web:
	@if command -v node >/dev/null 2>&1; then \
		node --check rust/porta-server/assets/portal-client.js; \
		node --check rust/porta-server/assets/portal-join.js; \
		node --check rust/porta-windows/frontend/app.js; \
		inline=$$(mktemp --suffix=.js) && \
		python3 -c 'import re,sys; print("\n".join(re.findall(r"<script[^>]*>(.*?)</script>", open(sys.argv[1]).read(), re.S)))' \
			rust/porta-server/assets/admin.html >"$$inline" && node --check "$$inline"; status=$$?; rm -f "$$inline"; [ $$status -eq 0 ] || exit 1; \
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

test-cascade:
	$(CARGO) build --manifest-path $(RUST_MANIFEST) \
		--package porta-server-rust --package porta-client-rust --locked
	sudo -n ./scripts/test-cascade.sh $(RUST_TARGET)/debug/porta-server $(RUST_TARGET)/debug/porta-client
	sudo -n env PORTA_CASCADE_TRANSPORT=h2 ./scripts/test-cascade.sh \
		$(RUST_TARGET)/debug/porta-server $(RUST_TARGET)/debug/porta-client

test-subnet-router:
	$(CARGO) build --manifest-path $(RUST_MANIFEST) \
		--package porta-server-rust --package porta-client-rust --locked
	sudo -n ./scripts/test-subnet-router.sh $(RUST_TARGET)/debug/porta-server $(RUST_TARGET)/debug/porta-client
	sudo -n env PORTA_SUBNET_TRANSPORT=h2 ./scripts/test-subnet-router.sh \
		$(RUST_TARGET)/debug/porta-server $(RUST_TARGET)/debug/porta-client

test-exit-selection:
	$(CARGO) build --manifest-path $(RUST_MANIFEST) \
		--package porta-server-rust --package porta-client-rust --locked
	sudo -n ./scripts/test-exit-selection.sh $(RUST_TARGET)/debug/porta-server $(RUST_TARGET)/debug/porta-client
	sudo -n env PORTA_EXIT_TRANSPORT=h2 ./scripts/test-exit-selection.sh \
		$(RUST_TARGET)/debug/porta-server $(RUST_TARGET)/debug/porta-client

test-dns-resolver:
	$(CARGO) build --manifest-path $(RUST_MANIFEST) \
		--package porta-server-rust --package porta-client-rust --locked
	sudo -n ./scripts/test-dns-resolver.sh $(RUST_TARGET)/debug/porta-server $(RUST_TARGET)/debug/porta-client

test-admin-identity:
	$(CARGO) build --manifest-path $(RUST_MANIFEST) --package porta-server-rust --locked
	sudo -n ./scripts/test-admin-identity.sh $(RUST_TARGET)/debug/porta-server

test-gateway-failover:
	$(CARGO) build --manifest-path $(RUST_MANIFEST) \
		--package porta-server-rust --package porta-client-rust --locked
	sudo -n ./scripts/test-gateway-failover.sh $(RUST_TARGET)/debug/porta-server $(RUST_TARGET)/debug/porta-client
	sudo -n env PORTA_FAILOVER_TRANSPORT=h2 ./scripts/test-gateway-failover.sh \
		$(RUST_TARGET)/debug/porta-server $(RUST_TARGET)/debug/porta-client

test-ipv6:
	$(CARGO) build --manifest-path $(RUST_MANIFEST) \
		--package porta-server-rust --package porta-client-rust --locked
	sudo -n ./scripts/test-ipv6.sh $(RUST_TARGET)/debug/porta-server $(RUST_TARGET)/debug/porta-client
	sudo -n env PORTA_IPV6_TRANSPORT=h2 ./scripts/test-ipv6.sh \
		$(RUST_TARGET)/debug/porta-server $(RUST_TARGET)/debug/porta-client

test-graceful-restart:
	$(CARGO) build --manifest-path $(RUST_MANIFEST) \
		--package porta-server-rust --package porta-client-rust --locked
	sudo -n ./scripts/test-graceful-restart.sh $(RUST_TARGET)/debug/porta-server $(RUST_TARGET)/debug/porta-client
	sudo -n env PORTA_RESTART_TRANSPORT=h2 ./scripts/test-graceful-restart.sh \
		$(RUST_TARGET)/debug/porta-server $(RUST_TARGET)/debug/porta-client

# The independent CONNECT-IP client for interop tests (quic-go/connect-ip-go);
# it is test tooling, not part of any client.
build-masque-probe:
	cd experiments/masque-interop && go build -trimpath -o ../../bin/masque-probe .

test-peer-to-peer:
	$(CARGO) build --manifest-path $(RUST_MANIFEST) \
		--package porta-server-rust --package porta-client-rust --locked
	sudo -n ./scripts/test-peer-to-peer.sh $(RUST_TARGET)/debug/porta-server $(RUST_TARGET)/debug/porta-client

test-standard-masque: build-masque-probe
	$(CARGO) build --manifest-path $(RUST_MANIFEST) \
		--package porta-server-rust --package porta-client-rust --locked
	sudo -n ./scripts/test-standard-masque.sh $(RUST_TARGET)/debug/porta-server bin/masque-probe \
		$(RUST_TARGET)/debug/porta-client

# The C interface of the macOS and iOS apps, exercised from C on Linux.
test-apple-ffi:
	$(CARGO) build --manifest-path $(RUST_MANIFEST) \
		--package porta-server-rust --package porta-apple --locked
	cc -Wall -Wextra -Werror -std=c11 -D_DEFAULT_SOURCE -I rust/porta-apple/include \
		rust/porta-apple/tests/probe.c $(RUST_TARGET)/debug/libporta.a -lpthread -ldl -lm \
		-o $(RUST_TARGET)/debug/porta-ffi-probe
	sudo -n ./scripts/test-apple-ffi.sh $(RUST_TARGET)/debug/porta-server $(RUST_TARGET)/debug/porta-ffi-probe

# macOS with Xcode only: Porta.xcframework and the PortaKit Swift package.
build-apple:
	./scripts/build-apple.sh

test-apple: build-apple
	swift test --package-path apple
	cd apple && xcodebuild -quiet -scheme PortaKit -destination 'generic/platform=iOS' \
		-derivedDataPath build/derived build

test-client-daemon:
	$(CARGO) build --manifest-path $(RUST_MANIFEST) \
		--package porta-server-rust --package porta-client-rust --locked
	sudo -n ./scripts/test-client-daemon.sh $(RUST_TARGET)/debug/porta-server $(RUST_TARGET)/debug/porta-client

# Needs GTK and WebKitGTK development files, for example on Debian/Ubuntu:
# sudo apt-get install libwebkit2gtk-4.1-dev libgtk-3-dev
build-linux-desktop:
	$(CARGO) build --manifest-path $(RUST_MANIFEST) --release --package porta-linux --features gui --locked
	install -d bin
	install -m 0755 $(RUST_TARGET)/release/porta-desktop bin/porta-desktop

test-service-user:
	$(CARGO) build --manifest-path $(RUST_MANIFEST) \
		--package porta-server-rust --package porta-client-rust --locked
	sudo -n ./scripts/test-service-user.sh $(RUST_TARGET)/debug/porta-server $(RUST_TARGET)/debug/porta-client

test-tpm-attestation:
	$(CARGO) build --manifest-path $(RUST_MANIFEST) \
		--package porta-server-rust --package porta-client-rust --locked
	sudo -n ./scripts/test-tpm-attestation.sh $(RUST_TARGET)/debug/porta-server $(RUST_TARGET)/debug/porta-client

test-transport-relay:
	$(CARGO) build --manifest-path $(RUST_MANIFEST) \
		--package porta-server-rust --package porta-client-rust --locked
	sudo -n ./scripts/test-transport-relay.sh $(RUST_TARGET)/debug/porta-server $(RUST_TARGET)/debug/porta-client

test-split-tunnel:
	$(CARGO) build --manifest-path $(RUST_MANIFEST) \
		--package porta-server-rust --package porta-client-rust --locked
	sudo -n ./scripts/test-split-tunnel.sh $(RUST_TARGET)/debug/porta-server $(RUST_TARGET)/debug/porta-client
	sudo -n env PORTA_SPLIT_TRANSPORT=h2 ./scripts/test-split-tunnel.sh \
		$(RUST_TARGET)/debug/porta-server $(RUST_TARGET)/debug/porta-client

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
