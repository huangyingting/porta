GO ?= go
CARGO ?= cargo
RUST_SERVER_MANIFEST := rust/porta-server/Cargo.toml

.PHONY: check-version test test-automation test-race test-native-firewall test-rust-server test-rust-interop test-server-web vet build build-rust-server build-go-clients build-windows android clean

check-version:
	./scripts/check-version.sh

test:
	$(GO) test ./...

test-automation:
	python3 scripts/test_automation.py
	$(GO) test ./scripts/package-windows.go ./scripts/package-windows_test.go

test-race:
	$(GO) test -race ./...

test-native-firewall:
	./scripts/test-server-firewall.sh

test-rust-server:
	$(CARGO) fmt --manifest-path $(RUST_SERVER_MANIFEST) --check
	$(CARGO) test --manifest-path $(RUST_SERVER_MANIFEST) --locked
	$(CARGO) clippy --manifest-path $(RUST_SERVER_MANIFEST) --locked --all-targets -- -D warnings
	$(MAKE) test-server-web

test-rust-interop:
	PORTA_SERVER_BENCH_WORK="$(CURDIR)/.server-interop" \
	PORTA_SERVER_BENCH_REPEATS=1 \
	PORTA_SERVER_BENCH_DURATION=250ms \
	PORTA_SERVER_BENCH_WARMUP=100ms \
	PORTA_SERVER_BENCH_CLIENTS=1 \
	PORTA_SERVER_BENCH_SERVER_CPUS=0 \
	PORTA_SERVER_BENCH_CLIENT_CPUS=0 \
	PORTA_SERVER_BENCH_SERVER_THREADS=1 \
	PORTA_SERVER_BENCH_CLIENT_THREADS=1 \
	PORTA_SERVER_BENCH_TRANSPORTS="h2 h3 auto" \
	PORTA_SERVER_BENCH_AUTO_MTU=true \
	CARGO="$(CARGO)" \
	./experiments/server-benchmark/run.sh

test-server-web:
	@if command -v node >/dev/null 2>&1; then \
		node scripts/tests/profile_qr_ui.cjs rust/porta-server/assets/admin.html; \
		node scripts/tests/onboarding_layout.cjs; \
	else \
		echo "Node.js not found; skipping server browser regressions"; \
	fi

vet:
	$(GO) vet ./...

build: build-rust-server build-go-clients

build-go-clients:
	mkdir -p bin
	CGO_ENABLED=0 $(GO) build -trimpath -o bin/porta-client ./cmd/porta-client
	CGO_ENABLED=0 $(GO) build -trimpath -o bin/porta-keygen ./cmd/porta-keygen

build-rust-server:
	$(CARGO) build --manifest-path $(RUST_SERVER_MANIFEST) --locked --release
	mkdir -p bin
	cp rust/porta-server/target/release/porta-server bin/porta-server

build-windows:
	rm -rf bin/windows-amd64
	mkdir -p bin/windows-amd64
	curl --fail --silent --show-error --location -o bin/wintun-0.14.1.zip https://www.wintun.net/builds/wintun-0.14.1.zip
	printf '%s  %s\n' 07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51 bin/wintun-0.14.1.zip | sha256sum -c -
	unzip -p bin/wintun-0.14.1.zip wintun/bin/amd64/wintun.dll > bin/windows-amd64/wintun.dll
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 $(GO) build -tags production -trimpath -ldflags="-s -w -H=windowsgui" -o bin/windows-amd64/porta.exe ./cmd/porta-windows
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 $(GO) build -trimpath -ldflags="-s -w" -o bin/windows-amd64/porta-cli.exe ./cmd/porta-client
	$(GO) run ./scripts/package-windows.go bin/porta-client-windows-amd64.zip bin/windows-amd64

android:
	cd android && ANDROID_HOME=$${ANDROID_HOME:-$$HOME/Android/Sdk} ./gradlew testDebugUnitTest assembleRelease

clean:
	$(GO) clean
	rm -rf rust/porta-server/target
	rm -rf bin/windows-amd64 bin/porta-client-windows-amd64.zip bin/wintun-0.14.1.zip
	cd android && ./gradlew clean
