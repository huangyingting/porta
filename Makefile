GO ?= go

.PHONY: check-version test test-automation test-race vet build build-windows android clean

check-version:
	./scripts/check-version.sh

test:
	GODEBUG=http2xconnect=1 $(GO) test ./...

test-automation:
	python3 scripts/test_automation.py
	$(GO) test ./scripts/package-windows.go ./scripts/package-windows_test.go

test-race:
	GODEBUG=http2xconnect=1 $(GO) test -race ./...

vet:
	$(GO) vet ./...

build:
	mkdir -p bin
	CGO_ENABLED=0 $(GO) build -trimpath -o bin/porta-server ./cmd/porta-server
	CGO_ENABLED=0 $(GO) build -trimpath -o bin/porta-client ./cmd/porta-client
	CGO_ENABLED=0 $(GO) build -trimpath -o bin/porta-keygen ./cmd/porta-keygen

build-windows:
	rm -rf bin/windows-amd64
	mkdir -p bin/windows-amd64
	curl --fail --silent --show-error --location -o bin/wintun-0.14.1.zip https://www.wintun.net/builds/wintun-0.14.1.zip
	printf '%s  %s\n' 07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51 bin/wintun-0.14.1.zip | sha256sum -c -
	unzip -p bin/wintun-0.14.1.zip wintun/bin/amd64/wintun.dll > bin/windows-amd64/wintun.dll
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 $(GO) build -trimpath -ldflags="-s -w -H=windowsgui" -o bin/windows-amd64/porta.exe ./cmd/porta-windows
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 $(GO) build -trimpath -ldflags="-s -w" -o bin/windows-amd64/porta-cli.exe ./cmd/porta-client
	$(GO) run ./scripts/package-windows.go bin/porta-client-windows-amd64.zip bin/windows-amd64

android:
	cd android && ANDROID_HOME=$${ANDROID_HOME:-/home/azadmin/Android/Sdk} ./gradlew testDebugUnitTest assembleRelease

clean:
	$(GO) clean
	rm -rf bin/windows-amd64 bin/porta-client-windows-amd64.zip bin/wintun-0.14.1.zip
	cd android && ./gradlew clean
