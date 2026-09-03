GO ?= go

.PHONY: test test-race vet build build-windows android clean

test:
	GODEBUG=http2xconnect=1 $(GO) test ./...

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
	mkdir -p bin
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 $(GO) build -trimpath -o bin/porta-client-windows-amd64.exe ./cmd/porta-client

android:
	cd android && ANDROID_HOME=$${ANDROID_HOME:-/home/azadmin/Android/Sdk} ./gradlew testDebugUnitTest assembleRelease

clean:
	$(GO) clean
	cd android && ./gradlew clean
