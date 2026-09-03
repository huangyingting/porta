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
	CGO_ENABLED=0 $(GO) build -trimpath -o bin/htun-server ./cmd/htun-server
	CGO_ENABLED=0 $(GO) build -trimpath -o bin/htun-client ./cmd/htun-client
	CGO_ENABLED=0 $(GO) build -trimpath -o bin/htun-keygen ./cmd/htun-keygen

build-windows:
	mkdir -p bin
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 $(GO) build -trimpath -o bin/htun-client-windows-amd64.exe ./cmd/htun-client

android:
	cd android && ANDROID_HOME=$${ANDROID_HOME:-/home/azadmin/Android/Sdk} ./gradlew testDebugUnitTest assembleDebug

clean:
	$(GO) clean
	cd android && ./gradlew clean
