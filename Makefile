# BIP38 Brute-Force Tool - Makefile

.PHONY: all build run clean deps test release native

BINARY=bwh

# Auto-detect architecture
UNAME_M := $(shell uname -m)
ifeq ($(UNAME_M),arm64)
    NATIVE_ARCH=arm64
    NATIVE_NAME=$(BINARY)-silicon
else
    NATIVE_ARCH=amd64
    NATIVE_NAME=$(BINARY)-intel
endif

all: native

deps:
	@echo "📦 Loading dependencies..."
	go mod tidy
	go mod download

native: deps
	@echo "🔨 Construct native for $(NATIVE_ARCH)..."
	CGO_ENABLED=0 GOARCH=$(NATIVE_ARCH) go build -o $(NATIVE_NAME) -ldflags="-s -w" main.go
	@echo "✅ Done: ./$(NATIVE_NAME)"

build:
	@echo "🔨 Construct $(BINARY)..."
	go build -o $(BINARY) -ldflags="-s -w" main.go
	@echo "✅ Done! Starting with: ./$(BINARY)"

run: native
	@echo "🚀 Starting Brute-Force..."
	./$(NATIVE_NAME)

clean:
	@echo "🧹 Cleaning..."
	rm -f $(BINARY) $(BINARY)-* *.dmg
	go clean

test:
	@echo "🧪 Testing compilation..."
	go build -o /dev/null main.go
	@echo "✅ Done!"

# Universal Binary
universal:
	@echo "🔥 Baue Universal Binary..."
	CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build -o $(BINARY)-intel -ldflags="-s -w" main.go
	CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build -o $(BINARY)-silicon -ldflags="-s -w" main.go
	lipo -create -output $(BINARY)-universal $(BINARY)-intel $(BINARY)-silicon
	rm $(BINARY)-intel $(BINARY)-silicon
	@echo "✅ Universal Binary: ./$(BINARY)-universal"

# Release: alle Varianten
release: universal
	@echo "📦 Creating Release..."
	zip $(BINARY)-universal.zip $(BINARY)-universal
	@echo "✅ Release created!"
