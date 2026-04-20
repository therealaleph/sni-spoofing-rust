BINARY_NAME = sni-spoof-rs
BIN_DIR = bins

.PHONY: all clean linux-x64 linux-arm64 macos-x64 macos-arm64 windows-x64

all: linux-x64 linux-arm64 macos-x64 macos-arm64 windows-x64

linux-x64:
	@mkdir -p $(BIN_DIR)
	cargo build --release --target x86_64-unknown-linux-gnu
	cp target/x86_64-unknown-linux-gnu/release/$(BINARY_NAME) $(BIN_DIR)/$(BINARY_NAME)-linux-x64

linux-arm64:
	@mkdir -p $(BIN_DIR)
	cargo build --release --target aarch64-unknown-linux-gnu
	cp target/aarch64-unknown-linux-gnu/release/$(BINARY_NAME) $(BIN_DIR)/$(BINARY_NAME)-linux-arm64

macos-x64:
	@mkdir -p $(BIN_DIR)
	cargo build --release --target x86_64-apple-darwin
	cp target/x86_64-apple-darwin/release/$(BINARY_NAME) $(BIN_DIR)/$(BINARY_NAME)-macos-x64

macos-arm64:
	@mkdir -p $(BIN_DIR)
	cargo build --release --target aarch64-apple-darwin
	cp target/aarch64-apple-darwin/release/$(BINARY_NAME) $(BIN_DIR)/$(BINARY_NAME)-macos-arm64

windows-x64:
	@mkdir -p $(BIN_DIR)
	cargo build --release --target x86_64-pc-windows-gnu
	cp target/x86_64-pc-windows-gnu/release/$(BINARY_NAME).exe $(BIN_DIR)/$(BINARY_NAME)-windows-x64.exe

clean:
	rm -rf $(BIN_DIR)
	cargo clean
