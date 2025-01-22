.PHONY: static-link
static-link:
	@cd link/bindgen; cargo build --release;
	@cp link/bindgen/target/release/libbindgen.a link/lib.a
	@rm -rf link/bindgen/target

# Run on osx
.PHONY: dynamic-link
dynamic-link-osx:
	@cd link/bindgen; cargo build --release;
	@cp link/bindgen/target/release/libbindgen.dylib link/osx.dylib
	@rm -rf link/bindgen/target

# Run on linux amd64
.PHONY: static-link-linux-amd64
static-link-linux-amd64:
	@cd link/bindgen; cargo build --release;
	@cp link/bindgen/target/release/libbindgen.a link/linux_amd64.a
	@rm -rf link/bindgen/target

# Run on linux amd64
.PHONY: dynamic-link-linux-amd64
dynamic-link-linux-amd64:
	@cd link/bindgen; cargo build --release;
	@cp link/bindgen/target/release/libbindgen.so link/linux_amd64.so
	@rm -rf link/bindgen/target

.PHONY: test
test:
	@go test -v ./...
