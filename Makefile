# Run on osx
.PHONY: build-static-link
static-link-osx:
	@cd link/bindgen; cargo build --release;
	@cp link/bindgen/target/release/libbindgen.a link/osx.a
	@rm -rf link/bindgen/target

# Run on linux amd64
.PHONY: static-link-linux-amd64
static-link-linux-amd64:
	@cd link/bindgen; cargo build --release;
	@cp link/bindgen/target/release/libbindgen.a link/linux_amd64.a
	@rm -rf link/bindgen/target

# Run on linux arm64
.PHONY: static-link-linux-arm64
static-link-linux-arm64:
	@cd link/bindgen; cargo build --release;
	@cp link/bindgen/target/release/libbindgen.a link/linux_arm64.a
	@rm -rf link/bindgen/target

.PHONY: test
test:
	@go test -v ./...
