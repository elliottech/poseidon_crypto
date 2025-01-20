# Run on osx
.PHONY: build-static-link
static-link-osx:
	@cd lib/bindgen; cargo build --release;
	@cp lib/bindgen/target/release/libbindgen.a lib/osx.a
	@rm -rf lib/bindgen/target

# Run on linux amd64
.PHONY: static-link-linux-amd64
static-link-linux-amd64:
	@cd lib/bindgen; cargo build --release;
	@cp lib/bindgen/target/release/libbindgen.a lib/linux_amd64.a
	@rm -rf lib/bindgen/target

# Run on linux arm64
.PHONY: static-link-linux-arm64
static-link-linux-arm64:
	@cd lib/bindgen; cargo build --release;
	@cp lib/bindgen/target/release/libbindgen.a lib/linux_arm64.a
	@rm -rf lib/bindgen/target

.PHONY: test
test:
	@go test -v ./...
