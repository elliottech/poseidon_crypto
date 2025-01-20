# Run on osx
.PHONY: build-static-link
static-link-osx:
	@cd lib/bindgen; cargo build --release;
	@cp lib/bindgen/target/release/libbindgen.a lib/osx.a
	@rm -rf lib/bindgen/target

# Run on linux
.PHONY: static-link-linux
static-link-linux:
	@cd lib/bindgen; cargo build --release;
	@cp lib/bindgen/target/release/libbindgen.a lib/linux.a
	@rm -rf lib/bindgen/target

.PHONY: test
test:
	@go test -v ./...
