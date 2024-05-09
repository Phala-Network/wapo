.PHONY: all guest clean

PROFILE=release
GUEST_PROG=../target/wasm32-wasi/$(PROFILE)/e2e-guest.wasm
WAPOD_PROG=../target/$(PROFILE)/wapod

CARGO_ARGS=

ifeq ($(PROFILE),release)
    CARGO_ARGS += --release
endif

all: guest wapod

data:
	mkdir -p data

wapod: data
	cargo build $(CARGO_ARGS) -p wapod
	cp $(WAPOD_PROG) data/

guest: data
	cargo build $(CARGO_ARGS) --target wasm32-wasi -p e2e-guest
	cp $(GUEST_PROG) data/

clean:
	rm -rf data/

test: all
	./test.sh
