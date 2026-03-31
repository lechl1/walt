build:
    cargo build --release -p rs-vault --bin rv

test:
    cargo test -p rs-vault

install: build
    cp ../../target/release/rv /usr/local/bin/rv
