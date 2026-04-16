build:
    cargo build --release -p rs-vault --bin walt

test:
    cargo test -p rs-vault

install: build
    cp target/release/walt /usr/local/bin/walt

uninstall:
    rm -f /usr/local/bin/walt

dev:
    cargo run -p rs-vault --bin walt -- --help
