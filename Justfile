build:
    cargo build --release -p rs-vault --bin walt

test:
    cargo test -p rs-vault

install: build
    cp target/release/walt /usr/local/bin/walt
