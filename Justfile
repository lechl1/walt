build:
    cargo build --release -p walt --bin walt

test:
    cargo test -p walt

install: build
    cp target/release/walt /usr/local/bin/walt

uninstall:
    rm -f /usr/local/bin/walt

dev:
    cargo run -p walt --bin walt -- --help
