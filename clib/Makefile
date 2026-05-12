# Nama library Rust (hasil cargo build)
RUST_LIB_DIR = ../target/debug
RUST_LIB = $(RUST_LIB_DIR)/libage_crypto.so

CC = gcc
CFLAGS = -Wall -Wextra -I.
LDFLAGS = -L$(RUST_LIB_DIR) -lage_crypto -lpthread -ldl -lm

all: example

 $(RUST_LIB):
    cargo build

example: example.c $(RUST_LIB)
    $(CC) example.c -o example $(CFLAGS) $(LDFLAGS)

run: example
    LD_LIBRARY_PATH=$(RUST_LIB_DIR) ./example

clean:
    rm -f example