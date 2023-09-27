# SPDX-License-Identifier: GPL-2.0-only

CFLAGS = -Wall -Wextra -O2

all: client server

client: client.c
server: server.c

clean:
	rm -vf client server

.PHONY: all clean
