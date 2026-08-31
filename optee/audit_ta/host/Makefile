CC ?= aarch64-linux-gnu-gcc
CFLAGS ?= -O2 -Wall -Wextra -Werror

.PHONY: all clean

all: audit-client

audit-client: audit_client.c ../include/cote3_audit_ta.h
	@test -n "$(TEEC_EXPORT)" || (echo "set TEEC_EXPORT"; exit 2)
	$(CC) $(CFLAGS) -I../include -I$(TEEC_EXPORT)/include -o $@ audit_client.c \
		-L$(TEEC_EXPORT)/lib -lteec

clean:
	rm -f audit-client

