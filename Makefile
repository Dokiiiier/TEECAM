CC ?= cc
CFLAGS ?= -O2 -g -std=c11 -D_POSIX_C_SOURCE=200809L -Wall -Wextra -Werror
CPPFLAGS ?= -Iinclude -Isrc/gateway
BUILD_DIR ?= build/host

COMMON := src/common/protocol.c
MOCK_GATEWAY := src/gateway/gateway.c src/gateway/backend_mock.c src/gateway/backend_optee_stub.c $(COMMON)
OPTEE_GATEWAY := src/gateway/gateway.c src/gateway/backend_mock.c src/gateway/backend_optee.c $(COMMON)

.PHONY: all clean distclean test optee-gateway

all: $(BUILD_DIR)/cote3-gateway $(BUILD_DIR)/cote3-client $(BUILD_DIR)/cote3-workload

$(BUILD_DIR):
	mkdir -p $@

$(BUILD_DIR)/cote3-gateway: $(MOCK_GATEWAY) | $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ $(MOCK_GATEWAY)

$(BUILD_DIR)/cote3-client: src/client/client.c $(COMMON) | $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ src/client/client.c $(COMMON)

$(BUILD_DIR)/cote3-workload: src/client/workload.c $(COMMON) | $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ src/client/workload.c $(COMMON)

optee-gateway: | $(BUILD_DIR)
	@test -n "$(TEEC_EXPORT)" || (echo "set TEEC_EXPORT to the OP-TEE client export directory"; exit 2)
	$(CC) $(CPPFLAGS) -I$(TEEC_EXPORT)/include $(CFLAGS) -o $(BUILD_DIR)/cote3-gateway-optee \
		$(OPTEE_GATEWAY) -L$(TEEC_EXPORT)/lib -lteec

test:
	python3 -m unittest discover -s tests -v

clean:
	rm -rf $(BUILD_DIR)

distclean:
	rm -rf build
