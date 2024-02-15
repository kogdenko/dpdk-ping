ifneq ($(shell pkg-config --exists libdpdk; echo $$?), 0)
$(error "Cannot find libdpdk using pkg-config")
endif

CFLAGS = -O0 -g -Wall $(shell pkg-config --cflags libdpdk)
CFLAGS := $(CFLAGS) -Wstrict-prototypes -Wmissing-prototypes

LDFLAGS = $(shell pkg-config --libs libdpdk) -lpthread -lm

dpdk-ping: main.c Makefile
	gcc $(CFLAGS) main.c $(LDFLAGS) -o dpdk-ping

clean:
	rm -f dpdk-ping
