ifneq ($(shell pkg-config --exists libdpdk; echo $$?), 0)
$(error "Cannot find libdpdk using pkg-config")
endif

CFLAGS = -O2 -g -Wall $(shell pkg-config --cflags libdpdk)
LDFLAGS = $(shell pkg-config --libs libdpdk) -lpthread -lm

dpdk-ping: main.c Makefile
	gcc $(CFLAGS) main.c $(LDFLAGS) -o dpdk-ping

clean:
	rm -f dpdk-ping
