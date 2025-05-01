// SPDX-License-Identifier: GPL-2.0-only

#include <arpa/inet.h>
#include <assert.h>
#include <ctype.h>
#include <getopt.h>
#include <math.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stdlib.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <rte_bus.h>
#include <rte_common.h>
#include <rte_cycles.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include <rte_pci.h>
#ifdef RTE_LIB_PDUMP
#include <rte_pdump.h>
#endif
#include <rte_version.h>

#define DPG_RX 0
#define DPG_TX 1

#define DPG_IPV6_ADDR_SIZE 16

#define DPG_DEFAULT_RPS 200*1000*1000
#define DPG_DEFAULT_SRC_IP "1.1.1.1"
#define DPG_DEFAULT_DST_IP "2.2.2.2"
#define DPG_DEFAULT_SRC_PORT "1111"
#define DPG_DEFAULT_DST_PORT "2222"
#define DPG_DEFAULT_ICMP_ID "1"
#define DPG_DEFAULT_ICMP_SEQ "1"
#define DPG_DEFAULT_PKT_LEN 60
#define DPG_DEFAULT_PDR_PERCENT 0.001
#define DPG_DEFAULT_PDR_PERIOD 30
#define DPG_DEFAULT_PDR_RPS 5
#define DPG_DEFAULT_OMIT 1

#define DPG_PAYLOAD_MAGIC dpg_hton32(0x70696e67)

#define DPG_LOG_BUF_SIZE 512

#define DPG_ETH_ADDRSTRLEN 18

#define DPG_IP_ICMP_ECHO_REPLY 0
#define DPG_IP_ICMP_ECHO_REQUEST 8

#define DPG_IPPROTO_ICMPV6 58

#define DPG_ICMPV6_NEIGH_SOLICITAION 135
#define DPG_ICMPV6_NEIGH_ADVERTISMENT 136

#define DPG_ETH_TYPE_ARP 0x0806
#define DPG_ETH_TYPE_IPV4 0x0800
#define DPG_ETH_TYPE_IPV6 0x86DD

#define DPG_IPV4_HDR_DF_FLAG (1 << 6)

#define	DPG_ARP_OP_REQUEST 1
#define	DPG_ARP_OP_REPLY 2

#define DPG_ETHER_TYPE_IPV4 0x0800
#define DPG_ARP_HRD_ETHER 1

#define DPG_MEMPOOL_CACHE_SIZE 128
#define DPG_MAX_PKT_BURST 128
#define DPG_TXBUF_SIZE DPG_MAX_PKT_BURST

#define DPG_PPSTR(x) DPG_PPXSTR(x)
#define DPG_PPXSTR(x) #x

#define DPG_PACKED  __attribute__((packed)) __attribute__((aligned(2)))

#pragma message "DPDK: "\
		DPG_PPSTR(RTE_VER_YEAR)"." \
		DPG_PPSTR(RTE_VER_MONTH)"." \
		DPG_PPSTR(RTE_VER_MINOR)"." \
		DPG_PPSTR(RTE_VER_RELEASE)

#if RTE_VERSION < RTE_VERSION_NUM(18, 5, 0, 16)
#error "Too old DPDK version (not tested)"
#endif

#if RTE_VERSION <= RTE_VERSION_NUM(21, 8, 0, 99) 
#define DPG_ETH_MQ_TX_NONE ETH_MQ_TX_NONE
#define DPG_ETH_TX_OFFLOAD_MBUF_FAST_FREE DEV_TX_OFFLOAD_MBUF_FAST_FREE
#define DPG_ETH_MQ_RX_RSS ETH_MQ_RX_RSS
#define DPG_ETH_RSS_IP ETH_RSS_IP
#define DPG_ETH_RSS_TCP ETH_RSS_TCP
#define DPG_ETH_RSS_UDP ETH_RSS_UDP
#else
// 21.11.0.99
#define DPG_ETH_MQ_TX_NONE RTE_ETH_MQ_TX_NONE
#define DPG_ETH_TX_OFFLOAD_MBUF_FAST_FREE RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE
#define DPG_ETH_MQ_RX_RSS RTE_ETH_MQ_RX_RSS
#define DPG_ETH_RSS_IP RTE_ETH_RSS_IP
#define DPG_ETH_RSS_TCP RTE_ETH_RSS_TCP
#define DPG_ETH_RSS_UDP RTE_ETH_RSS_UDP
#endif

#if RTE_VERSION <= RTE_VERSION_NUM(19, 5, 0, 99)
typedef struct ether_addr dpg_eth_addr_t;
#define dpg_eth_format_addr ether_format_addr
#else
// 19, 8, 0, 99
typedef struct rte_ether_addr dpg_eth_addr_t;
#define dpg_eth_format_addr rte_ether_format_addr
#endif

#if RTE_VERSION <= RTE_VERSION_NUM(22, 7, 0, 99)
#define dpg_dev_name(dev) ((dev)->name)
#else
// 22.11.0.99
#define dpg_dev_name(dev) rte_dev_name(dev)
#endif

#define dpg_ntoh16 rte_be_to_cpu_16
#define dpg_hton16 rte_cpu_to_be_16
#define dpg_ntoh32 rte_be_to_cpu_32
#define dpg_hton32 rte_cpu_to_be_32
#define dpg_ntoh64 rte_cpu_to_be_64
#define dpg_hton64 rte_be_to_cpu_64

#define DPG_TCP_FIN 0x01
#define DPG_TCP_SYN 0x02
#define DPG_TCP_RST 0x04
#define DPG_TCP_PSH 0x08
#define DPG_TCP_ACK 0x10
#define DPG_TCP_URG 0x20

#define DPG_X_OSELECTOR(X) \
	X(ipackets) \
	X(opackets) \
	X(ibytes) \
	X(obytes) \
	X(imissed) \
	X(ierrors) \
	X(oerrors) \
	X(rx_nombuf) \
	X(ipps) \
	X(ibps) \
	X(opps) \
	X(obps) \
	X(requests) \
	X(replies)

#define DPG_FOREACH_PORT(port, port_id) \
	RTE_ETH_FOREACH_DEV(port_id) \
		if ((port = g_dpg_ports[port_id]) != NULL && dpg_port_is_configured(port))

typedef unsigned __int128 dpg_uint128_t;

struct dpg_dlist {
	struct dpg_dlist *dls_next;
	struct dpg_dlist *dls_prev;
};

struct dpg_counter {
	uint64_t per_lcore[RTE_MAX_LCORE];
};

struct dpg_strbuf {
	int cap;
	int len;
	char *buf;
};

struct dpg_darray {
	size_t size;
	size_t cap;
	size_t item_size;
	uint8_t *data;
};

struct dpg_container {
	struct dpg_dlist list;

	dpg_uint128_t size;

	struct dpg_darray array;

	dpg_uint128_t begin;
	dpg_uint128_t end;

	dpg_uint128_t (*get)(struct dpg_container *, dpg_uint128_t);
	bool (*find)(struct dpg_container *, dpg_uint128_t);
};

struct dpg_iterator {
	struct dpg_dlist list;

	dpg_uint128_t current;
	dpg_uint128_t pos;
	dpg_uint128_t step;

	struct dpg_container *container;
};

struct dpg_eth_hdr {
	dpg_eth_addr_t dst_addr;
	dpg_eth_addr_t src_addr;
	rte_be16_t eth_type;
} DPG_PACKED;

struct dpg_arp_hdr {
	rte_be16_t arp_hardware;
	rte_be16_t arp_protocol;
	uint8_t arp_hlen;
	uint8_t arp_plen;
	rte_be16_t arp_opcode;
	dpg_eth_addr_t arp_sha;
	rte_be32_t arp_sip;
	dpg_eth_addr_t arp_tha;
	rte_be32_t arp_tip;
} DPG_PACKED;

struct dpg_ipv4_hdr {
        union {
		uint8_t version_ihl;
		struct {
#if RTE_BYTE_ORDER == RTE_LITTLE_ENDIAN
			uint8_t ihl:4;
			uint8_t version:4;
#elif RTE_BYTE_ORDER == RTE_BIG_ENDIAN
			uint8_t version:4;
			uint8_t ihl:4;
#endif
		};
	};
	uint8_t  type_of_service;
	rte_be16_t total_length;
	rte_be16_t packet_id;
	rte_be16_t fragment_offset;
	uint8_t time_to_live;
	uint8_t next_proto_id;
	rte_be16_t hdr_checksum;
	rte_be32_t src_addr;
	rte_be32_t dst_addr;
} DPG_PACKED;

struct dpg_icmp_hdr {
	uint8_t icmp_type;
	uint8_t icmp_code;
	rte_be16_t icmp_cksum;
	rte_be16_t icmp_ident;
	rte_be16_t icmp_seq_nb;
} DPG_PACKED;

struct dpg_udp_hdr {
	rte_be16_t src_port;
	rte_be16_t dst_port;
	rte_be16_t dgram_len;
	rte_be16_t dgram_cksum;
} DPG_PACKED;

struct dpg_tcp_hdr {
	rte_be16_t src_port;
	rte_be16_t dst_port;
	rte_be32_t sent_seq;
	rte_be32_t recv_ack;
	uint8_t data_off;
	uint8_t tcp_flags;
	rte_be16_t rx_win;
	rte_be16_t cksum;
	rte_be16_t tcp_urp;
} DPG_PACKED;

struct dpg_ipv4_pseudo_hdr {
	rte_be32_t src;
	rte_be32_t dst;
	uint8_t pad;
	uint8_t proto;
	rte_be16_t len;
} DPG_PACKED;

struct dpg_ipv6_hdr {
	rte_be32_t vtc_flow;
	rte_be16_t payload_len;
	uint8_t proto;
	uint8_t hop_limits;
	uint8_t src_addr[DPG_IPV6_ADDR_SIZE];
	uint8_t dst_addr[DPG_IPV6_ADDR_SIZE];
} DPG_PACKED;

struct dpg_icmpv6_hdr {
	uint8_t type;
	uint8_t code;
	uint16_t checksum;
} DPG_PACKED;

struct dpg_ipv6_pseudo_hdr {
	uint8_t src_addr[DPG_IPV6_ADDR_SIZE];
	uint8_t dst_addr[DPG_IPV6_ADDR_SIZE];
	rte_be32_t len;
	rte_be32_t proto;
} DPG_PACKED;

struct dpg_icmpv6_neigh_solicitaion {
	uint8_t type;
	uint8_t code;
	uint16_t checksum;
	uint32_t reserved;
	uint8_t target[DPG_IPV6_ADDR_SIZE];
} DPG_PACKED;

struct dpg_icmpv6_neigh_advertisment {
	uint8_t type;
	uint8_t code;
	uint16_t checksum;
	uint32_t flags;
	uint8_t target[DPG_IPV6_ADDR_SIZE];
} DPG_PACKED;

struct dpg_target_link_layer_address_option {
	uint8_t type;
	uint8_t length;
	dpg_eth_addr_t address;
} DPG_PACKED;

struct dpg_srv6_hdr {
	uint8_t next_header;
	uint8_t hdr_ext_len;
	uint8_t routing_type;
	uint8_t segments_left;
	uint8_t last_entry;
	uint8_t flags;
	rte_be16_t tag;
	uint8_t localsid[DPG_IPV6_ADDR_SIZE];
} DPG_PACKED;

struct dpg_payload {
	rte_be32_t payload_magic;
	rte_be32_t payload_pad;
	rte_be64_t payload_seq;
} DPG_PACKED;

enum dpg_session_field {
	DPG_SESSION_SRC_IP = 0,
	DPG_SESSION_DST_IP,
	DPG_SESSION_SRC_PORT,
	DPG_SESSION_DST_PORT,
	DPG_SESSION_ICMP_ID,
	DPG_SESSION_ICMP_SEQ,
	DPG_SESSION_SRV6_DST,
	DPG_SESSION_FIELD_MAX,
};

struct dpg_tx_queue {
	int bytes;
	int n_pkts;
	struct rte_mbuf *pkts[DPG_MAX_PKT_BURST];
};

struct dpg_task {
	struct dpg_dlist llist;
	struct dpg_dlist plist;

	uint16_t port_id;
	uint16_t queue_id;
	uint16_t lcore_id;

	volatile int rps;
	uint64_t req_tx_time;

	uint32_t rand_state;
	uint32_t rand_seed;
	uint32_t rand_session_count;
	uint32_t rand_session_index;

	uint64_t arp_request_time;

	struct dpg_iterator session_field[DPG_SESSION_FIELD_MAX];

	struct dpg_dlist session_field_head;

	struct dpg_tx_queue req_queue;
	struct dpg_tx_queue rpl_queue;
};

struct dpg_port {
	dpg_eth_addr_t src_eth_addr;
	dpg_eth_addr_t dst_eth_addr;
	rte_be32_t gateway;

	bool Rflag;
	bool Eflag;

	volatile uint8_t arp_resolved;

	uint16_t pkt_len;
	uint8_t proto;

	struct dpg_container addresses4;
	struct dpg_container addresses6;

	struct dpg_container session_field[DPG_SESSION_FIELD_MAX];

	int srv6;
	uint8_t srv6_src[DPG_IPV6_ADDR_SIZE];

	int pt_id;
	int pt_fwd_id;

	int rps_max;

	bool rand;
	uint32_t rand_seed;
	uint32_t rand_session_count;

	bool software_counters;
	struct dpg_counter ipackets;
	struct dpg_counter opackets;
	struct dpg_counter ibytes;
	struct dpg_counter obytes;

	uint64_t send_seq;
	uint64_t recv_seq;
	uint64_t pt_drops;
	uint64_t pt_drops_prev;
	uint64_t pt_requests;
	uint64_t pt_requests_prev;
	uint64_t pt_replies;
	uint64_t pt_replies_prev;

	struct dpg_dlist task_head;

	struct dpg_dlist session_field_head;

	uint8_t pdr;
	int8_t pdr_dir;
	double pdr_percent;
	int64_t rps;
	int64_t pdr_step;
	u_int pdr_elapsed;
	u_int pdr_period;

	uint16_t n_rxd;
	uint16_t n_txd;
	int n_queues;

	uint64_t pt_ipackets_prev;
	uint64_t pt_opackets_prev;
	uint64_t pt_ibytes_prev;
	uint64_t pt_obytes_prev;

	uint64_t pt_ipackets_hot;
	uint64_t pt_opackets_hot;
	uint64_t pt_ibytes_hot;
	uint64_t pt_obytes_hot;

	uint64_t pt_ipps;
	uint64_t pt_ibps;
	uint64_t pt_opps;
	uint64_t pt_obps; 

	struct rte_eth_conf pt_conf;
};

struct dpg_lcore {
	struct dpg_dlist task_head;
	uint64_t tsc;
	int is_first;
};

enum dpg_oselector {
#define DPG_OSELECTOR_ENUM(name) DPG_OSELECTOR_##name,
	DPG_X_OSELECTOR(DPG_OSELECTOR_ENUM)
#undef DPG_OSELECTOR_ENUM
	DPG_OSELECTOR_COUNT
};

static volatile int g_dpg_done;
static uint64_t g_dpg_hz;
static struct dpg_port *g_dpg_ports[RTE_MAX_ETHPORTS];
static struct dpg_lcore g_dpg_lcores[RTE_MAX_LCORE];
static struct rte_mempool *g_dpg_pktmbuf_pool;
static int g_dpg_verbose[2];
static int g_dpg_bflag;
static int g_dpg_elapsed = 0;
static int g_dpg_duration = INT_MAX;
static int g_dpg_omit = DPG_DEFAULT_OMIT;
static bool g_dpg_human_readable = true;
static uint32_t g_dpg_oselectors[DPG_OSELECTOR_COUNT] = {
#define DPG_OSELECTOR_VALUE(name) DPG_OSELECTOR_##name,
	DPG_X_OSELECTOR(DPG_OSELECTOR_VALUE)
#undef DPG_OSELECTOR_VALUE
};

static int g_dpg_oselector_count = DPG_OSELECTOR_COUNT;
static const char *g_dpg_oselector_strings[DPG_OSELECTOR_COUNT] = {
#define DPG_OSELECTOR_STRING(name) #name,
	DPG_X_OSELECTOR(DPG_OSELECTOR_STRING)
#undef DPG_OSELECTOR_STRING
};

#define DPG_SWAP(a, b) do { \
	typeof(a) t; \
	memcpy(&(t), &(a), sizeof(t)); \
	memcpy(&(a), &(b), sizeof(a)); \
	memcpy(&(b), &(t), sizeof(b)); \
} while (0)

#define DPG_MIN(a, b) ((a) < (b) ? (a) : (b))
#define DPG_MAX(a, b) ((a) > (b) ? (a) : (b))

#define DPG_ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))

#define dpg_field_off(type, field) ((intptr_t)&((type *)0)->field)

#define dpg_container_of(ptr, type, field) \
	((type *)((intptr_t)(ptr) - dpg_field_off(type, field)))

#define dpg_die(...) \
	rte_exit(EXIT_FAILURE, ##__VA_ARGS__);

#define DPG_READ_ONCE(x) \
({ \
	union { \
		typeof(x) val; \
		u_char data[1]; \
	} u; \
	dpg_read_once(&(x), u.data, sizeof(x)); \
	u.val; \
})

#define DPG_WRITE_ONCE(x, v) \
({ \
	union { \
		typeof(x) val; \
		u_char data[1]; \
	} u = { \
		.val = (typeof(x))(v) \
	}; \
	dpg_write_once(&(x), u.data, sizeof(x)); \
	u.val; \
})

#define dpg_dbg(f, ...) do { \
	printf("%u: ", __LINE__); \
	printf(f, ##__VA_ARGS__); \
	printf("\n"); \
	fflush(stdout); \
} while (0)

static dpg_uint128_t dpg_container_get(struct dpg_container *ct, dpg_uint128_t i);

static void dpg_print_hexdump_ascii(const void *data, int count)
	__attribute__((unused));

static void
dpg_print_hexdump_ascii(const void *data, int count)
{
	int i, j, k, savei;
	u_char ch;

	for (i = 0; i < count;) {
		savei = i;
		for (j = 0; j < 8; ++j) {
			for (k = 0; k < 2; ++k) {
				if (i < count) {
					ch = ((const u_char *)data)[i];
					printf("%02hhx", ch);
					i++;
				} else {
					printf("  ");
				}
			}
			printf(" ");
		}
		printf(" ");
		for (j = savei; j < i; ++j) {
			ch = ((const u_char *)data)[j];
			printf("%c", isprint(ch) ? ch : '.');
		}
		printf("\n");
	}
	fflush(stdout);
}

static int64_t
dpg_parse_human_readable(const char *s)
{
	double val;
	char *endptr, *unit;
	static const char *units = "kmgt";

	val = strtod(s, &endptr);
	if (*endptr == '\0') {
		return val;
	} else {
		unit = strchr(units, *endptr);
		if (unit == NULL) {
			return -EINVAL;
		}
		return val * pow(1000, (unit - units + 1));
	}
}

static int
dpg_print_human_readable5(char *buf, size_t count, double val, char *fmt)
{
	static const char *units[] = { "", "k", "m", "g", "t" };
	int i;

	if (g_dpg_human_readable) {
		for (i = 0; val >=1000 && i < DPG_ARRAY_SIZE(units) - 1; i++) {
			val /= 1000;
		}
	} else {
		i = 0;
	}

	return snprintf(buf, count, fmt, val, units[i]);
}

static int
dpg_print_human_readable(char *buf, size_t count, double val)
{
	if (g_dpg_human_readable) {
		return dpg_print_human_readable5(buf, count, val, "%.3f%s");
	} else {
		return dpg_print_human_readable5(buf, count, val, "%.0f%s");
	}
}

static void *
dpg_xmalloc(size_t size)
{
	void *ptr;

	ptr = malloc(size);
	if (ptr == NULL) {
		dpg_die("malloc(%zu) failed\n", size);
	}
	return ptr;
}

static void *
dpg_xrealloc(void *ptr, size_t size)
{
	void *cp;

	cp = realloc(ptr, size);
	if (cp == NULL) {
		dpg_die("realloc(%zu) failed\n", size);
	}
	return cp;
}

static struct rte_mbuf *
dpg_pktmbuf_alloc(void)
{
	struct rte_mbuf *m;

	m = rte_pktmbuf_alloc(g_dpg_pktmbuf_pool);
	if (m == NULL) {
		dpg_die("rte_pktmbuf_alloc() failed\n");
	}
	return m;
}

static const char *
dpg_get_port_name(uint16_t port_id)
{
	static char port_name[RTE_MAX_ETHPORTS][RTE_ETH_NAME_MAX_LEN];

	if (port_name[port_id][0] == '\0') {
		rte_eth_dev_get_name_by_port(port_id, port_name[port_id]);
	}
	return port_name[port_id];
}

static bool
dpg_is_zero(const void *ptr, size_t n)
{
	uint8_t rc;
	size_t i;

	for (i = 0; i < n; ++i) {
		rc = ((const uint8_t *)ptr)[i];
		if (rc) {
			return false;
		}
	}

	return true;
}

/*static uint32_t
dpg_upper_pow2_32(uint32_t x)
{
	x--;
	x |= x >>  1lu;
	x |= x >>  2lu;
	x |= x >>  4lu;
	x |= x >>  8lu;
	x |= x >> 16lu;
	x++;

	return x;
}*/

static uint32_t
dpg_rand_xorshift(uint32_t *state)
{
	uint32_t x;

	x = *state;

	x ^= x << 13;
	x ^= x >> 17;
	x ^= x << 5;

	*state = x;

	return x;
}

static void
dpg_read_once(const volatile void *p, void *data, int size)
{
	switch (size) {
	case 1: *(uint8_t *)data = *(volatile uint8_t *)p; break;
	case 2: *(uint16_t *)data = *(volatile uint16_t *)p; break;
	case 4: *(uint32_t *)data = *(volatile uint32_t *)p; break;
	case 8: *(uint64_t *)data = *(volatile uint64_t *)p; break;
	}
}

static void
dpg_write_once(volatile void *p, void *data, int size)
{
	switch (size) {
	case 1: *(volatile uint8_t *)p = *(uint8_t *)data; break;
	case 2: *(volatile uint16_t *)p = *(uint16_t *)data; break;
	case 4: *(volatile uint32_t *)p = *(uint32_t *)data; break;
	case 8: *(volatile uint64_t *)p = *(uint64_t *)data; break;
	}
}

static void
dpg_dlist_init(struct  dpg_dlist *head)
{
	head->dls_next = head->dls_prev = head;
}

static int
dpg_dlist_is_empty(struct dpg_dlist *head)
{
	return head->dls_next == head;
}

#define DPG_DLIST_FIRST(head, type, field) \
	dpg_container_of((head)->dls_next, type, field)

#define DPG_DLIST_NEXT(var, field) \
	dpg_container_of((var)->field.dls_next, __typeof__(*(var)), field)

#define DPG_DLIST_FOREACH(var, head, field) \
	for (var = DPG_DLIST_FIRST(head, typeof(*(var)), field); \
	     &((var)->field) != (head); \
	     var = DPG_DLIST_NEXT(var, field))

static void
dpg_dlist_insert_head(struct dpg_dlist *head, struct dpg_dlist *l)
{
	l->dls_next = head->dls_next;
	l->dls_prev = head;
	head->dls_next->dls_prev = l;
	head->dls_next = l;
}

#define DPG_DLIST_INSERT_HEAD(head, var, field) \
	dpg_dlist_insert_head(head, &((var)->field))

static void
dpg_dlist_insert_tail(struct dpg_dlist *head, struct dpg_dlist *l)
{
	l->dls_next = head;
	l->dls_prev = head->dls_prev;
	head->dls_prev->dls_next = l;
	head->dls_prev = l;
}

#define DPG_DLIST_INSERT_TAIL(head, var, field) \
	dpg_dlist_insert_tail(head, &((var)->field))

static void
dpg_dlist_remove(struct dpg_dlist *list)
{
	list->dls_next->dls_prev = list->dls_prev;
	list->dls_prev->dls_next = list->dls_next;
}

#define DPG_DLIST_REMOVE(var, field) \
	dpg_dlist_remove(&(var)->field)

static void
dpg_counter_add(struct dpg_counter *c, uint64_t add)
{
	c->per_lcore[rte_lcore_id()] += add;
}

static uint64_t
dpg_counter_get(struct dpg_counter *c)
{
	int i;
	uint64_t sum;

	sum = 0;
	for (i = 0; i < DPG_ARRAY_SIZE(c->per_lcore); ++i) {
		sum += c->per_lcore[i];
	}

	return sum;
}

static void
dpg_strbuf_init(struct dpg_strbuf *sb, char *buf, int size)
{
	sb->len = 0;
	sb->cap = size;
	sb->buf = buf;
}

static int
dpg_strbuf_space(struct dpg_strbuf *sb)
{
	return sb->cap > sb->len ? sb->cap - sb->len - 1 : 0;
}

static char *
dpg_strbuf_cstr(struct dpg_strbuf *sb)
{
	if (sb->cap == 0) {
		return "";
	} else {
		sb->buf[DPG_MIN(sb->len, sb->cap - 1)] = '\0';
		return sb->buf;
	}
}

static void
dpg_strbuf_print(struct dpg_strbuf *sb)
{
	fprintf(stdout, "%s\n", dpg_strbuf_cstr(sb));
	fflush(stdout);
}

static void
dpg_strbuf_add(struct dpg_strbuf *sb, const void *buf, int size)
{
	int n;

	if (sb->cap > sb->len) {
		n = DPG_MIN(size, sb->cap - sb->len);
		memcpy(sb->buf + sb->len, buf, n);
	}
	sb->len += size;
}

static void
dpg_strbuf_addch(struct dpg_strbuf *sb, char c)
{
	dpg_strbuf_add(sb, &c, 1);
}

static void
dpg_strbuf_adds(struct dpg_strbuf *sb, const char *str)
{
	dpg_strbuf_add(sb, str, strlen(str));
}

static void
dpg_strbuf_vaddf(struct dpg_strbuf *sb, const char *fmt, va_list ap)
{
	int rc, cnt;

	cnt = dpg_strbuf_space(sb);
	rc = vsnprintf(sb->buf + sb->len, cnt, fmt, ap);
	sb->len += rc;
}

static void
dpg_strbuf_addf(struct dpg_strbuf *sb, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	dpg_strbuf_vaddf(sb, fmt, ap);
	va_end(ap);
}

static void
dpg_strbuf_add_tcp_flags(struct dpg_strbuf *sb, uint8_t tcp_flags)
{
	if (tcp_flags & DPG_TCP_FIN) {
		dpg_strbuf_addch(sb, 'F');
	}
	if (tcp_flags & DPG_TCP_SYN) {
		dpg_strbuf_addch(sb, 'S');
	}
	if (tcp_flags & DPG_TCP_RST) {
		dpg_strbuf_addch(sb, 'R');
	}
	if (tcp_flags & DPG_TCP_PSH) {
		dpg_strbuf_addch(sb, 'P');
	}
	if (tcp_flags & DPG_TCP_ACK) {
		dpg_strbuf_addch(sb, '.');
	}
	if (tcp_flags & DPG_TCP_URG) {
		dpg_strbuf_addch(sb, 'U');
	}
}

static void
dpg_strbuf_add_human_readable(struct dpg_strbuf *sb, double val)
{
	int rc, cnt;

	cnt = dpg_strbuf_space(sb);
	rc = dpg_print_human_readable(sb->buf + sb->len, cnt, val);
	sb->len += rc;
}

static void
dpg_strbuf_add_output(struct dpg_strbuf *sb, uint64_t v)
{
	dpg_strbuf_addf(sb, "%"PRIu64, v);
}

static void
dpg_darray_init(struct dpg_darray *da, int item_size)
{
	da->data = NULL;
	da->size = da->cap = 0;
	da->item_size = item_size;
}

static void
dpg_darray_deinit(struct dpg_darray *da)
{
	free(da->data);
	da->size = da->cap = 0;
}

/*
static void
dpg_darray_copy(struct dpg_darray *dst, struct dpg_darray *src)
{
	dst->size = src->size;
	dst->cap = src->cap;
	dst->item_size = src->item_size;

	free(dst->data);
	
	dst->data = dpg_xmemdup(src->data, dst->cap * dst->item_size);
}
*/

static void
dpg_darray_resize(struct dpg_darray *da, int size)
{
	if (size > da->cap) {
		da->cap = DPG_MAX(size + 1, 3 * da->cap / 2);
		da->data = dpg_xrealloc(da->data, da->cap * da->item_size);	
	}
	da->size = size;
}

static void *
dpg_darray_add(struct dpg_darray *da)
{
	dpg_darray_resize(da, da->size + 1);

	return da->data + (da->size - 1) * da->item_size;
}

/*static void *
dpg_darray_add2(struct dpg_darray *da, void *item)
{
	void *new;

	new = dpg_darray_add(da);
	memcpy(new, item, da->item_size);

	return new;
}*/

static void *
dpg_darray_get(struct dpg_darray *da, size_t i)
{
	assert(i < da->size);
	return da->data + i * da->item_size;
}

static int
dpg_darray_find(struct dpg_darray *da, void *item)
{
	int i;
	uint8_t *iter;

	iter = da->data;
	for (i = 0; i < da->size; ++i) {
		if (!memcmp(iter, item, da->item_size)) {
			return i;
		}
		iter += da->item_size;
	}

	return -ESRCH;
}

static dpg_uint128_t
dpg_container_array_get(struct dpg_container *ct, dpg_uint128_t i)
{
	dpg_uint128_t *val;

	val = dpg_darray_get(&ct->array, i);
	return *val;
}

static bool
dpg_container_array_find(struct dpg_container *ct, dpg_uint128_t val)
{
	int rc;

	rc = dpg_darray_find(&ct->array, &val);

	return rc >= 0;
}

static dpg_uint128_t
dpg_container_interval_get(struct dpg_container *ct, dpg_uint128_t i)
{
	assert(i < ct->size);
	return ct->begin + i;
}

static bool
dpg_container_interval_find(struct dpg_container *ct, dpg_uint128_t val)
{
	return val >= ct->begin && val <= ct->end;
}

static dpg_uint128_t
dpg_container_get(struct dpg_container *ct, dpg_uint128_t i)
{
	assert(ct->size);
	assert(ct->get != NULL);
	return (*ct->get)(ct, i);
}

static bool
dpg_container_find(struct dpg_container *ct, dpg_uint128_t val)
{
	if (ct->find == NULL) {
		return -ESRCH;
	} else {
		return (*ct->find)(ct, val);
	}
}

static void
dpg_container_deinit(struct dpg_container *ct)
{
	dpg_darray_deinit(&ct->array);
	ct->size = 0;
}

static int
dpg_container_parse(char *str, struct dpg_container *ct, int (*parse)(char *, dpg_uint128_t *))
{
	int rc;
	dpg_uint128_t *val;
	char *s, *d;

	dpg_container_deinit(ct);

	d = strchr(str, '-');
	if (d == NULL) {
		dpg_darray_init(&ct->array, sizeof(dpg_uint128_t));

		ct->get = dpg_container_array_get;
		ct->find = dpg_container_array_find;

		for (s = strtok(str, ","); s != NULL; s = strtok(NULL, ",")) {
			val = dpg_darray_add(&ct->array);
			rc = (*parse)(s, val);
			if (rc < 0) {
				goto err;
			}
		}

		ct->size = ct->array.size;
	} else {
		*d = '\0';

		ct->get = dpg_container_interval_get;
		ct->find = dpg_container_interval_find;

		rc = (*parse)(str, &ct->begin);
		if (rc < 0) {
			goto err;
		}
		rc = (*parse)(d + 1, &ct->end);
		if (rc < 0) {
			goto err;
		}
		*d = '-';
	
		if (ct->begin > ct->end) {
			rc = -EINVAL;
			goto err;
		}

		ct->size = ct->end - ct->begin + 1;
	}

	return 0;

err:
	dpg_container_deinit(ct);
	return rc;
}

static dpg_uint128_t
dpg_iterator_get(struct dpg_iterator *it)
{
	return dpg_container_get(it->container, it->current);
}

static void
dpg_iterator_init(struct dpg_iterator *it, struct dpg_container *ct,
		dpg_uint128_t step, dpg_uint128_t pos)
{
	assert(ct->size != 0);

	it->container = ct;
	it->step = step;
	it->pos = pos < ct->size ? pos : pos % ct->size;
	it->current = it->pos;
//	it->upper_size = dpg_upper_pow2_32(ct->size);
//	it->upper_mask = it->upper_size - 1;
}

static bool
dpg_iterator_next(struct dpg_iterator *it)
{
	dpg_uint128_t size;
	bool overflow;

	size = it->container->size;
	assert(size);

	overflow = false;

	it->current += it->step;
	if (it->current >= size) {
		it->current = it->pos;
		overflow = true;
	}

	return overflow;
}

static void
dpg_iterator_set_rand(struct dpg_iterator *it, uint32_t r)
{
	/*uint32_t offset;

	offset = r & it->upper_mask;
	if (offset >= it->container->size) {
		offset -= it->container->size;
	}
	assert(offset < it->container->size);
	it->current = offset;*/

	it->current = r % it->container->size;
}

static const char *
dpg_bool_str(int b)
{
	return b ? "true" : "false";
}

static int
dpg_parse_bool(char *str)
{
	int b;
	char *endptr;

	b = strtoul(str, &endptr, 10);
	if (*endptr == '\0') {
		if (b != 0 && b != 1) {
			return -EINVAL;
		} else {
			return b;
		}
	}
	if (!strcasecmp(str, "on") ||
	    !strcasecmp(str, "yes") ||
	    !strcasecmp(str, "true")) {
		return 1;
	} else if (!strcasecmp(str, "off") ||
	           !strcasecmp(str, "no") ||
	           !strcasecmp(str, "false")) {
		return 0;
	} else {
		return -EINVAL;
	}
}

static int
dpg_parse_u16(char *str, dpg_uint128_t *res)
{
	u_long ul;
	char *endptr;

	ul = strtoul(str, &endptr, 10);
	if (*endptr != '\0' || ul > UINT16_MAX) {
		return -EINVAL;
	} else {
		*res = ul;
		return 0;
	}
}

static int
dpg_parse_ipv4(char *str, dpg_uint128_t *res)
{
	int rc;
	struct in_addr tmp;

	rc = inet_pton(AF_INET, str, &tmp);
	if (rc == 1) {
		*res = rte_be_to_cpu_32(tmp.s_addr);
		return 0;
	} else {
		return -EINVAL;
	}
}

static int
dpg_find_oselector(const char *s)
{
	int i;

	for (i = 0; i < DPG_OSELECTOR_COUNT; ++i) {
		if (!strcmp(s, g_dpg_oselector_strings[i])) {
			return i;
		}
	}
	return -EINVAL;
}

static int
dpg_parse_oselectors(char *s)
{
	int rc;
	char *one;

	g_dpg_oselector_count = 0;
	for (one = strtok(s, ","); one != NULL; one = strtok(NULL, ",")) {
		rc = dpg_find_oselector(one);
		if (rc < 0) {
			return rc;
		}
		g_dpg_oselectors[g_dpg_oselector_count++] = rc;
		if (g_dpg_oselector_count == DPG_OSELECTOR_COUNT) {
			break;
		}
	}
	return 0;
}

#if RTE_BYTE_ORDER == RTE_BIG_ENDIAN
#define dpg_hton128(x) (x)
#define dpg_ntoh128(x) (x)
#else
static dpg_uint128_t
dpg_swap128(dpg_uint128_t src)
{
	int i;
	dpg_uint128_t dst;

	for (i = 0; i < sizeof(dst); ++i) {
		((uint8_t *)&dst)[i] = ((uint8_t *)&src)[sizeof(dst) - 1 - i];
	}

	return dst;
}
#define dpg_hton128(x) dpg_swap128(x)
#define dpg_ntoh128(x) dpg_swap128(x)
#endif

static int
dpg_ipv6_parse(char *str, dpg_uint128_t *res)
{
	int rc;
	dpg_uint128_t addr;

	rc = inet_pton(AF_INET6, str, &addr);
	if (rc == 1) {
		*res = dpg_ntoh128(addr);
		return 0;
	} else {
		return -EINVAL;
	}
}

static void
dpg_uint128_to_ipv6(uint8_t *ipv6, dpg_uint128_t u)
{
	u = dpg_hton128(u);
	memcpy(ipv6, &u, DPG_IPV6_ADDR_SIZE);
}

static dpg_uint128_t
dpg_ipv6_to_uint128(uint8_t  *ipv6)
{
	dpg_uint128_t u;

	memcpy(&u, ipv6, DPG_IPV6_ADDR_SIZE);
	u = dpg_ntoh128(u);
	return u;
}

static int
dpg_eth_unformat_addr(const char *str, dpg_eth_addr_t *a)
{
	int rc;

	rc = sscanf(str, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
			a->addr_bytes + 0, a->addr_bytes + 1, a->addr_bytes + 2,
			a->addr_bytes + 3, a->addr_bytes + 4, a->addr_bytes + 5);

	return rc == 6 ? 0 : -EINVAL;
}

static int
dpg_eth_macaddr_get(uint16_t port_id, dpg_eth_addr_t *mac_addr)
{
	int rc;

#if RTE_VERSION <= RTE_VERSION_NUM(19, 8, 0, 99)
	rte_eth_macaddr_get(port_id, mac_addr);
	rc = 0;
#else
	// 19.11.0.99
	rc = rte_eth_macaddr_get(port_id, mac_addr);
#endif
	return rc;
}

static void
dpg_eth_dev_info_get(uint16_t port_id, struct rte_eth_dev_info *dev_info)
{
#if RTE_VERSION <= RTE_VERSION_NUM(19, 8, 0, 99)
	rte_eth_dev_info_get(port_id, dev_info);
#else
	// 19.11.0.99
	int rc;

	rc = rte_eth_dev_info_get(port_id, dev_info);
	if (rc < 0) {
		dpg_die("rte_eth_dev_info_get('%s') failed (%d:%s)\n",
				dpg_get_port_name(port_id), -rc, rte_strerror(-rc));
	}
#endif
}

static void
dpg_invalid_argument(int short_name, const char *long_name)
{
	if (long_name != NULL) {
		dpg_die("Invalid argument: '--%s'\n", long_name);
	} else {
		dpg_die("Invalid argument: '-%c'\n", short_name);
	}
}

static int
dpg_argument_already_specified(int short_name, const char *long_name)
{
	if (long_name != NULL) {
		dpg_die("Argument '--%s' already specified\n", long_name);
	} else {
		dpg_die("Argument '-%c' already specified\n", short_name);
	}
}

static void
dpg_argument_not_specified(int short_name, const char *long_name)
{
	if (long_name != NULL) {
		dpg_die("Argument '--%s' not specified\n", long_name);
	} else {
		dpg_die("Argument '-%c' not specified\n", short_name);
	}
}

static void
dpg_noone_argument_specified(const char *arg_list)
{
	dpg_die("One of the arguments (%s) should be specified", arg_list);
}

static inline uint64_t
dpg_cksum_add(uint64_t sum, uint64_t x)
{
	sum += x;
	if (sum < x) {
		++sum;
	}
	return sum;
}

static uint16_t
dpg_cksum_reduce(uint64_t sum)
{
	uint64_t mask;
	uint16_t reduced;

	mask = 0xffffffff00000000lu;
	while (sum & mask) {
		sum = dpg_cksum_add(sum & ~mask, (sum >> 32) & ~mask);
	}
	mask = 0xffffffffffff0000lu;
	while (sum & mask) {
		sum = dpg_cksum_add(sum & ~mask, (sum >> 16) & ~mask);
	}
	reduced = ~((uint16_t)sum);
	if (reduced == 0) {
		reduced = 0xffff;
	}
	return reduced;
}

static uint64_t
dpg_cksum_raw(const void *data, int size)
{
	uint64_t sum;
	const uint8_t *b;

	b = data;
	sum = 0;

	while (size >= sizeof(uint64_t)) {
		sum = dpg_cksum_add(sum, *((uint64_t *)b));
		size -= sizeof(uint64_t);
		b += sizeof(uint64_t);
	}
	if (size >= 4) {
		sum = dpg_cksum_add(sum, *((uint32_t *)b));
		size -= sizeof(uint32_t);
		b += sizeof(uint32_t);
	}
	if (size >= 2) {
		sum = dpg_cksum_add(sum, *((uint16_t *)b));
		size -= sizeof(uint16_t);
		b += sizeof(uint16_t);
	}
	if (size) {
		assert(size == 1);
		sum = dpg_cksum_add(sum, *b);
	}

	return sum;
}

static uint16_t
dpg_cksum(void *data, int len)
{
	uint64_t sum;
	uint16_t reduced;

	sum = dpg_cksum_raw(data, len);
	reduced = dpg_cksum_reduce(sum);
	return reduced;
}

static uint64_t
dpg_ipv4_pseudo_cksum(struct dpg_ipv4_hdr *ih, int len)
{	
	uint64_t sum;
	struct dpg_ipv4_pseudo_hdr pseudo;

	pseudo.src = ih->src_addr;
	pseudo.dst = ih->dst_addr;
	pseudo.pad = 0;
	pseudo.proto = ih->next_proto_id;
	pseudo.len = dpg_hton16(len);
	sum = dpg_cksum_raw(&pseudo, sizeof(pseudo));
	return sum;
}

static uint16_t
dpg_ipv4_udp_cksum(struct dpg_ipv4_hdr *ih, void *l4_hdr, int len)
{
	uint16_t reduced;
	uint64_t sum, pseudo_sum;

	sum = dpg_cksum_raw(l4_hdr, len);
	pseudo_sum = dpg_ipv4_pseudo_cksum(ih, len);
	sum = dpg_cksum_add(sum, pseudo_sum);
	reduced = dpg_cksum_reduce(sum);
	return reduced;
}

static const char *
dpg_icmp_type_string(int icmp_type)
{
	return icmp_type == DPG_IP_ICMP_ECHO_REQUEST ? "request" : "reply";
}

static struct dpg_port *
dpg_port_get(int port_id)
{
	struct dpg_port *port;

	port = g_dpg_ports[port_id];
	assert(port != NULL);

	return port;
}

static void
dpg_log_rxtx(struct dpg_strbuf *sb, struct dpg_task *task, struct dpg_eth_hdr *eh, int dir)
{
	char shbuf[DPG_ETH_ADDRSTRLEN];
	char dhbuf[DPG_ETH_ADDRSTRLEN];
	struct dpg_port *port;

	port = dpg_port_get(task->port_id);

	dpg_strbuf_adds(sb, dir == DPG_RX ? "RX ": "TX ");

	dpg_strbuf_adds(sb, dpg_get_port_name(port->pt_id));
	dpg_strbuf_adds(sb, " ");

//	if (dir != DPG_RX) {
//		return;
//	}
	if (g_dpg_verbose[dir] < 1) {
		return;
	}

	if (port->n_queues > 1) {
		dpg_strbuf_addf(sb, "(q=%d) ", task->queue_id);
	}

	dpg_eth_format_addr(shbuf, sizeof(shbuf), &eh->src_addr);
	dpg_eth_format_addr(dhbuf, sizeof(dhbuf), &eh->dst_addr);
	dpg_strbuf_addf(sb, "%s->%s ", shbuf, dhbuf);
}

static void
dpg_log_packet(struct dpg_task *task, int dir, struct dpg_eth_hdr *eh, struct dpg_ipv6_hdr *ih6,
		struct dpg_ipv4_hdr *ih, int hl)
{
	char sabuf[INET6_ADDRSTRLEN];
	char dabuf[INET6_ADDRSTRLEN];
	char logbuf[DPG_LOG_BUF_SIZE];
	struct dpg_strbuf sb;
	struct dpg_icmp_hdr *ich;
	struct dpg_tcp_hdr *th;
	struct dpg_udp_hdr *uh;

	if (g_dpg_verbose[dir] <= 0) {
		return;
	}

	dpg_strbuf_init(&sb, logbuf, sizeof(logbuf));

	dpg_log_rxtx(&sb, task, eh, dir);

	if (ih6 != NULL) {
		inet_ntop(AF_INET6, &ih6->src_addr, sabuf, sizeof(sabuf));
		inet_ntop(AF_INET6, &ih6->dst_addr, dabuf, sizeof(dabuf));
		dpg_strbuf_addf(&sb, "%s->%s: ", sabuf, dabuf);
	}

	inet_ntop(AF_INET, &ih->src_addr, sabuf, sizeof(sabuf));
	inet_ntop(AF_INET, &ih->dst_addr, dabuf, sizeof(dabuf));

	switch (ih->next_proto_id) {
	case IPPROTO_ICMP:
		ich = (struct dpg_icmp_hdr *)((uint8_t *)ih + hl);
		dpg_strbuf_addf(&sb, "ICMP echo %s: %s->%s, id=%d, seq=%d",
				dpg_icmp_type_string(ich->icmp_type),
				sabuf, dabuf,
				dpg_ntoh16(ich->icmp_ident),
				dpg_ntoh16(ich->icmp_seq_nb));
		break;

	case IPPROTO_TCP:
		th = (struct dpg_tcp_hdr *)((uint8_t *)ih + hl);
		dpg_strbuf_adds(&sb, "TCP [");
		dpg_strbuf_add_tcp_flags(&sb, th->tcp_flags);
		dpg_strbuf_addf(&sb, "] %s:%hu->%s:%hu",
				sabuf, dpg_ntoh16(th->src_port),
				dabuf, dpg_ntoh16(th->dst_port));
		break;

	case IPPROTO_UDP:
		uh = (struct dpg_udp_hdr *)((uint8_t *)ih + hl);
		dpg_strbuf_addf(&sb, "UDP %s:%hu->%s:%hu",
				sabuf, dpg_ntoh16(uh->src_port),
				dabuf, dpg_ntoh16(uh->dst_port));
		break;

	default:
		dpg_strbuf_addf(&sb, "IP %s->%s: proto %d", sabuf, dabuf, ih->next_proto_id);
		break;
	}

	dpg_strbuf_print(&sb);
}

static void
dpg_log_arp(struct dpg_task *task, int dir, struct dpg_eth_hdr *eh, struct dpg_arp_hdr *ah)
{
	int is_req;
	char tibuf[INET_ADDRSTRLEN];
	char sibuf[INET_ADDRSTRLEN];
	char thbuf[DPG_ETH_ADDRSTRLEN];
	char shbuf[DPG_ETH_ADDRSTRLEN];
	char logbuf[DPG_LOG_BUF_SIZE];
	struct dpg_strbuf sb;

	if (g_dpg_verbose[dir] <= 0) {
		return;
	}

	dpg_strbuf_init(&sb, logbuf, sizeof(logbuf));

	dpg_log_rxtx(&sb, task, eh, dir);

	is_req = ah->arp_opcode == RTE_BE16(DPG_ARP_OP_REQUEST);
	inet_ntop(AF_INET, &ah->arp_tip, tibuf, sizeof(tibuf));
	inet_ntop(AF_INET, &ah->arp_sip, sibuf, sizeof(sibuf));
	dpg_eth_format_addr(thbuf, sizeof(thbuf), &ah->arp_tha);
	dpg_eth_format_addr(shbuf, sizeof(shbuf), &ah->arp_sha);

	dpg_strbuf_addf(&sb, ": ARP %s %s(%s)->%s(%s)",
			is_req ? "request" : "reply",
			sibuf, shbuf, tibuf, thbuf);

	dpg_strbuf_print(&sb);
}

static void
dpg_log_ipv6(struct dpg_task *task, int dir, struct dpg_eth_hdr *eh, struct dpg_ipv6_hdr *ih,
		const char *desc)
{
	char srcbuf[INET6_ADDRSTRLEN];
	char dstbuf[INET6_ADDRSTRLEN];
	char logbuf[DPG_LOG_BUF_SIZE];
	struct dpg_strbuf sb;

	if (g_dpg_verbose[dir] <= 0) {
		return;
	}

	dpg_strbuf_init(&sb, logbuf, sizeof(logbuf));

	dpg_log_rxtx(&sb, task, eh, dir);

	inet_ntop(AF_INET6, ih->src_addr, srcbuf, sizeof(srcbuf));
	inet_ntop(AF_INET6, ih->dst_addr, dstbuf, sizeof(dstbuf));

	dpg_strbuf_addf(&sb, ": %s->%s: %s", srcbuf, dstbuf, desc);

	dpg_strbuf_print(&sb);
}

static void
dpg_log_custom(struct dpg_task *task, struct dpg_eth_hdr *eh, const char *proto)
{
	char logbuf[DPG_LOG_BUF_SIZE];
	struct dpg_strbuf sb;

	if (g_dpg_verbose[DPG_RX] <= 0) {
		return;
	}

	dpg_strbuf_init(&sb, logbuf, sizeof(logbuf));

	dpg_log_rxtx(&sb, task, eh, DPG_RX);

	dpg_strbuf_addf(&sb, "%s packet", proto);

	dpg_strbuf_print(&sb);
}

static uint64_t
dpg_rdtsc(void)
{
	return g_dpg_lcores[rte_lcore_id()].tsc;
}

static int
dpg_port_is_configured(struct dpg_port *port)
{
	return port->n_queues != 0;
}

static int
dpg_container_parse_u16(char *str, struct dpg_container *c)
{
	int rc;

	rc = dpg_container_parse(str, c, dpg_parse_u16);

	return rc;
}

static int
dpg_container_parse_ipv4(char *str, struct dpg_container *c)
{
	int rc;

	rc = dpg_container_parse(str, c, dpg_parse_ipv4);

	return rc;
}

static int
dpg_container_parse_ipv6(char *str, struct dpg_container *c)
{
	int rc;

	rc = dpg_container_parse(str, c, dpg_ipv6_parse);

	return rc;
}

static bool
dpg_tx_queue_full(struct dpg_tx_queue *q)
{
	return q->n_pkts == DPG_ARRAY_SIZE(q->pkts);
}

static bool
dpg_tx_queue_empty(struct dpg_tx_queue *q)
{
	return q->n_pkts == 0;
}

static int
dpg_tx_queue_room(struct dpg_tx_queue *q)
{
	return DPG_ARRAY_SIZE(q->pkts) - q->n_pkts;
}

static void
dpg_tx_queue_add(struct dpg_tx_queue *q, struct rte_mbuf *m)
{
	assert(!dpg_tx_queue_full(q));
	q->pkts[q->n_pkts++] = m;
}

static int
dpg_tx_queue_tx(struct dpg_tx_queue *q, int port_id, int queue_id)
{
	int txed;

	txed = 0;
	if (q->n_pkts) {
		txed = rte_eth_tx_burst(port_id, queue_id, q->pkts, q->n_pkts);
		memmove(q->pkts, q->pkts + txed, (q->n_pkts - txed) * sizeof (struct rte_mbuf *));
		q->n_pkts -= txed;
	}
	return txed;
}

static void
dpg_del_session_field(struct dpg_port *port, int field_id)
{
	struct dpg_container *field;

	field = port->session_field + field_id;
	if (field->list.dls_next != NULL) {
		DPG_DLIST_REMOVE(field, list);
		field->list.dls_next = NULL;
	}
}

static void
dpg_add_session_field(struct dpg_port *port, int field_id)
{
	struct dpg_container *field;

	dpg_del_session_field(port, field_id);

	field = port->session_field + field_id;
	DPG_DLIST_INSERT_TAIL(&port->session_field_head, field, list);
}

static uint16_t
dpg_set_port(struct dpg_port *port, const char *name)
{
	int rc;
	uint16_t port_id;

	rc = rte_eth_dev_get_port_by_name(name, &port_id);
	if (rc < 0) {
		dpg_die("DPDK doesn't run on port '%s'\n", optarg);		
	}

	if (g_dpg_ports[port_id] == NULL) {
		port->pt_id = port_id;
		g_dpg_ports[port->pt_id] = port;
	} else {
		dpg_die("%s: Already configured", name);
	}

	return port_id;
}

static struct dpg_port *
dpg_create_port(void)
{
	int i;
	struct dpg_port *port;

	port = dpg_xmalloc(sizeof(*port));
	memset(port, 0, sizeof(*port));
	port->pt_id = RTE_MAX_ETHPORTS;
	port->pt_fwd_id = RTE_MAX_ETHPORTS;
	port->rps_max = DPG_DEFAULT_RPS;
	port->pkt_len = DPG_DEFAULT_PKT_LEN;
	port->proto = IPPROTO_ICMP;

	port->pdr_percent = DPG_DEFAULT_PDR_PERCENT;
	port->pdr_period = DPG_DEFAULT_PDR_PERIOD;
	port->rps = DPG_DEFAULT_PDR_RPS;
	port->pdr_dir = 1;

	dpg_dlist_init(&port->task_head);
	dpg_dlist_init(&port->session_field_head);

	for (i = 0; i < DPG_ARRAY_SIZE(port->dst_eth_addr.addr_bytes); ++i) {
		port->dst_eth_addr.addr_bytes[i] = 0xFF;
	}

	dpg_container_parse_ipv4(DPG_DEFAULT_SRC_IP, &port->session_field[DPG_SESSION_SRC_IP]);
	dpg_container_parse_ipv4(DPG_DEFAULT_DST_IP, &port->session_field[DPG_SESSION_DST_IP]);

	dpg_container_parse_u16(DPG_DEFAULT_SRC_PORT, &port->session_field[DPG_SESSION_SRC_PORT]);
	dpg_container_parse_u16(DPG_DEFAULT_DST_PORT, &port->session_field[DPG_SESSION_DST_PORT]);

	dpg_container_parse_u16(DPG_DEFAULT_ICMP_ID, &port->session_field[DPG_SESSION_ICMP_ID]);
	dpg_container_parse_u16(DPG_DEFAULT_ICMP_SEQ, &port->session_field[DPG_SESSION_ICMP_SEQ]);

	dpg_add_session_field(port, DPG_SESSION_SRC_PORT);
	dpg_add_session_field(port, DPG_SESSION_DST_PORT);
	dpg_add_session_field(port, DPG_SESSION_ICMP_ID);
	dpg_add_session_field(port, DPG_SESSION_SRC_IP);
	dpg_add_session_field(port, DPG_SESSION_DST_IP);
	dpg_add_session_field(port, DPG_SESSION_ICMP_SEQ);

	return port;
}

static void
dpg_set_rand_seed(struct dpg_port *port, uint32_t seed)
{
	port->rand_seed = (seed << 8) & 0xffffff00;
}

static void
dpg_set_rand(struct dpg_port *port)
{
	port->rand = true;
	if (port->rand_seed == 0) {
		dpg_set_rand_seed(port, time(NULL) ^ getpid());
	}
}

static void
dpg_set_task_rand_session_count(struct dpg_task *task)
{
	uint32_t sum;
	struct dpg_port *port;

	port = dpg_port_get(task->port_id);

	task->rand_session_count = DPG_MAX(1, port->rand_session_count / port->n_queues);
	if (task->queue_id != 0) {
		return;
	}

	sum = task->rand_session_count * port->n_queues;
	if (sum >= port->rand_session_count) {
		return;
	}

	task->rand_session_count += port->rand_session_count - sum;
}

static void
dpg_create_task(struct dpg_port *port, uint16_t lcore_id, uint16_t queue_id)
{
	int field_id;
	bool first;
	struct dpg_lcore *lcore;
	struct dpg_task *task;
	struct dpg_container *ct;
	struct dpg_iterator *it;

	lcore = g_dpg_lcores + lcore_id;

	task = dpg_xmalloc(sizeof(*task));
	memset(task, 0, sizeof(*task));

	task->port_id = port->pt_id;
	task->lcore_id = lcore_id;
	task->queue_id = queue_id;

	dpg_dlist_init(&task->session_field_head);

	first = true;
	DPG_DLIST_FOREACH(ct, &port->session_field_head, list) {
		field_id = ct - port->session_field;
		it = task->session_field + field_id;
		if (first) {
			dpg_iterator_init(it, ct, port->n_queues, queue_id);
			first = false;
		} else {
			dpg_iterator_init(it, ct, 1, 0);
		}
		DPG_DLIST_INSERT_TAIL(&task->session_field_head, it, list);
	}

	if (port->rand) {
		task->rand_seed = port->rand_seed | task->queue_id;
		task->rand_state = task->rand_seed;
		if (port->rand_session_count) {
			dpg_set_task_rand_session_count(task);
		}
	}

	DPG_DLIST_INSERT_HEAD(&lcore->task_head, task, llist);
	DPG_DLIST_INSERT_HEAD(&port->task_head, task, plist);
}

static void
dpg_configure_port(struct dpg_port *port, struct dpg_container *lcores)
{
	int i, lcore_id;

	port->n_queues = lcores->size;
	for (i = 0; i < port->n_queues; ++i) {
		lcore_id = dpg_container_get(lcores, i);
		dpg_create_task(port, lcore_id, i);
	}
}

#define DPG_AS(s) dpg_strbuf_adds(&sb, s)
#define DPG_AF(fmt, ...) dpg_strbuf_addf(&sb, fmt, __VA_ARGS__)

static void
dpg_print_usage(void)
{
	int rc, port_id;
	dpg_eth_addr_t mac_addr;
	char rate_buf[32];
	char eth_addr_buf[DPG_ETH_ADDRSTRLEN];
	const char *port_name;
	char usage_buf[4096];
	struct dpg_strbuf sb;

	dpg_strbuf_init(&sb, usage_buf, sizeof(usage_buf));

	dpg_print_human_readable(rate_buf, sizeof(rate_buf), DPG_DEFAULT_RPS);

	DPG_AS("Usage: dpdk-ping [DPDK options] -- port options [-- port options ...]\n\n");
	DPG_AS("Port options:\n");
	DPG_AS("\t-h|--help:  Print this help\n");
	DPG_AS("\t-V {level}:  Be verbose (default: 0)\n");
	DPG_AS("\t-o {selectors}:  Specify output selectors\n");
	DPG_AS("\t-t {seconds}: Test duration in seconds (default: infinity\n");
	DPG_AF("\t-b {bool}:  Print bits/sec in report (default: %s)\n",
			dpg_bool_str(g_dpg_bflag));
	DPG_AS("\t-l {lcore id..}:  Lcores to run on\n");
	DPG_AS("\t-p {port name}:  Port to run on\n");
	DPG_AF("\t-R {bool}:  Send ICMP echo requests (default: %s)\n",
			dpg_bool_str(false));
	DPG_AF("\t-E {bool}:  Send ICMP echo reply on incoming ICMP echo requests (default: %s)\n",
			dpg_bool_str(false));	
	DPG_AS("\t-4 {IP..}:  Interaface IP address iterator\n");
	DPG_AS("\t-6 {IPv6..}:  Interface IPv6 address iterator\n");
	DPG_AF("\t-B {pps}:  ICMP requests bandwidth (default:%s)\n", rate_buf);
	DPG_AS("\t-H {ether address}:  Destination ethernet address "
			"(default: ff:ff:ff:ff:ff:ff)\n");
	DPG_AS("\t-g {IP}:  Gateway ip address\n");
	DPG_AF("\t-s {IP..}:  Source ip addresses iterator (default: %s)\n", 
			DPG_DEFAULT_SRC_IP);
	DPG_AF("\t-d {IP..}:  Destination ip addresses iterator (default: %s)\n",
			DPG_DEFAULT_DST_IP);
	DPG_AF("\t-S {port..}:  Source port iterator (default: %s)\n",
			DPG_DEFAULT_SRC_PORT);
	DPG_AF("\t-D {port..}:  Destination port iterator (default: %s)\n",
			DPG_DEFAULT_DST_PORT);
	DPG_AF("\t-L {bytes}:  Packet size (default: %d)\n", DPG_DEFAULT_PKT_LEN);
	DPG_AS("\t--rx-verbose {level}:  Be verbose on rx path (default: 0)\n");
	DPG_AS("\t--tx-verbose {level}:  Be verbose on tx path (default: 0)\n");
	DPG_AS("\t--quiet: Be quiet (do not print report)\n");
	DPG_AF("\t--human-readable {bool}:  Print output in human readable format "
			"(default: %s)\n", dpg_bool_str(g_dpg_human_readable));
	DPG_AS("\t--udp:  Send UDP packets\n");
	DPG_AS("\t--tcp:  Send TCP SYN packets\n");
	DPG_AS("\t--icmp:  Send ICMP echo packets\n");
	DPG_AF("\t--icmp-id {id..}:  ICMP request id iterator (default: %s)\n",
			DPG_DEFAULT_ICMP_ID);
	DPG_AF("\t--icmp-seq {seq..}:  ICMP request sequence iterator (default: %s)\n",
			DPG_DEFAULT_ICMP_SEQ);
	DPG_AS("\t--srv6-src {IPv6}:  SRv6 tunnel source address\n");
	DPG_AS("\t--srv6-dst {IPv6..}:  SRv6 tunnel destination address iterator\n");
	DPG_AF("\t--omit|-O {N}:  Omit {N} seconds to calculate throughput (default: %d)\n",
			DPG_DEFAULT_OMIT);
	DPG_AF("\t--software-counters {bool}:  Use software counters for reports (default: %s)\n",
			dpg_bool_str(false));
	DPG_AS("\t--pdr:  Enable partial drop rate rate mode\n");
	DPG_AF("\t--pdr-period  {seconds}:  specify patrial drop rate measurment period (default: %d)\n",
			DPG_DEFAULT_PDR_PERIOD);
	DPG_AF("\t--pdr-percent {percent}:  Specify partial drop rate percentage (default: %f)\n",
			DPG_DEFAULT_PDR_PERCENT);
	DPG_AF("\t--pdr-start {rps}:  Specify initail pdr rps (default: %d)\n",
			DPG_DEFAULT_PDR_RPS);
	DPG_AS("\t--pdr-step {rps}:  Specify initial pdr step (default: 0)\n");
	DPG_AS("\t--rand:  Iterate sessions randomly\n");
	DPG_AS("\t--rand-seed {number}:  Specify random generator seed\n");
	DPG_AS("\t--rand-sessions {number}: Specify _approximate_ random sessions number\n");
	DPG_AS("\tIterator of values x (x..):  {x,x,x...|x-x}\n");
	DPG_AS("Ports:\n");

	RTE_ETH_FOREACH_DEV(port_id) {
		port_name = dpg_get_port_name(port_id);
		DPG_AS(port_name);

		rc = dpg_eth_macaddr_get(port_id, &mac_addr);
		if (rc == 0) {
			dpg_eth_format_addr(eth_addr_buf, sizeof(eth_addr_buf), &mac_addr);
			DPG_AF("  %s", eth_addr_buf);
		}
		DPG_AS("\n");
	}

	dpg_strbuf_print(&sb);

	rte_exit(EXIT_SUCCESS, "\n");
}

#undef DPG_AS
#undef DPG_AF

static int
dpg_parse_port(int argc, char **argv)
{
	int i, opt, option_index;
	int64_t rc;
	uint8_t Hflag, gflag;
	uint16_t lcore_id;
	char *endptr;
	const char *optname;
	struct dpg_port *port, *fwd;
	struct dpg_container lcores;
	struct dpg_container *ct;

	static struct option long_options[] = {
		{ "help", no_argument, 0, 'h' },
		{ "rx-verbose", required_argument, 0, 0 },
		{ "tx-verbose", required_argument, 0, 0 },
		{ "quiet", no_argument, 0, 0 },
		{ "human-readable", required_argument, 0, 0 },
		{ "udp", no_argument, 0, 0 },
		{ "tcp", no_argument, 0, 0 },
		{ "icmp", no_argument, 0, 0 },
		{ "icmp-id", required_argument, 0, 0 },
		{ "icmp-seq", required_argument, 0, 0 },
		{ "srv6-src", required_argument, 0, 0 },
		{ "srv6-dst", required_argument, 0, 0 },
		{ "omit", required_argument, 0, 'O' },
		{ "software-counters", required_argument, 0, 0 },
		{ "pdr", no_argument, 0, 0 },
		{ "pdr-period", required_argument, 0, 0 },
		{ "pdr-percent",  required_argument, 0, 0 },
		{ "pdr-start", required_argument, 0, 0 },
		{ "pdr-step", required_argument, 0, 0 },
		{ "rand", no_argument, 0, 0 },
		{ "rand-seed", required_argument, 0, 0 },
		{ "rand-sessions", required_argument, 0, 0 },
		{ NULL, 0, 0, 0 },
	};

	memset(&lcores, 0, sizeof(lcores));
	Hflag = gflag = 0;

	port = dpg_create_port();

	while ((opt = getopt_long(argc, argv, "hV:o:t:b:l:p:f:R:E:4:6:B:H:g:s:d:S:D:L:O:",
			long_options, &option_index)) != -1) {
		switch (opt) {
		case 0:
			optname = long_options[option_index].name;
			if (!strcmp(optname, "rx-verbose")) {
				g_dpg_verbose[DPG_RX] = strtoul(optarg, NULL, 10);
			} else if (!strcmp(optname, "tx-verbose")) {
				g_dpg_verbose[DPG_TX] = strtoul(optarg, NULL, 10);
			} else if (!strcmp(optname, "quiet")) {
				g_dpg_verbose[DPG_RX] = g_dpg_verbose[DPG_TX] = -1;
			} else if (!strcmp(optname, "human-readable")) {
				rc = dpg_parse_bool(optarg);
				if (rc < 0) {
					dpg_invalid_argument(0, optname);
				}
				g_dpg_human_readable = rc;
			} else if (!strcmp(optname, "udp")) {
				port->proto = IPPROTO_UDP;
			} else if (!strcmp(optname, "tcp")) {
				port->proto = IPPROTO_TCP;
			} else if (!strcmp(optname, "icmp")) {
				port->proto = IPPROTO_ICMP;
			} else if (!strcmp(optname, "icmp-id")) {
				ct = port->session_field + DPG_SESSION_ICMP_ID;
				rc = dpg_container_parse_u16(optarg, ct);
				if (rc < 0) {
					dpg_invalid_argument(0, optname);
				}
				dpg_add_session_field(port, DPG_SESSION_ICMP_ID);
			} else if (!strcmp(optname, "icmp-seq")) {
				ct = port->session_field + DPG_SESSION_ICMP_SEQ;
				rc = dpg_container_parse_u16(optarg, ct);
				if (rc < 0) {
					dpg_invalid_argument(0, optname);
				}
				dpg_add_session_field(port, DPG_SESSION_ICMP_SEQ);
			} else if (!strcmp(optname, "srv6-src")) {
				rc = inet_pton(AF_INET6, optarg, port->srv6_src);
				if (rc != 1) {
					dpg_invalid_argument(0, optname);
				}
				port->srv6 = 1;
			} else if (!strcmp(optname, "srv6-dst")) {
				ct = port->session_field + DPG_SESSION_SRV6_DST;
				rc = dpg_container_parse_ipv6(optarg, ct);
				if (rc < 0) {
					dpg_invalid_argument(0, optname);
				}
				port->srv6 = 1;
				dpg_add_session_field(port, DPG_SESSION_SRV6_DST);
			} else if (!strcmp(optname, "software-counters")) {
				rc = dpg_parse_bool(optarg);
				if (rc < 0) {
					dpg_invalid_argument(0, optname);
				}
				port->software_counters = rc;
			} else if (!strcmp(optname, "pdr")) {
				port->pdr = 1;
			} else if (!strcmp(optname, "pdr-period")) {
				port->pdr_period = strtoul(optarg, NULL, 10);
				if (port->pdr_period < 1) {
					dpg_invalid_argument(0, optname);
				}
				port->pdr = 1;
			} else if (!strcmp(optname, "pdr-percent")) {
				rc = sscanf(optarg, "%lf", &port->pdr_percent);
				if (rc == 0 || rc == EOF) {
					dpg_invalid_argument(0, optname);
				}
				if (port->pdr_percent <= 0 || port->pdr_percent >= 100) {
					dpg_invalid_argument(0, optname);
				}
				port->pdr = 1;
			} else if (!strcmp(optname, "pdr-start")) {
				rc = dpg_parse_human_readable(optarg);
				if (rc < 0 || port->rps <= 0) {
					dpg_invalid_argument(opt, NULL);
				}
				port->rps = rc;
				port->pdr = 1;
			} else if (!strcmp(optname, "pdr-step")) {
				rc = dpg_parse_human_readable(optarg);
				if (rc < 0) {
					dpg_invalid_argument(opt, NULL);
				}
				port->pdr_step = rc;
				port->pdr = 1;
			} else if (!strcmp(optname, "rand")) {
				dpg_set_rand(port);
			} else if (!strcmp(optname, "rand-seed")) {
				port->rand = true;
				dpg_set_rand_seed(port, strtoul(optarg, NULL, 10));
			} else if (!strcmp(optname, "rand-sessions")) {
				dpg_set_rand(port);
				rc = dpg_parse_human_readable(optarg);
				if (rc < 0) {
					dpg_invalid_argument(0, optname);
				}
				port->rand_session_count = rc;
			} else {
				dpg_die("Unknown argument: '--%s'\n", optname);
			}
			break;

		case 'h':
			dpg_print_usage();
			break;

		case 'V':
			g_dpg_verbose[DPG_RX] = g_dpg_verbose[DPG_TX] =
					strtoul(optarg, NULL, 10);
			break;

		case 'o':
			rc = dpg_parse_oselectors(optarg);
			if (rc < 0) {
				dpg_invalid_argument(opt, NULL);
			}
			break;

		case 't':
			g_dpg_duration = strtoul(optarg, &endptr, 10);
			if (*endptr != '\0' || g_dpg_duration == 0) {
				dpg_invalid_argument(opt, NULL);
			}
			break;

		case 'b':
			rc = dpg_parse_bool(optarg);
			if (rc < 0) {
				dpg_invalid_argument(opt, NULL);
			}
			g_dpg_bflag = rc;
			break;

		case 'l':
			rc = dpg_container_parse_u16(optarg, &lcores);
			if (rc < 0) {
				dpg_invalid_argument(opt, NULL);
			}

			for (i = 0; i < lcores.size; ++i) {
				lcore_id = dpg_container_get(&lcores, i);
				rc = rte_lcore_is_enabled(lcore_id);
				if (!rc) {
					dpg_die("DPDK doesn't run on lcore %d\n", lcore_id);
				}
			}

			break;

		case 'p':
			if (port->pt_id != RTE_MAX_ETHPORTS) {
				dpg_argument_already_specified(opt, NULL);
			}
			dpg_set_port(port, optarg);
			break;

		case 'f':
			if (port->pt_fwd_id != RTE_MAX_ETHPORTS) {
				dpg_argument_already_specified(opt, NULL);
			}
			
			fwd = dpg_create_port();	
			port->pt_fwd_id = dpg_set_port(fwd, optarg);
			break;


		case 'R':
			rc = dpg_parse_bool(optarg);
			if (rc < 0) {
				dpg_invalid_argument(opt, NULL);
			}
			port->Rflag = rc;
			break;

		case 'E':
			rc = dpg_parse_bool(optarg);
			if (rc < 0) {
				dpg_invalid_argument(opt, NULL);
			}
			port->Eflag = rc;
			break;

		case '4':
			rc = dpg_container_parse_ipv4(optarg, &port->addresses4);
			if (rc < 0) {
				dpg_invalid_argument(opt, NULL);
			}
			break;

		case '6':
			rc = dpg_container_parse_ipv6(optarg, &port->addresses6);
			if (rc < 0) {
				dpg_invalid_argument(opt, NULL);
			}
			break;

		case 'B':
			rc = dpg_parse_human_readable(optarg);
			if (rc < 0) {
				dpg_invalid_argument(opt, NULL);
			}
			port->rps_max = rc;
			break;

		case 'H':
			rc = dpg_eth_unformat_addr(optarg, &port->dst_eth_addr);
			if (rc != 0) {
				dpg_invalid_argument(opt, NULL);
			}
			port->arp_resolved = 1;
			Hflag = 1;
			break;

		case 'g':
			rc = inet_pton(AF_INET, optarg, &port->gateway);
			if (rc != 1) {
				dpg_invalid_argument(opt, NULL);
			}
			gflag = 1;
			break;

		case 's':
			ct = port->session_field + DPG_SESSION_SRC_IP;
			rc = dpg_container_parse_ipv4(optarg, ct);
			if (rc < 0) {
				dpg_invalid_argument(opt, NULL);
			}
			dpg_add_session_field(port, DPG_SESSION_SRC_IP);
			break;

		case 'd':
			ct = port->session_field + DPG_SESSION_DST_IP;
			rc = dpg_container_parse_ipv4(optarg, ct);
			if (rc < 0) {
				dpg_invalid_argument(opt, NULL);
			}
			dpg_add_session_field(port, DPG_SESSION_DST_IP);
			break;

		case 'S':
			ct = port->session_field + DPG_SESSION_SRC_PORT;
			rc = dpg_container_parse_u16(optarg, ct);
			if (rc < 0) {
				dpg_invalid_argument(opt, NULL);
			}
			dpg_add_session_field(port, DPG_SESSION_SRC_PORT);
			break;

		case 'D':
			ct = port->session_field + DPG_SESSION_DST_PORT;
			rc = dpg_container_parse_u16(optarg, ct);
			if (rc < 0) {
				dpg_invalid_argument(opt, NULL);
			}
			dpg_add_session_field(port, DPG_SESSION_DST_PORT);
			break;

		case 'L':
			port->pkt_len = strtoul(optarg, &endptr, 10);
			if (*endptr != '\0' || port->pkt_len < DPG_DEFAULT_PKT_LEN) {
				dpg_invalid_argument(opt, NULL);
			}
			break;

		case 'O':
			g_dpg_omit = strtoul(optarg, &endptr, 10);
			if (*endptr != '\0' || g_dpg_omit < 1) {
				dpg_invalid_argument(opt, NULL);
			}
			break;

		default:
			dpg_die("Unknown argument: '-%c'\n", opt);
			break;
		}
	}

	if (optind < argc && strcmp(argv[optind - 1], "--")) {
		dpg_die("Unknown input: '%s'\n", argv[optind]);
	}

	if (port->pt_id == RTE_MAX_ETHPORTS) {
		dpg_argument_not_specified('p', NULL);
	}

	if (!lcores.size) {
		dpg_argument_not_specified('l', NULL);
	}

	if (2 * g_dpg_omit >= g_dpg_duration) {
		dpg_die("Too short test duration (should be at least %d seconds)\n",
				2 * g_dpg_omit + 1);
	}

	if (port->pt_fwd_id != RTE_MAX_ETHPORTS) {
		fwd = g_dpg_ports[port->pt_fwd_id];
		fwd->pt_fwd_id = port->pt_id;

		dpg_configure_port(fwd, &lcores);

		if (port->Rflag || port->Eflag) {
			dpg_noone_argument_specified("-R,-E,-f");

		}
	} else {
		if (!port->Rflag && !port->Eflag) {
			dpg_noone_argument_specified("-R,-E,-f");
		}

		if (port->Rflag) {
			if (!(Hflag ^ gflag)) {
				dpg_noone_argument_specified("-H'-g");
			}
		}

		if (port->srv6) {
			if (dpg_is_zero(&port->srv6_src, sizeof(port->srv6_src))) {
				dpg_argument_not_specified(0, "srv6-src");
			}
			if (port->session_field[DPG_SESSION_SRV6_DST].size == 0) {
				dpg_argument_not_specified(0, "srv6-dst");
			}
		}

		if (port->proto == IPPROTO_ICMP) {
			dpg_del_session_field(port, DPG_SESSION_SRC_PORT);
			dpg_del_session_field(port, DPG_SESSION_DST_PORT);
		} else {
			dpg_del_session_field(port, DPG_SESSION_ICMP_ID);
			dpg_del_session_field(port, DPG_SESSION_ICMP_SEQ);
		}
	}

	dpg_configure_port(port, &lcores);

	return optind;
}

static void
dpg_set_eth_hdr_addresses(struct dpg_port *port, struct rte_mbuf *m)
{
	struct dpg_eth_hdr *eh;

	eh = rte_pktmbuf_mtod(m, struct dpg_eth_hdr *);

	if (port->arp_resolved) {
		eh->dst_addr = port->dst_eth_addr;
	} else {
		// `echo` case
		eh->dst_addr = eh->src_addr;
	}
	eh->src_addr = port->src_eth_addr;
}

static void
dpg_next_session(struct dpg_task *task)
{
	bool overflow;
	uint32_t r;
	struct dpg_iterator *it;
	struct dpg_port *port;

	port = dpg_port_get(task->port_id);
	if (port->rand) {
		DPG_DLIST_FOREACH(it, &task->session_field_head, list) {
			r = dpg_rand_xorshift(&task->rand_state);
			dpg_iterator_set_rand(it, r);
		}

		if (task->rand_session_count) {
			task->rand_session_index++;
			if (task->rand_session_index == task->rand_session_count) {
				task->rand_session_index = 0;
				task->rand_state = task->rand_seed;
			}
		}
	} else {
		DPG_DLIST_FOREACH(it, &task->session_field_head, list) {
			overflow = dpg_iterator_next(it);
			if (!overflow) {
				break;
			}
		}
	}
}

static void
dpg_set_payload(void *data, uint64_t seq)
{
	struct dpg_payload *p;

	p = data;
	p->payload_magic = DPG_PAYLOAD_MAGIC;
	p->payload_seq = dpg_hton64(seq);
}

static struct rte_mbuf *
dpg_create_arp_request(struct dpg_task *task)
{
	dpg_uint128_t src_ip;
	struct rte_mbuf *m;
	struct dpg_eth_hdr *eh;
	struct dpg_arp_hdr *ah;
	struct dpg_port *port;
	struct dpg_iterator *field;

	port = dpg_port_get(task->port_id);

	field = task->session_field + DPG_SESSION_SRC_IP;
	src_ip = dpg_iterator_get(field);

	m = dpg_pktmbuf_alloc();
	m->next = NULL;
	m->pkt_len = m->data_len = sizeof(*eh) + sizeof(*ah);

	eh = rte_pktmbuf_mtod(m, struct dpg_eth_hdr *);
	ah = (struct dpg_arp_hdr *)(eh + 1);

	eh->eth_type = RTE_BE16(DPG_ETH_TYPE_ARP);
	eh->src_addr = port->src_eth_addr;
	memset(&eh->dst_addr, 0xff, sizeof(eh->dst_addr));

	ah->arp_opcode = RTE_BE16(DPG_ARP_OP_REQUEST);
	ah->arp_hardware = RTE_BE16(DPG_ARP_HRD_ETHER); 
	ah->arp_protocol = RTE_BE16(DPG_ETHER_TYPE_IPV4);
	ah->arp_hlen = 6;
	ah->arp_plen = 4;
	ah->arp_tha = port->dst_eth_addr;
	ah->arp_sha = port->src_eth_addr;
	ah->arp_tip = port->gateway;
	ah->arp_sip = rte_cpu_to_be_32(src_ip);

	dpg_log_arp(task, DPG_TX, eh, ah);

	return m;
}

static struct rte_mbuf *
dpg_create_request(struct dpg_task *task)
{
	int ih_total_length;
	dpg_uint128_t srv6_dst, src_ip, dst_ip, src_port, dst_port, icmp_id, icmp_seq;
	struct rte_mbuf *m;
	struct dpg_eth_hdr *eh;
	struct dpg_ipv4_hdr *ih;
	struct dpg_ipv6_hdr *ih6;
	struct dpg_icmp_hdr *ich;
	struct dpg_tcp_hdr *th;
	struct dpg_udp_hdr *uh;
	struct dpg_srv6_hdr *srh;
	struct dpg_port *port;
	struct dpg_iterator *field;

	port = dpg_port_get(task->port_id);

	m = dpg_pktmbuf_alloc();

	eh = rte_pktmbuf_mtod(m, struct dpg_eth_hdr *);

	m->pkt_len = sizeof(*eh) + sizeof(*ih);
	switch (port->proto) {
	case IPPROTO_ICMP:
		m->pkt_len += sizeof(*ich);
		break;

	case IPPROTO_TCP:
		m->pkt_len += sizeof(*th);
		break;

	default:
		// UDP
		m->pkt_len += sizeof(*uh);
		break;
	}

	m->pkt_len += sizeof(struct dpg_payload);

	if (port->srv6) {
		m->pkt_len += sizeof(*ih6) + sizeof(*srh);

		m->pkt_len = DPG_MAX(port->pkt_len, m->pkt_len);
		ih_total_length = m->pkt_len - (sizeof(*eh) + sizeof(*ih6) + sizeof(*srh));

		eh->eth_type = RTE_BE16(DPG_ETH_TYPE_IPV6);
		ih6 = (struct dpg_ipv6_hdr *)(eh + 1);
		srh = (struct dpg_srv6_hdr *)(ih6 + 1);
		ih = (struct dpg_ipv4_hdr *)(srh + 1);

		field = task->session_field + DPG_SESSION_SRV6_DST;
		srv6_dst = dpg_iterator_get(field);

		ih6->vtc_flow = rte_cpu_to_be_32(0x60000000);
		ih6->payload_len = dpg_hton16(m->pkt_len - (sizeof(*eh) + sizeof(*ih6)));
		ih6->proto = IPPROTO_ROUTING;
		ih6->hop_limits = 64;
		memcpy(ih6->src_addr, port->srv6_src, sizeof(ih6->src_addr));
		dpg_uint128_to_ipv6(ih6->dst_addr, srv6_dst);

		srh->next_header = IPPROTO_IPIP;
		srh->hdr_ext_len = sizeof(*srh) / 8 - 1;
		srh->routing_type = 4; // Segment Routing v6
		srh->segments_left = 0;
		srh->last_entry = 0;
		srh->flags = 0;
		srh->tag = 0;
		memcpy(srh->localsid, ih6->dst_addr, DPG_IPV6_ADDR_SIZE);
	} else {
		m->pkt_len = DPG_MAX(port->pkt_len, m->pkt_len);
		ih_total_length = m->pkt_len - sizeof(*eh);

		eh->eth_type = RTE_BE16(DPG_ETH_TYPE_IPV4);
		ih = (struct dpg_ipv4_hdr *)(eh + 1);

		ih6 = NULL;
	}

	m->next = NULL;
	m->data_len = m->pkt_len;

	dpg_set_eth_hdr_addresses(port, m);

	ih->version = 4;
	ih->ihl = sizeof(*ih) / sizeof(uint32_t);
	ih->type_of_service = 0;
	ih->total_length = dpg_hton16(ih_total_length);
	ih->packet_id = 0;
	ih->fragment_offset = 0;
	ih->time_to_live = 64;
	ih->next_proto_id = port->proto;
	ih->hdr_checksum = 0;

	field = task->session_field + DPG_SESSION_SRC_IP;
	src_ip = dpg_iterator_get(field);
	ih->src_addr = rte_cpu_to_be_32(src_ip);

	field = task->session_field + DPG_SESSION_DST_IP;
	dst_ip = dpg_iterator_get(field);
	ih->dst_addr = rte_cpu_to_be_32(dst_ip);

	ih->hdr_checksum = dpg_cksum(ih, sizeof(*ih));

	switch (port->proto) {
	case IPPROTO_ICMP:
		ich = (struct dpg_icmp_hdr *)(ih + 1);
		ich->icmp_type = DPG_IP_ICMP_ECHO_REQUEST;
		ich->icmp_code = 0;
		ich->icmp_cksum = 0;

		field = task->session_field + DPG_SESSION_ICMP_ID;
		icmp_id = dpg_iterator_get(field);
		ich->icmp_ident = dpg_hton16(icmp_id);

		field = task->session_field + DPG_SESSION_ICMP_SEQ;
		icmp_seq = dpg_iterator_get(field);
		ich->icmp_seq_nb = dpg_hton16(icmp_seq);

		dpg_set_payload(ich + 1, port->send_seq++);

		ich->icmp_cksum = dpg_cksum(ich, ih_total_length - sizeof(*ih));
		break;

	case IPPROTO_TCP:
		th = (struct dpg_tcp_hdr *)(ih + 1);

		field = task->session_field + DPG_SESSION_SRC_PORT;
		src_port = dpg_iterator_get(field);
		th->src_port = dpg_hton16(src_port);

		field = task->session_field + DPG_SESSION_DST_PORT;
		dst_port = dpg_iterator_get(field);
		th->dst_port = dpg_hton16(dst_port);

		th->sent_seq = rte_cpu_to_be_32(1);
		th->recv_ack = 0;
		th->data_off = sizeof(*th) << 2;
		th->tcp_flags = DPG_TCP_SYN;
		th->rx_win = dpg_hton16(4096);
		th->tcp_urp = 0;

		dpg_set_payload(th + 1, port->send_seq++);

		th->cksum = 0;
		th->cksum = dpg_ipv4_udp_cksum(ih, th, ih_total_length - sizeof(*ih));
		break;

	default:
		// UDP
		uh = (struct dpg_udp_hdr *)(ih + 1);

		field = task->session_field + DPG_SESSION_SRC_PORT;
		src_port = dpg_iterator_get(field);
		uh->src_port = dpg_hton16(src_port);

		field = task->session_field + DPG_SESSION_DST_PORT;
		dst_port = dpg_iterator_get(field);
		uh->dst_port = dpg_hton16(dst_port);
		uh->dgram_len = dpg_hton16(ih_total_length - sizeof(*ih));

		dpg_set_payload(uh + 1, port->send_seq++);

		uh->dgram_cksum = 0;
		uh->dgram_cksum = dpg_ipv4_udp_cksum(ih, uh, ih_total_length - sizeof(*ih));
		break;
	}

	port->pt_requests++;

	dpg_next_session(task);

	dpg_log_packet(task, DPG_TX, eh, ih6, ih, sizeof(*ih));

	return m;
}

static int
dpg_ip_input(struct dpg_task *task, struct rte_mbuf *m,
		struct dpg_eth_hdr *eh, struct dpg_ipv6_hdr *ih6, void *ptr, int len)
{
	int hl, ih_total_length, l4_hdr_len;
	uint32_t seq;
	uint64_t recv_seq;
	void *l4_hdr;
	struct dpg_ipv4_hdr *ih;
	struct dpg_icmp_hdr *ich;
	struct dpg_udp_hdr *uh;
	struct dpg_tcp_hdr *th;
	struct dpg_payload *payload;
	struct dpg_port *port;

	port = dpg_port_get(task->port_id);

	ih = ptr;
	if (len < sizeof(*ih)) {
		return -EINVAL;
	}

	hl = ih->ihl * sizeof(uint32_t);
	if (hl < sizeof(*ih)) {
		return -EINVAL;
	}

	if (len < hl) {
		return -EINVAL;
	}

	ih_total_length = dpg_ntoh16(ih->total_length);

	if (ih_total_length > len) {
		return -EINVAL;
	}

	l4_hdr = (uint8_t *)ih + hl;
	switch (ih->next_proto_id) {
	case IPPROTO_ICMP:
		l4_hdr_len = sizeof(*ich);
		break;
	case IPPROTO_UDP:
		l4_hdr_len = sizeof(*uh);
		break;
	case IPPROTO_TCP:
		l4_hdr_len = sizeof(*th);
		break;
	default:
		l4_hdr_len = 0;
		break;
	}

	if (ih_total_length < hl + l4_hdr_len) {
		return -EINVAL;
	}

	if (ih_total_length < hl + l4_hdr_len + sizeof(*payload)) {
		payload = NULL;
	} else {
		payload = (struct dpg_payload *)((uint8_t *)l4_hdr + l4_hdr_len);
	}

	dpg_log_packet(task, DPG_RX, eh, ih6, ih, hl);

	if (ih6 != NULL) {
		if (port->srv6) {
			return -ENOTSUP;
		}

		memcpy((uint8_t *)ih - sizeof(*eh), eh, sizeof(*eh));
		eh = (struct dpg_eth_hdr *)rte_pktmbuf_adj(m, (uint8_t *)ih - (uint8_t *)(eh + 1));
		assert(eh == rte_pktmbuf_mtod(m, struct dpg_eth_hdr *));
		assert((struct dpg_ipv4_hdr *)(eh + 1) == ih);
		eh->eth_type = RTE_BE16(DPG_ETH_TYPE_IPV4);
		ih6 = NULL;
	}

	switch (ih->next_proto_id) {
	case IPPROTO_ICMP:
		ich = (struct dpg_icmp_hdr *)l4_hdr;

		if (port->Eflag) {
			if (ich->icmp_type != DPG_IP_ICMP_ECHO_REQUEST) {
				return -ENOTSUP;
			}
			ich->icmp_type = DPG_IP_ICMP_ECHO_REPLY;
			ich->icmp_cksum = 0;
			ich->icmp_cksum = dpg_cksum(ich, ih_total_length - hl);
		}
		break;

	case IPPROTO_TCP:
		th = (struct dpg_tcp_hdr *)l4_hdr;

		if (port->Eflag) {
			if (th->tcp_flags != DPG_TCP_SYN) {
				return -ENOTSUP;
			}
			DPG_SWAP(th->src_port, th->dst_port);
			th->tcp_flags = DPG_TCP_SYN|DPG_TCP_ACK;
			seq = dpg_ntoh32(th->sent_seq);
			th->sent_seq = rte_cpu_to_be_32(1);
			th->recv_ack = rte_cpu_to_be_32(seq + 1);
			th->cksum = 0;
			th->cksum = dpg_ipv4_udp_cksum(ih, th, ih_total_length - hl);
		}
		break;

	case IPPROTO_UDP:
		uh = (struct dpg_udp_hdr *)l4_hdr;

		if (port->Eflag) {
			DPG_SWAP(uh->src_port, uh->dst_port);
			uh->dgram_cksum = 0;
			uh->dgram_cksum = dpg_ipv4_udp_cksum(ih, uh, ih_total_length - hl);
		}
		break;

	default:
		return -ENOTSUP;
	}

	if (port->Eflag) {
		DPG_SWAP(ih->src_addr, ih->dst_addr);
		ih->hdr_checksum = 0;
		ih->hdr_checksum = dpg_cksum(ih, hl);

		dpg_log_packet(task, DPG_TX, eh, ih6, ih, hl);

		return 0;
	} else {
		if (payload != NULL && payload->payload_magic == DPG_PAYLOAD_MAGIC) {
			if (port->pdr) {
				recv_seq = dpg_ntoh64(payload->payload_seq);
				if (recv_seq > port->recv_seq) {
					port->pt_drops++;
				}
				port->recv_seq = recv_seq + 1;
			}
			port->pt_replies++;
		} else {
			port->pt_drops++;
		}

		return -ENOTSUP;
	}
}

static void
dpg_create_neighbour_advertisment(struct dpg_port *port, struct rte_mbuf *m,
		struct dpg_ipv6_hdr *ih, struct dpg_icmpv6_neigh_solicitaion *ns)
{
	int len;
	uint64_t sum;
	uint8_t target[DPG_IPV6_ADDR_SIZE];
	struct dpg_icmpv6_neigh_advertisment *na;
	struct dpg_target_link_layer_address_option *opt;
	struct dpg_ipv6_pseudo_hdr pseudo;

	len = sizeof(*na) + sizeof(*opt);
	m->pkt_len = m->data_len = sizeof(struct dpg_eth_hdr) + sizeof(*ih) + len;

	memcpy(target, ns->target, sizeof(target));

	ih->payload_len = dpg_hton16(len);
	ih->proto = DPG_IPPROTO_ICMPV6;
	DPG_SWAP(ih->src_addr, ih->dst_addr);
	memcpy(ih->src_addr, target, sizeof(target));

	na = (struct dpg_icmpv6_neigh_advertisment *)(ih + 1);

	na->type = DPG_ICMPV6_NEIGH_ADVERTISMENT;
	na->code = 0;
	na->checksum = 0;
	na->flags = rte_cpu_to_be_32(0x60000000);
	memcpy(na->target, target, sizeof(na->target));

	opt = (struct dpg_target_link_layer_address_option *)(na + 1);
	opt->type = 2;
	opt->length = sizeof(*opt) / 8;
	opt->address = port->src_eth_addr;

	memcpy(pseudo.src_addr, ih->src_addr, sizeof(pseudo.src_addr));
	memcpy(pseudo.dst_addr, ih->dst_addr, sizeof(pseudo.dst_addr));
	pseudo.proto = (uint32_t)(DPG_IPPROTO_ICMPV6 << 24);
	pseudo.len = rte_cpu_to_be_32(len);

	sum = dpg_cksum_raw(&pseudo, sizeof(pseudo));
	sum = dpg_cksum_add(sum, dpg_cksum_raw(na, sizeof(*na)));
	sum = dpg_cksum_add(sum, dpg_cksum_raw(opt, sizeof(*opt)));

	na->checksum = dpg_cksum_reduce(sum);
}

static int
dpg_ipv6_input(struct dpg_task *task, struct rte_mbuf *m)
{
	int rc, hl, proto;
	uint8_t *ptr;
	uint16_t len;
	char tgtbuf[INET6_ADDRSTRLEN];
	char desc[128];
	dpg_uint128_t target;
	struct dpg_eth_hdr *eh;
	struct dpg_ipv6_hdr *ih6;
	struct dpg_icmpv6_hdr *ich6;
	struct dpg_srv6_hdr *srh;
	struct dpg_icmpv6_neigh_solicitaion *ns;
	struct dpg_port *port;

	port = dpg_port_get(task->port_id);

	eh = rte_pktmbuf_mtod(m, struct dpg_eth_hdr *);
	ih6 = (struct dpg_ipv6_hdr *)(eh + 1);

	len = dpg_ntoh16(ih6->payload_len);
	if (m->pkt_len < sizeof(*eh) + sizeof(*ih6) + len) {
		dpg_log_custom(task, eh, "Malformed IPv6");
		return -EINVAL;
	}

	ptr = (uint8_t *)(ih6 + 1);
	proto = ih6->proto;

	while (1) {
		switch (proto) {
		case IPPROTO_ROUTING:
			if (len < sizeof(*srh)) {
				goto out;
			}
			srh = (struct dpg_srv6_hdr *)ptr;
			hl = 8 * (srh->hdr_ext_len + 1);
			if (len < hl) {
				goto out;
			}

			len -= hl;
			ptr += hl;

			proto = srh->next_header;
			break;

		case DPG_IPPROTO_ICMPV6:
			if (len < sizeof(*ich6)) {
				goto out;
			}
			ich6 = (struct dpg_icmpv6_hdr *)ptr;
			if (ich6->type != DPG_ICMPV6_NEIGH_SOLICITAION || len < sizeof(*ns)) {
				goto out;
			}
			ns = (struct dpg_icmpv6_neigh_solicitaion *)ptr;
			ptr += sizeof(*ns);
			len -= sizeof(*ns);

			if (g_dpg_verbose[DPG_RX] > 0) {
				inet_ntop(AF_INET6, ns->target, tgtbuf, sizeof(tgtbuf));
				snprintf(desc, sizeof(desc),
				         "Neighbour Solicitation (target=%s)",
				         tgtbuf);
				dpg_log_ipv6(task, DPG_RX, eh, ih6, desc);
			}

			if (port->Rflag || port->Eflag) {
				target = dpg_ipv6_to_uint128(ns->target);
				rc = dpg_container_find(&port->addresses6, target);
				if (!rc) {
					return -EINVAL;
				}

				dpg_create_neighbour_advertisment(port, m, ih6, ns);

				dpg_log_ipv6(task, DPG_TX, eh, ih6, "Neighbour Advertisment");
			}

			return 0;

		default:
			goto out;
		}
	}

out:
	if (proto == IPPROTO_IPIP) {
		return dpg_ip_input(task, m, eh, ih6, ptr, len);
	} else {
		if (g_dpg_verbose[DPG_RX] > 0) {
			snprintf(desc, sizeof(desc), "proto %d", proto);
			dpg_log_ipv6(task, DPG_RX, eh, ih6, desc);
		}
		return -EINVAL;
	}
}

static int
dpg_arp_input(struct dpg_task *task, struct rte_mbuf *m)
{
	struct dpg_eth_hdr *eh;
	struct dpg_arp_hdr *ah;
	struct dpg_port *port;

	port = dpg_port_get(task->port_id);

	eh = rte_pktmbuf_mtod(m, struct dpg_eth_hdr *);
	if (m->pkt_len < sizeof(*eh) + sizeof(*ah)) {
		return -EINVAL;
	}

	ah = (struct dpg_arp_hdr *)(eh + 1);

	dpg_log_arp(task, DPG_RX, eh, ah);

	switch (ah->arp_opcode) {
	case RTE_BE16(DPG_ARP_OP_REQUEST):
		break;
	case RTE_BE16(DPG_ARP_OP_REPLY):
		if (ah->arp_sip == port->gateway) {
			port->dst_eth_addr = eh->dst_addr;
			DPG_WRITE_ONCE(port->arp_resolved, 1);
		}
	default:
		return -EINVAL;
	}

	ah->arp_opcode = RTE_BE16(DPG_ARP_OP_REPLY);
	ah->arp_tha = port->dst_eth_addr;
	ah->arp_sha = port->src_eth_addr;
	DPG_SWAP(ah->arp_tip, ah->arp_sip);

	dpg_log_arp(task, DPG_TX, NULL, ah);

	return 0;
}

static int
dpg_rps_ratelimit(struct dpg_task *task, int rate, int room)
{
	int n_reqs, dp;
	uint64_t tsc, dt;

	if (rate == 0) {
		return 0;
	}

	tsc = dpg_rdtsc();
	dt = tsc - task->req_tx_time;

	dp = rate * dt / g_dpg_hz;

	n_reqs = DPG_MIN(dp, room);

	task->req_tx_time += n_reqs * g_dpg_hz / rate;

	return n_reqs;
}

static int
dpg_process_packet(struct dpg_task *task, struct rte_mbuf *m)
{
	int rc;
	char proto[32];
	struct dpg_eth_hdr *eh;

	eh = rte_pktmbuf_mtod(m, struct dpg_eth_hdr *);
	if (m->pkt_len < sizeof(*eh)) {
		return -EINVAL;
	}

	switch (eh->eth_type) {
	case RTE_BE16(DPG_ETH_TYPE_IPV4):
		rc = dpg_ip_input(task, m, eh, NULL, eh + 1, m->pkt_len - sizeof(*eh));
		if (rc == -EINVAL) {
			dpg_log_custom(task, eh, "Malformed IP");
		}
		if (rc < 0) {
			return rc;
		}
		break;

	case RTE_BE16(DPG_ETH_TYPE_IPV6):
		rc = dpg_ipv6_input(task, m);
		if (rc < 0) {
			return rc;
		}
		break;
	
	case RTE_BE16(DPG_ETH_TYPE_ARP):
		rc = dpg_arp_input(task, m);
		if (rc < 0) {
			return rc;
		}
		break;

	default:
		if (g_dpg_verbose[DPG_RX] > 0) {
			snprintf(proto, sizeof(proto), "proto=0x%04hx",
					dpg_ntoh16(eh->eth_type));
			dpg_log_custom(task, eh, proto);
		}
		return -EINVAL;
	}

	return 0;
}

static void
dpg_do_ping(struct dpg_port *port, struct dpg_task *task)
{
	int i, rc, n_rx, n_reqs, room, txed, rx_bytes;
	uint8_t arp_resolved;
	struct dpg_lcore *lcore;
	struct rte_mbuf *m, *rx_pkts[DPG_MAX_PKT_BURST];

	lcore = g_dpg_lcores + task->lcore_id;

	rx_bytes = 0;
	n_rx = rte_eth_rx_burst(task->port_id, task->queue_id, rx_pkts,
	                        DPG_ARRAY_SIZE(rx_pkts));

	for (i = 0; i < n_rx; ++i) {
		m = rx_pkts[i];
		rx_bytes += m->data_len;

		rc = dpg_process_packet(task, m);
		if (rc == 0) {
			dpg_set_eth_hdr_addresses(port, m);
			rte_pktmbuf_free(m);

			m = dpg_create_request(task);

			if (!dpg_tx_queue_full(&task->rpl_queue)) {
				dpg_tx_queue_add(&task->rpl_queue, m);
				continue;
			}
		}
		rte_pktmbuf_free(m);
	}

	room = dpg_tx_queue_room(&task->req_queue);
	arp_resolved = DPG_READ_ONCE(port->arp_resolved);
	
	if (room && (port->Rflag || !arp_resolved)) {
		if (!arp_resolved) {
			if (task->queue_id == 0 &&
			    lcore->tsc - task->arp_request_time > g_dpg_hz) {
				task->arp_request_time = lcore->tsc;
				m = dpg_create_arp_request(task);
				dpg_tx_queue_add(&task->req_queue, m);
			}
		} else if (port->Rflag) {
			if (task->rps == 0) {
				n_reqs = 0;
			} else if (task->rps > 0) {
				n_reqs = dpg_rps_ratelimit(task, task->rps, room);
			} else {
				n_reqs = room;
			}

			for (i = 0; i < n_reqs; ++i) {
				m = dpg_create_request(task);
				dpg_tx_queue_add(&task->req_queue, m);
			}
		}
	}

	txed = dpg_tx_queue_tx(&task->rpl_queue, task->port_id, task->queue_id);
	if (dpg_tx_queue_empty(&task->rpl_queue)) {
		txed += dpg_tx_queue_tx(&task->req_queue, task->port_id,
		                        task->queue_id);
	}

	if (port->software_counters) {
		dpg_counter_add(&port->ipackets, n_rx);
		dpg_counter_add(&port->ibytes, rx_bytes);

		dpg_counter_add(&port->opackets, txed);
		dpg_counter_add(&port->obytes, 0);
	}
}

static void
dpg_do_fwd(struct dpg_port *port, struct dpg_task *task)
{
	int i, n_rx, room;
	struct rte_mbuf *rx_pkts[DPG_MAX_PKT_BURST];

	n_rx = rte_eth_rx_burst(port->pt_id, task->queue_id, rx_pkts,
	                        DPG_ARRAY_SIZE(rx_pkts));

	if (g_dpg_verbose[DPG_RX] > 0) {
		for (i = 0; i < n_rx; ++i) {
			dpg_process_packet(task, rx_pkts[i]);
		}
	}

	room = dpg_tx_queue_room(&task->rpl_queue);
	for (i = 0; i < DPG_MIN(n_rx, room); ++i) {
		dpg_tx_queue_add(&task->rpl_queue, rx_pkts[i]);
	}
	for (; i < n_rx; ++i) {
		dpg_dbg("DROP!!");
		rte_pktmbuf_free(rx_pkts[i]);
	}


//	for (i = 0; i < n_rx; ++i) {
//		dpg_set_eth_hdr_addresses(port, rx_pkts[i]);
//	}

	dpg_tx_queue_tx(&task->rpl_queue, port->pt_fwd_id, task->queue_id);
}

static int
dpg_compute_rps(struct dpg_port *port)
{
	int rps, dir;
	const char *port_name;
	double requests, replies, drops, drop_percent;
	char log_buf[DPG_LOG_BUF_SIZE];
	struct dpg_strbuf sb;

	if (!port->pdr) {
		return port->rps_max;
	}

	port->pdr_elapsed++;
	assert(port->pdr_elapsed <= port->pdr_period);

	if (port->pdr_elapsed < port->pdr_period) {
		return port->rps;
	}

	requests = port->pt_requests - port->pt_requests_prev;
	replies = port->pt_replies - port->pt_replies_prev;
	drops = port->pt_drops - port->pt_drops_prev;

	if (replies < requests/2) {
		drop_percent = 100;
	} else {
		drop_percent = 100*(drops/DPG_MAX(requests, replies));
	}

	if (drop_percent > port->pdr_percent) {
		// Significant packet loss
		dir = -1;
		if (port->pdr_step == 0) {
			port->pdr_step = port->rps / 2;
		}
	} else {
		dir = 1;
		if (port->pdr_step == 0) {
			// Slow start
			rps = port->rps * 10;
			goto out;
		}
	}

	// Congestion avoidance
	if (port->pdr_dir == dir) {
		if (dir < 0) {
			port->pdr_step = DPG_MIN(port->pdr_step * 2,
			                         port->rps / 4);
		}
	} else {
		if (dir < 0) {
			port->pdr_step /= 2;
		} else {
			port->pdr_step /= 4;
		}
	}
	port->pdr_dir = dir;
	rps = port->rps + dir * port->pdr_step;

out:
	port->pt_requests_prev = port->pt_requests;
	port->pt_replies_prev = port->pt_replies;
	port->pt_drops_prev = port->pt_drops;
	port->pdr_elapsed = 0;

	rps = DPG_MIN(rps, port->rps_max);
	rps = DPG_MAX(rps, DPG_DEFAULT_PDR_RPS);

	if (rps != port->rps) {
		dpg_strbuf_init(&sb, log_buf, sizeof(log_buf));

		port_name = dpg_get_port_name(port->pt_id);
		dpg_strbuf_addf(&sb, "%s: RPS: ", port_name);
		dpg_strbuf_add_human_readable(&sb, port->rps);
		dpg_strbuf_adds(&sb, "->");
		dpg_strbuf_add_human_readable(&sb, rps);
		dpg_strbuf_adds(&sb, " (step=");
		dpg_strbuf_add_human_readable(&sb, port->pdr_step);
		dpg_strbuf_addf(&sb, ", drops=%.3lf)", drop_percent);

		dpg_strbuf_print(&sb);
	}

	return rps;
}

static void
dpg_set_rps(struct dpg_port *port, int rps)
{
	int rps_per_task, rps_rem;
	struct dpg_task *task;

	assert(rps > 0);

	port->rps = rps;
	rps_per_task = rps/port->n_queues;
	rps_rem = rps % port->n_queues;

	DPG_DLIST_FOREACH(task, &port->task_head, plist) {
		task->rps = rps_per_task + rps_rem;
		rps_rem = 0;
	}
}

static void
dpg_update_rps(struct dpg_port *port)
{
	int rps;

	rps = dpg_compute_rps(port);

	if (port->rps != rps) {
		dpg_set_rps(port, rps);
	}
}

static void
dpg_get_stats(uint64_t *ipps_accum, uint64_t *ibps_accum,
		uint64_t *opps_accum, uint64_t *obps_accum)
{
	int dt, port_id;
	uint64_t ip, ib, op, ob;
	struct rte_eth_stats stats;
	struct dpg_port *port;

	*ipps_accum = 0;
	*ibps_accum = 0;
	*opps_accum = 0;
	*obps_accum = 0;

	DPG_FOREACH_PORT(port, port_id) {
		if (port->software_counters) {
			ip = dpg_counter_get(&port->ipackets);
			ib = dpg_counter_get(&port->ibytes);
			op = dpg_counter_get(&port->opackets);
			ob = dpg_counter_get(&port->obytes);
		} else {
			rte_eth_stats_get(port_id, &stats);

			ip = stats.ipackets;
			ib = stats.ibytes;
			op = stats.opackets;
			ob = stats.obytes;
		}

		if (ip >= port->pt_ipackets_prev) {
			*ipps_accum += ip - port->pt_ipackets_prev;
			port->pt_ipackets_prev = ip;
		}

		if (ib >= port->pt_ibytes_prev) {
			*ibps_accum += 8 * (ib - port->pt_ibytes_prev);
			port->pt_ibytes_prev = ib;
		}

		if (op >= port->pt_opackets_prev) {
			*opps_accum += op - port->pt_opackets_prev;
			port->pt_opackets_prev = op;
		}

		if (ob >= port->pt_obytes_prev) {
			*obps_accum += 8 * (ob - port->pt_obytes_prev);
			port->pt_obytes_prev = ob;
		}

		if (g_dpg_elapsed == g_dpg_omit) {
			port->pt_ipackets_hot = port->pt_ipackets_prev;
			port->pt_ibytes_hot = port->pt_ibytes_prev;
			port->pt_opackets_hot = port->pt_opackets_prev;
			port->pt_obytes_hot = port->pt_obytes_prev;
		}

		if (g_dpg_elapsed + g_dpg_omit == g_dpg_duration) {
			port->Rflag = 0;
			dt = g_dpg_duration - 2 * g_dpg_omit;
			port->pt_ipps = (port->pt_ipackets_prev - port->pt_ipackets_hot)/dt;
			port->pt_ibps = 8 * (port->pt_ibytes_prev - port->pt_ibytes_hot)/dt;
			port->pt_opps = (port->pt_opackets_prev - port->pt_opackets_hot)/dt;
			port->pt_obps = 8 * (port->pt_obytes_prev - port->pt_obytes_hot)/dt;	
		}

		dpg_update_rps(port);
	}
}

static void
dpg_print_report(uint64_t ipps, uint64_t ibps, uint64_t opps, uint64_t obps)
{
	char ipps_b[40], ibps_b[40], opps_b[40], obps_b[40];
	char log_buf[DPG_LOG_BUF_SIZE];
	struct dpg_strbuf sb;
	static int reports;

	dpg_strbuf_init(&sb, log_buf, sizeof(log_buf));

	if (reports % 20 == 0 && (reports == 0 || g_dpg_human_readable)) {
		dpg_strbuf_addf(&sb, "%-12s", "ipps");
		if (g_dpg_bflag) {
			dpg_strbuf_addf(&sb, "%-12s", "ibps");
		}
		dpg_strbuf_addf(&sb, "%-12s", "opps");
		if (g_dpg_bflag) {
			dpg_strbuf_addf(&sb, "%-12s", "obps");
		}
		dpg_strbuf_adds(&sb, "\n");
	}

	dpg_print_human_readable(ipps_b, sizeof(ipps_b), ipps);
	dpg_strbuf_addf(&sb, "%-12s", ipps_b);
	if (g_dpg_bflag) {
		dpg_print_human_readable(ibps_b, sizeof(ibps_b), ibps);
		dpg_strbuf_addf(&sb, "%-12s", ibps_b);
	}
	dpg_print_human_readable(opps_b, sizeof(opps_b), opps);
	dpg_strbuf_addf(&sb, "%-12s", opps_b);
	if (g_dpg_bflag) {
		dpg_print_human_readable(obps_b, sizeof(obps_b), obps);
		dpg_strbuf_addf(&sb, "%-12s", obps_b);
	}
	dpg_strbuf_print(&sb);

	reports++;
}

static void
dpg_update_stats(void)
{
	uint64_t ipps, ibps, opps, obps;

	g_dpg_elapsed++;

	dpg_get_stats(&ipps, &ibps, &opps, &obps);

	if (g_dpg_verbose[DPG_RX] >= 0) {
		dpg_print_report(ipps, ibps, opps, obps);
	}

	if (g_dpg_elapsed == g_dpg_duration) {
		DPG_WRITE_ONCE(g_dpg_done, 1);
	}
}

static void
dpg_print_stat_banner(void)
{
	int i;
	char buf[512];
	struct dpg_strbuf sb;

	dpg_strbuf_init(&sb, buf, sizeof(buf));
	dpg_strbuf_adds(&sb, "ifname");
	for (i = 0; i < g_dpg_oselector_count; ++i) {
		dpg_strbuf_addf(&sb, ",%s", g_dpg_oselector_strings[g_dpg_oselectors[i]]);
	}
	dpg_strbuf_print(&sb);
}

static void
dpg_print_port_stat(struct dpg_port *port)
{
	int i;
	struct rte_eth_stats stats;
	const char *port_name;
	char buf[512];
	struct dpg_strbuf sb;

	rte_eth_stats_get(port->pt_id, &stats);

	dpg_strbuf_init(&sb, buf, sizeof(buf));

	port_name = dpg_get_port_name(port->pt_id);
	dpg_strbuf_adds(&sb, port_name);

	for (i = 0; i < g_dpg_oselector_count; ++i) {
		dpg_strbuf_addch(&sb, ',');
		switch (g_dpg_oselectors[i]) {
		case DPG_OSELECTOR_ipackets:
			dpg_strbuf_add_output(&sb, stats.ipackets);
			break;
		case DPG_OSELECTOR_opackets:
			dpg_strbuf_add_output(&sb, stats.opackets);
			break;
		case DPG_OSELECTOR_ibytes:
			dpg_strbuf_add_output(&sb, stats.ibytes);
			break;
		case DPG_OSELECTOR_obytes:
			dpg_strbuf_add_output(&sb, stats.obytes);
			break;
		case DPG_OSELECTOR_imissed:
			dpg_strbuf_add_output(&sb, stats.imissed);
			break;
		case DPG_OSELECTOR_ierrors:
			dpg_strbuf_add_output(&sb, stats.ierrors);
			break;
		case DPG_OSELECTOR_oerrors:
			dpg_strbuf_add_output(&sb, stats.oerrors);
			break;
		case DPG_OSELECTOR_rx_nombuf:
			dpg_strbuf_add_output(&sb, stats.rx_nombuf);
			break;
		case DPG_OSELECTOR_ipps:
			dpg_strbuf_add_output(&sb, port->pt_ipps);
			break;
		case DPG_OSELECTOR_ibps:
			dpg_strbuf_add_output(&sb, port->pt_ibps);
			break;
		case DPG_OSELECTOR_opps:
			dpg_strbuf_add_output(&sb, port->pt_opps);
			break;
		case DPG_OSELECTOR_obps:
			dpg_strbuf_add_output(&sb, port->pt_obps);
			break;
		case DPG_OSELECTOR_requests:
			dpg_strbuf_add_output(&sb, port->pt_requests);
			break;
		case DPG_OSELECTOR_replies:
			dpg_strbuf_add_output(&sb, port->pt_replies);
			break;
		}
	}
	dpg_strbuf_print(&sb);
}

static void
dpg_sighandler(int signum)
{
	DPG_WRITE_ONCE(g_dpg_done, 1);
}

static int
dpg_lcore_loop(void *dummy)
{
	uint64_t stat_time, tsc;
	struct dpg_lcore *lcore;
	struct dpg_task *task;
	struct dpg_port *port;

	lcore = g_dpg_lcores + rte_lcore_id();

	tsc = rte_rdtsc();
	stat_time = tsc;

	DPG_DLIST_FOREACH(task, &lcore->task_head, llist) {
		task->req_tx_time = tsc;
	}

	while (!DPG_READ_ONCE(g_dpg_done)) {
		lcore->tsc = rte_rdtsc();

		DPG_DLIST_FOREACH(task, &lcore->task_head, llist) {
			port = dpg_port_get(task->port_id);
			if (port->pt_fwd_id == RTE_MAX_ETHPORTS) {
				dpg_do_ping(port, task);
			} else {
				dpg_do_fwd(port, task);
			}
		}

		if (lcore->is_first) {
			tsc = lcore->tsc;
			if (tsc - stat_time >= g_dpg_hz) {
				dpg_update_stats();
				stat_time += g_dpg_hz;
			}
		}
	}

	return 0;
}

int
main(int argc, char **argv)
{
	int i, rc, port_id, n_rxq, n_txq, n_mbufs, main_lcore, first_lcore;
	const char *port_name;
	struct rte_eth_conf port_conf;
	struct rte_eth_dev_info dev_info;
	struct rte_eth_rxconf rxq_conf;
	struct rte_eth_txconf txq_conf;
	struct dpg_port *port;
	struct dpg_lcore *lcore;

	rc = rte_eal_init(argc, argv);
	if (rc < 0) {
		dpg_die("rte_eal_init() failed (%d:%s)\n", -rc, rte_strerror(-rc));
	}

	argc -= rc;
	argv += rc;

#ifdef RTE_LIB_PDUMP
	rte_pdump_init();
#endif

	g_dpg_hz = rte_get_tsc_hz();

	for (i = 0; i < DPG_ARRAY_SIZE(g_dpg_lcores); ++i) {
		lcore = g_dpg_lcores + i;
		dpg_dlist_init(&lcore->task_head);
	}

	memset(&port_conf, 0, sizeof(port_conf));
	port_conf.txmode.mq_mode = DPG_ETH_MQ_TX_NONE;

	while (argc > 1) {
		rc = dpg_parse_port(argc, argv);

		argc -= (rc - 1);
		argv += (rc - 1);
		optind = 1;
	}

	n_mbufs = DPG_MEMPOOL_CACHE_SIZE;

	DPG_FOREACH_PORT(port, port_id) {
		port_name = dpg_get_port_name(port_id);

		dpg_eth_dev_info_get(port_id, &dev_info);

		if (port->pdr && port->n_queues > 1) {
			dpg_die("%s: pdr not implemented for multiqueue mode\n", port_name);
		}

		port->pt_conf = port_conf;
		if (dev_info.tx_offload_capa & DPG_ETH_TX_OFFLOAD_MBUF_FAST_FREE) {
			port->pt_conf.txmode.offloads |= DPG_ETH_TX_OFFLOAD_MBUF_FAST_FREE;
		}
		if (port->n_queues > 1) {
			port->pt_conf.rxmode.mq_mode = DPG_ETH_MQ_RX_RSS;
			port->pt_conf.rx_adv_conf.rss_conf.rss_hf =
					DPG_ETH_RSS_IP | DPG_ETH_RSS_TCP | DPG_ETH_RSS_UDP;

			port->pt_conf.rx_adv_conf.rss_conf.rss_hf &=
					dev_info.flow_type_rss_offloads;
		}

		n_rxq = n_txq = port->n_queues;
		rc = rte_eth_dev_configure(port_id, n_rxq, n_txq, &port->pt_conf);
		if (rc < 0) {
			dpg_die("rte_eth_dev_configure('%s', %d, %d) failed (%d:%s)\n",
					port_name, n_rxq, n_txq,
					-rc, rte_strerror(-rc));
		}

		port->n_rxd = 4096;
		port->n_txd = 4096;
		rc = rte_eth_dev_adjust_nb_rx_tx_desc(port_id, &port->n_rxd, &port->n_txd);
		if (rc < 0) {
			dpg_die("rte_eth_dev_adjust_nb_rx_tx_desc('%s') failed (%d:%s)\n",
					port_name, -rc, rte_strerror(-rc));
		}

		rc = dpg_eth_macaddr_get(port_id, &port->src_eth_addr);
		if (rc < 0) {
			dpg_die("rte_eth_macaddr_get('%s') failed (%d:%s)\n",
					port_name, -rc, rte_strerror(-rc));
		}

		n_mbufs += n_rxq * port->n_rxd;
		n_mbufs += n_txq * (port->n_txd + DPG_MAX_PKT_BURST);
	}

	n_mbufs *= 2;
	n_mbufs = DPG_MAX(n_mbufs, 8192);

	g_dpg_pktmbuf_pool = rte_pktmbuf_pool_create("mbuf_pool", n_mbufs,
			DPG_MEMPOOL_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());

	if (g_dpg_pktmbuf_pool == NULL) {
		dpg_die("rte_pktmbuf_pool_create(%d) failed\n", n_mbufs);
	}

	DPG_FOREACH_PORT(port, port_id) {
		port_name = dpg_get_port_name(port_id);

		dpg_eth_dev_info_get(port_id, &dev_info);

		for (i = 0; i < port->n_queues; ++i) {
			rxq_conf = dev_info.default_rxconf;
			rxq_conf.offloads = port->pt_conf.rxmode.offloads;
			rc = rte_eth_rx_queue_setup(port_id, i, port->n_rxd,
					rte_eth_dev_socket_id(port_id),
					&rxq_conf,
					g_dpg_pktmbuf_pool);
			if (rc < 0) {
				dpg_die("rte_eth_rx_queue_setup('%s', %d, %d) failed (%d:%s)\n",
						port_name, port_id, i, -rc, rte_strerror(-rc));
			}

			txq_conf = dev_info.default_txconf;
			txq_conf.offloads = port->pt_conf.txmode.offloads;
			rc = rte_eth_tx_queue_setup(port_id, i, port->n_txd,
					rte_eth_dev_socket_id(port_id),
					&txq_conf);
			if (rc < 0) {
				dpg_die("rte_eth_tx_queue_setup('%s', %d, %d) failed (%d:%s)\n",
						port_name, port_id, i, -rc, rte_strerror(-rc));
			}
		}

		rc = rte_eth_dev_start(port_id);
		if (rc < 0) {
			dpg_die("rte_eth_dev_start('%s') failed (%d:%s)\n",
					port_name, -rc, rte_strerror(-rc));
		}

		rte_eth_promiscuous_enable(port_id);

		rte_eth_dev_set_link_up(port_id);

		dpg_set_rps(port, port->rps);
	}

	signal(SIGINT, dpg_sighandler);

	main_lcore = rte_lcore_id();
	first_lcore = -1;
	RTE_LCORE_FOREACH(i) {
		lcore = g_dpg_lcores + i;

		if (dpg_dlist_is_empty(&lcore->task_head)) {
			continue;
		}

		if (first_lcore < 0) {
			first_lcore = i;
			lcore->is_first = 1;
		}

		if (i != main_lcore) {
			rte_eal_remote_launch(dpg_lcore_loop, NULL, i);
		}
	}

	lcore = g_dpg_lcores + main_lcore;
	if (!dpg_dlist_is_empty(&lcore->task_head)) {
		dpg_lcore_loop(NULL);
	}

	RTE_LCORE_FOREACH(i) {
		lcore = g_dpg_lcores + i;

		if (dpg_dlist_is_empty(&lcore->task_head)) {
			continue;
		}

		if (i != main_lcore) {
			rte_eal_wait_lcore(i);
		}
	}

#ifdef RTE_LIB_PDUMP
	rte_pdump_uninit();
#endif

	dpg_print_stat_banner();
	DPG_FOREACH_PORT(port, port_id) {
		dpg_print_port_stat(port);
	}

	return 0;
}
