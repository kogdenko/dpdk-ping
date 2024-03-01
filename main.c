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
#define DPG_DEFAULT_NO_DROP false
#define DPG_DEFAULT_NO_DROP_PERCENT 0.2
#define DPG_DEFAULT_NO_DROP_TRIES 30
#define DPG_DEFAULT_NO_DROP_SEQ 10

#define DPG_UDP_DATA_PING "ping"
#define DPG_UDP_DATA_PONG "pong"

#define DPG_LOG_BUFSIZE 512

#define DPG_NO_DROP_RPS_MIN 5

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

//	uint32_t upper_size;
//	uint32_t upper_mask;
};

struct dpg_eth_hdr {
	dpg_eth_addr_t dst_addr;
	dpg_eth_addr_t src_addr;
	uint16_t eth_type;
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

	struct dpg_iterator session_field[DPG_SESSION_FIELD_MAX];

	struct dpg_dlist session_field_head;

	int tx_bytes;
	int n_tx_pkts;
	struct rte_mbuf *tx_pkts[DPG_TXBUF_SIZE];
};

struct dpg_port {
	dpg_eth_addr_t src_eth_addr;
	dpg_eth_addr_t dst_eth_addr;

	bool Rflag;
	bool Eflag;

	uint8_t verbose[2];

	uint16_t pkt_len;
	uint8_t proto;

	struct dpg_container addresses4;
	struct dpg_container addresses6;

	struct dpg_container session_field[DPG_SESSION_FIELD_MAX];

	int srv6;
	uint8_t srv6_src[DPG_IPV6_ADDR_SIZE];

	int id;

	int rps_max;
	int rps_cur;
	int rps_lo;
	int rps_step;
	uint8_t rps_seq;
	uint8_t rps_tries;

	bool rand;
	uint32_t rand_seed;
	uint32_t rand_session_count;

	bool software_counters;
	struct dpg_counter ipackets;
	struct dpg_counter opackets;
	struct dpg_counter ibytes;
	struct dpg_counter obytes;

	uint64_t ipackets_prev;
	uint64_t opackets_prev;
	uint64_t ibytes_prev;
	uint64_t obytes_prev;

	struct dpg_dlist task_head;

	struct dpg_dlist session_field_head;

	bool no_drop;
	double no_drop_percent;
	u_int no_drop_tries;
	u_int no_drop_seq;

	uint16_t n_rxd;
	uint16_t n_txd;
	int n_queues;

	struct rte_eth_conf conf;
};

struct dpg_lcore {
	struct dpg_dlist task_head;
	uint64_t tsc;
	int is_first;
};

static volatile int g_dpg_done;
static uint64_t g_dpg_hz;
static struct dpg_port *g_dpg_ports[RTE_MAX_ETHPORTS];
static struct dpg_lcore g_dpg_lcores[RTE_MAX_LCORE];
static struct rte_mempool *g_dpg_pktmbuf_pool;
static bool g_dpg_bflag;

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

#define dpg_dbg(f, ...) do { \
	printf("%u: ", __LINE__); \
	printf(f, ##__VA_ARGS__); \
	printf("\n"); \
} while (0)

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

/*
static void *
dpg_xmemdup(void *ptr, int size)
{
	void *cp;

	cp = dpg_xmalloc(size);
	memcpy(cp, ptr, size);
	return cp;
}
*/

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

static void
dpg_container_array_init(struct dpg_container *ct)
{
	dpg_darray_init(&ct->array, sizeof(dpg_uint128_t));

	ct->get = dpg_container_array_get;
	ct->find = dpg_container_array_find;
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

static void
dpg_container_interval_init(struct dpg_container *ct)
{
	ct->get = dpg_container_interval_get;
	ct->find = dpg_container_interval_find;
}

static dpg_uint128_t
dpg_container_get(struct dpg_container *ct, dpg_uint128_t i)
{
	assert(ct->size);
	return (*ct->get)(ct, i);
}

static bool
dpg_container_find(struct dpg_container *ct, dpg_uint128_t val)
{
	return (*ct->find)(ct, val);
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
		dpg_container_array_init(ct);

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

		dpg_container_interval_init(ct);

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
dpg_parse_bool(char *str, bool *pb)
{
	int b;
	char *endptr;

	b = strtoul(str, &endptr, 10);
	if (*endptr == '\0') {
		if (b != 0 && b != 1) {
			return -EINVAL;
		} else {
			*pb = b ? true : false;
			return 0;
		}
	}
	if (!strcasecmp(str, "on") || !strcasecmp(str, "yes")) {
		*pb = true;
		return 0;
	} else if (!strcasecmp(str, "off") || !strcasecmp(str, "no")) {
		*pb = false;
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
	char port_name[RTE_ETH_NAME_MAX_LEN];

	rc = rte_eth_dev_info_get(port_id, dev_info);
	if (rc < 0) {
		rte_eth_dev_get_name_by_port(port_id, port_name);
		dpg_die("rte_eth_dev_info_get('%s') failed (%d:%s)\n",
				port_name, -rc, rte_strerror(-rc));
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

static void
dpg_argument_not_specified(int short_name, const char *long_name)
{
	if (long_name != NULL) {
		dpg_die("Argument '--%s' not specified\n", long_name);
	} else {
		dpg_die("Argument '-%c' not specified\n", short_name);
	}
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
	pseudo.len = rte_cpu_to_be_16(len);
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

static void
dpg_print_human_readable5(char *buf, size_t count, double val, char *fmt, int normalize)
{
	static const char *units[] = { "", "k", "m", "g", "t" };
	int i;

	if (normalize) {
		for (i = 0; val >=1000 && i < DPG_ARRAY_SIZE(units) - 1; i++) {
			val /= 1000;
		}
	} else {
		i = 0;
	}

	snprintf(buf, count, fmt, val, units[i]);
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

static void
dpg_print_human_readable(char *buf, size_t count, double val, int normalize)
{
	if (normalize) {
		dpg_print_human_readable5(buf, count, val, "%.3f%s", normalize);
	} else {
		dpg_print_human_readable5(buf, count, val, "%.0f%s", normalize);
	}
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
dpg_log_rxtx(struct dpg_strbuf *sb,  struct dpg_task *task, struct dpg_eth_hdr *eh, int dir)
{
	char port_name[RTE_ETH_NAME_MAX_LEN];
	char shbuf[DPG_ETH_ADDRSTRLEN];
	char dhbuf[DPG_ETH_ADDRSTRLEN];
	struct dpg_port *port;

	port = dpg_port_get(task->port_id);

	dpg_strbuf_adds(sb, dir == DPG_RX ? "RX ": "TX ");

	rte_eth_dev_get_name_by_port(port->id, port_name);
	dpg_strbuf_adds(sb, port_name);
	dpg_strbuf_adds(sb, " ");
	if (dir != DPG_RX || port->verbose[DPG_RX] < 1) {
		return;
	}
	if (port->n_queues > 1) {
		dpg_strbuf_addf(sb, "(q=%d) ", task->queue_id);
	}

//	if (eh != NULL) {
	dpg_eth_format_addr(shbuf, sizeof(shbuf), &eh->src_addr);
	dpg_eth_format_addr(dhbuf, sizeof(dhbuf), &eh->dst_addr);
	dpg_strbuf_addf(sb, "%s->%s ", shbuf, dhbuf);
}

static void
dpg_log_packet(struct dpg_task *task, int dir, struct dpg_eth_hdr *eh, struct dpg_ipv6_hdr *ih6,
		struct dpg_ipv4_hdr *ih, void *l4_hdr)
{
	char sabuf[INET6_ADDRSTRLEN];
	char dabuf[INET6_ADDRSTRLEN];
	char logbuf[DPG_LOG_BUFSIZE];
	struct dpg_strbuf sb;
	struct dpg_port *port;
	struct dpg_icmp_hdr *ich;
	struct dpg_udp_hdr *uh;

	port = dpg_port_get(task->port_id);
	if (!port->verbose[dir]) {
		return;
	}

	dpg_strbuf_init(&sb, logbuf, sizeof(logbuf));

	dpg_log_rxtx(&sb, task, eh, dir);

	if (ih6 != NULL) {
		inet_ntop(AF_INET6, &ih6->src_addr, sabuf, sizeof(sabuf));
		inet_ntop(AF_INET6, &ih6->dst_addr, dabuf, sizeof(dabuf));
		dpg_strbuf_addf(&sb, "%s->%s\n\t", sabuf, dabuf);
	}

	inet_ntop(AF_INET, &ih->src_addr, sabuf, sizeof(sabuf));
	inet_ntop(AF_INET, &ih->dst_addr, dabuf, sizeof(dabuf));

	switch (ih->next_proto_id) {
	case IPPROTO_ICMP:
		ich = l4_hdr;
		dpg_strbuf_addf(&sb, "ICMP echo %s: %s->%s, id=%d, seq=%d",
				dpg_icmp_type_string(ich->icmp_type),
				sabuf, dabuf,
				rte_be_to_cpu_16(ich->icmp_ident),
				rte_be_to_cpu_16(ich->icmp_seq_nb));
		break;

	case IPPROTO_UDP:
		uh = l4_hdr;
		dpg_strbuf_addf(&sb, "UDP %s:%hu->%s:%hu",
				sabuf, rte_be_to_cpu_16(uh->src_port),
				dabuf, rte_be_to_cpu_16(uh->dst_port));
		break;
	}

	printf("%s\n", dpg_strbuf_cstr(&sb));
}

static void
dpg_log_arp(struct dpg_task *task, int dir, struct dpg_eth_hdr *eh, struct dpg_arp_hdr *ah)
{
	int is_req;
	char tibuf[INET_ADDRSTRLEN];
	char sibuf[INET_ADDRSTRLEN];
	char thbuf[DPG_ETH_ADDRSTRLEN];
	char shbuf[DPG_ETH_ADDRSTRLEN];
	char logbuf[DPG_LOG_BUFSIZE];
	struct dpg_strbuf sb;
	struct dpg_port *port;

	port = dpg_port_get(task->port_id);
	if (!port->verbose[dir]) {
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

	printf("%s\n", dpg_strbuf_cstr(&sb));
}

static void
dpg_log_ipv6(struct dpg_task *task, int dir, struct dpg_eth_hdr *eh, struct dpg_ipv6_hdr *ih,
		const char *desc)
{
	char srcbuf[INET6_ADDRSTRLEN];
	char dstbuf[INET6_ADDRSTRLEN];
	char logbuf[DPG_LOG_BUFSIZE];
	struct dpg_strbuf sb;
	struct dpg_port *port;

	port = dpg_port_get(task->port_id);
	if (!port->verbose[dir]) {
		return;
	}

	dpg_strbuf_init(&sb, logbuf, sizeof(logbuf));

	dpg_log_rxtx(&sb, task, eh, dir);

	inet_ntop(AF_INET6, ih->src_addr, srcbuf, sizeof(srcbuf));
	inet_ntop(AF_INET6, ih->dst_addr, dstbuf, sizeof(dstbuf));

	dpg_strbuf_addf(&sb, ": %s->%s: %s", srcbuf, dstbuf, desc);

	printf("%s\n", dpg_strbuf_cstr(&sb));
}

static void
dpg_log_custom(struct dpg_task *task, struct dpg_eth_hdr *eh, const char *proto)
{
	char logbuf[DPG_LOG_BUFSIZE];
	struct dpg_strbuf sb;
	struct dpg_port *port;

	port = dpg_port_get(task->port_id);
	if (!port->verbose[DPG_RX]) {
		return;
	}

	dpg_strbuf_init(&sb, logbuf, sizeof(logbuf));

	dpg_log_rxtx(&sb, task, eh, DPG_RX);

	dpg_strbuf_addf(&sb, ": %s packet", proto);

	printf("%s\n", dpg_strbuf_cstr(&sb));
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

static struct dpg_port *
dpg_create_port(void)
{
	int i;
	struct dpg_port *port;

	port = dpg_xmalloc(sizeof(*port));
	memset(port, 0, sizeof(*port));
	port->id = RTE_MAX_ETHPORTS;
	port->rps_max = DPG_DEFAULT_RPS;
	port->pkt_len = DPG_DEFAULT_PKT_LEN;
	port->proto = IPPROTO_ICMP;

	port->no_drop = DPG_DEFAULT_NO_DROP;
	port->no_drop_percent = DPG_DEFAULT_NO_DROP_PERCENT;
	port->no_drop_tries = DPG_DEFAULT_NO_DROP_TRIES;
	port->no_drop_seq = DPG_DEFAULT_NO_DROP_SEQ;

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

	task->port_id = port->id;
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
dpg_print_usage(void)
{
	int rc, port_id;
	dpg_eth_addr_t mac_addr;
	char rate_buf[32];
	char eth_addr_buf[DPG_ETH_ADDRSTRLEN];
	char port_name[RTE_ETH_NAME_MAX_LEN];

	dpg_print_human_readable(rate_buf, sizeof(rate_buf), DPG_DEFAULT_RPS, 1);

	printf("Usage: dpdk-ping [DPDK options] -- port options [-- port options ...]\n"
	"\n"
	"Port options:\n"
	"\t-h|--help:  Print this help\n"
	"\t-V {level}:  Be verbose (default: 0)\n"
	"\t-b {bool}:  Print bits/sec in report (default: %s)\n"
	"\t-l {lcore id..}:  Lcores to run on\n"
	"\t-p {port name}:  Port to run on\n"
	"\t-R {bool}:  Send ICMP echo requests (default: %s)\n"
	"\t-E {bool}:  Send ICMP echo reply on incoming ICMP echo requests (default: %s)\n"
	"\t-4 {IP..}:  Interaface IP address iterator\n"
	"\t-6 {IPv6..}:  Interface IPv6 address iterator\n"
	"\t-B {packets per second}:  ICMP requests bandwidth (default:%s)\n"
	"\t-H {ether address}:  Destination ethernet address (default: ff:ff:ff:ff:ff:ff)\n"
	"\t-s {IP..}:  Source ip addresses iterator (default: %s)\n"
	"\t-d {IP..}:  Destination ip addresses iterator (default: %s)\n"
	"\t-S {port..}:  Source port iterator (default: %s)\n"
	"\t-D {port..}:  Destination port iterator (default: %s)\n"
	"\t-L {bytes}:  Packet size (default: %d)\n"
	"\t--rx-verbose {level}:  Be verbose on rx path (default: %d)\n"
	"\t--tx-verbose {level}:  Be verbose on tx path (default: %d)\n"
	"\t--icmp-id {id..}:  ICMP request id iterator (default: %s)\n"
	"\t--icmp-seq {seq..}:  ICMP request sequence iterator (default: %s)\n"
	"\t--srv6-src {IPv6}:  SRv6 tunnel source address\n"
	"\t--srv6-dst {IPv6..}:  SRv6 tunnel destination address iterator\n"
	"\t--software-counters {bool}:  Use software counters for reports (default: %s)\n"
	"\t--no-drop {%%[,T[,t]]}:  Specify no-drop rate search algorithm parameters (default: %f,%u,%u)\n"
	"\tIterator of values x (x..):  {x,x,x...|x-x}\n"
	"Ports:\n",
		dpg_bool_str(g_dpg_bflag),
		dpg_bool_str(false),
		dpg_bool_str(false),
		rate_buf,
		DPG_DEFAULT_SRC_IP,
		DPG_DEFAULT_DST_IP,
		DPG_DEFAULT_SRC_PORT,
		DPG_DEFAULT_DST_PORT,
		DPG_DEFAULT_PKT_LEN,
		0,
		0,
		DPG_DEFAULT_ICMP_ID,
		DPG_DEFAULT_ICMP_SEQ,
		dpg_bool_str(DPG_DEFAULT_NO_DROP),
		DPG_DEFAULT_NO_DROP_PERCENT,
		DPG_DEFAULT_NO_DROP_TRIES,
		DPG_DEFAULT_NO_DROP_SEQ
	);

	RTE_ETH_FOREACH_DEV(port_id) {
		rte_eth_dev_get_name_by_port(port_id, port_name);
		printf("%s", port_name);

		rc = dpg_eth_macaddr_get(port_id, &mac_addr);
		if (rc == 0) {
			dpg_eth_format_addr(eth_addr_buf, sizeof(eth_addr_buf), &mac_addr);
			printf("  %s", eth_addr_buf);
		}
		printf("\n");
	}

	rte_exit(EXIT_SUCCESS, "\n");
}

static int
dpg_parse_port(int argc, char **argv)
{
	int i, opt, option_index;
	int64_t rc;
	uint16_t port_id, lcore_id;
	char *endptr;
	const char *optname;
	struct dpg_port *port;
	struct dpg_container lcores;
	struct dpg_container *ct;

	static struct option long_options[] = {
		{ "help", no_argument, 0, 'h' },
		{ "rx-verbose", required_argument, 0, 0 },
		{ "tx-verbose", required_argument, 0, 0 },
		{ "udp", no_argument, 0, 0 },
		{ "icmp", no_argument, 0, 0 },
		{ "icmp-id", required_argument, 0, 0 },
		{ "icmp-seq", required_argument, 0, 0 },
		{ "srv6-src", required_argument, 0, 0 },
		{ "srv6-dst", required_argument, 0, 0 },
		{ "software-counters", required_argument, 0, 0 },
		{ "no-drop",  required_argument, 0, 0 },
		{ "rand", no_argument, 0, 0 },
		{ "rand-seed", required_argument, 0, 0 },
		{ "rand-sessions", required_argument, 0, 0 },
		{ NULL, 0, 0, 0 },
	};

	memset(&lcores, 0, sizeof(lcores));

	port = dpg_create_port();

	while ((opt = getopt_long(argc, argv, "hV:b:l:p:R:E:4:6:B:H:s:d:S:D:L:",
			long_options, &option_index)) != -1) {
		switch (opt) {
		case 0:
			optname = long_options[option_index].name;
			if (!strcmp(optname, "rx-verbose")) {
				port->verbose[DPG_RX] = strtoul(optarg, NULL, 10);
			} else if (!strcmp(optname, "tx-verbose")) {
				port->verbose[DPG_TX] = strtoul(optarg, NULL, 10);
			} else if (!strcmp(optname, "udp")) {
				port->proto = IPPROTO_UDP;
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
				rc = dpg_parse_bool(optarg, &port->software_counters);
				if (rc < 0) {
					dpg_invalid_argument(0, optname);
				}
			} else if (!strcmp(optname, "no-drop")) {
				rc = sscanf(optarg, "%lf,%u,%u",
						&port->no_drop_percent,
						&port->no_drop_tries,
						&port->no_drop_seq);
				if (rc == 0 || rc == EOF) {
					dpg_invalid_argument(0, optname);
				} else if (rc == 2) {
					port->no_drop_seq = DPG_MAX(1, port->no_drop_tries / 3);
				}

				if (port->no_drop_percent <= 0 || port->no_drop_percent >= 100) {
					dpg_invalid_argument(0, optname);
				}

				if (port->no_drop_tries < 2 ||
				    port->no_drop_tries < port->no_drop_seq) {
					dpg_invalid_argument(0, optname);
				}

				port->no_drop = true;
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
			}
			break;

		case 'h':
			dpg_print_usage();
			break;

		case 'V':
			port->verbose[DPG_RX] = port->verbose[DPG_TX] = strtoul(optarg, NULL, 10);
			break;

		case 'b':
			rc = dpg_parse_bool(optarg, &g_dpg_bflag);
			if (rc < 0) {
				dpg_invalid_argument(opt, NULL);
			}
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
			if (port->id != RTE_MAX_ETHPORTS) {
				break;
			}
			rc = rte_eth_dev_get_port_by_name(optarg, &port_id);
			if (rc < 0) {
				dpg_die("DPDK doesn't run on port '%s'\n", optarg);		
			}

			if (g_dpg_ports[port_id] == NULL) {
				port->id = port_id;
				g_dpg_ports[port->id] = port;
			}
			break;

		case 'R':
			rc = dpg_parse_bool(optarg, &port->Rflag);
			if (rc < 0) {
				dpg_invalid_argument(opt, NULL);
			}
			break;

		case 'E':
			rc = dpg_parse_bool(optarg, &port->Eflag);
			if (rc < 0) {
				dpg_invalid_argument(opt, NULL);
			}
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

		default:
			dpg_die("Unknown argument: '-%c'\n", opt);
			break;
		}
	}

	if (optind < argc && strcmp(argv[optind - 1], "--")) {
		dpg_die("Unknown input: '%s'\n", argv[optind]);
	}

	if (port->id == RTE_MAX_ETHPORTS) {
		dpg_argument_not_specified('p', NULL);
	}

	if (!lcores.size) {
		dpg_argument_not_specified('l', NULL);
	}
	port->n_queues = lcores.size;

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

	for (i = 0; i < lcores.size; ++i) {
		lcore_id = dpg_container_get(&lcores, i);
		dpg_create_task(port, lcore_id, i);
	}

	return optind;
}

static void
dpg_set_eth_hdr_addresses(struct dpg_port *port, struct dpg_eth_hdr *eh)
{
	eh->dst_addr = port->dst_eth_addr;
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
		r = dpg_rand_xorshift(&task->rand_state);
		DPG_DLIST_FOREACH(it, &task->session_field_head, list) {
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
	struct dpg_udp_hdr *uh;
	struct dpg_srv6_hdr *srh;
	struct dpg_port *port;
	struct dpg_iterator *field;

	port = dpg_port_get(task->port_id);

	m = rte_pktmbuf_alloc(g_dpg_pktmbuf_pool);
	if (m == NULL) {
		dpg_die("rte_pktmbuf_alloc() failed\n");
	}

	eh = rte_pktmbuf_mtod(m, struct dpg_eth_hdr *);

	m->pkt_len = sizeof(*eh) + sizeof(*ih);
	switch (port->proto) {
	case IPPROTO_ICMP:
		m->pkt_len += sizeof(*ich);
		break;

	default:
		// UDP
		m->pkt_len += sizeof(*uh) + sizeof(DPG_UDP_DATA_PING);
		break;
	}

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
		ih6->payload_len = rte_cpu_to_be_16(m->pkt_len - (sizeof(*eh) + sizeof(*ih6)));
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

	dpg_set_eth_hdr_addresses(port, eh);

	ih->version = 4;
	ih->ihl = sizeof(*ih) / sizeof(uint32_t);
	ih->type_of_service = 0;
	ih->total_length = rte_cpu_to_be_16(ih_total_length);
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
		ich->icmp_ident = rte_cpu_to_be_16(icmp_id);

		field = task->session_field + DPG_SESSION_ICMP_SEQ;
		icmp_seq = dpg_iterator_get(field);
		ich->icmp_seq_nb = rte_cpu_to_be_16(icmp_seq);

		ich->icmp_cksum = dpg_cksum(ich, ih_total_length - sizeof(*ih));
		break;

	default:
		// UDP
		uh = (struct dpg_udp_hdr *)(ih + 1);

		field = task->session_field + DPG_SESSION_SRC_PORT;
		src_port = dpg_iterator_get(field);
		uh->src_port = rte_cpu_to_be_16(src_port);

		field = task->session_field + DPG_SESSION_DST_PORT;
		dst_port = dpg_iterator_get(field);
		uh->dst_port = rte_cpu_to_be_16(dst_port);

		uh->dgram_len = rte_cpu_to_be_16(ih_total_length - sizeof(*ih));
		uh->dgram_cksum = 0;
		memcpy(uh + 1, DPG_UDP_DATA_PING, sizeof(DPG_UDP_DATA_PING));
		uh->dgram_cksum = dpg_ipv4_udp_cksum(ih, uh, ih_total_length - sizeof(*ih));
		break;
	}

	dpg_next_session(task);

	dpg_log_packet(task, DPG_TX, NULL, ih6, ih, ih + 1);

	return m;
}

static int
dpg_ip_input(struct dpg_task *task, struct dpg_eth_hdr *eh, struct dpg_ipv6_hdr *ih6,
		void *ptr, int len)
{
	int hl, ih_total_length;
	void *l4_hdr;
	struct dpg_ipv4_hdr *ih;
	struct dpg_icmp_hdr *ich;
	struct dpg_udp_hdr *uh;
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

	ih_total_length = rte_be_to_cpu_16(ih->total_length);

	if (ih_total_length > len) {
		return -EINVAL;
	}

	l4_hdr = (uint8_t *)ih + hl;

	dpg_log_packet(task, DPG_RX, eh, ih6, ih, l4_hdr);

	if (!port->Eflag || ih6 != NULL) {
		return -ENOTSUP;
	}

	switch (ih->next_proto_id) {
	case IPPROTO_ICMP:
		if (ih_total_length < hl + sizeof(*ich)) {
			return -EINVAL;
		}

		ich = (struct dpg_icmp_hdr *)l4_hdr;

		if (ich->icmp_type != DPG_IP_ICMP_ECHO_REQUEST) {
			return -ENOTSUP;
		}

		ich->icmp_type = DPG_IP_ICMP_ECHO_REPLY;
		DPG_SWAP(ih->src_addr, ih->dst_addr);

		ich->icmp_cksum = 0;
		ich->icmp_cksum = dpg_cksum(ich, ih_total_length - hl);
		break;

	case IPPROTO_UDP:
		if (ih_total_length < hl + sizeof(*uh)) {
			return -EINVAL;
		}

		if (ih_total_length < hl + sizeof(*uh) + sizeof(DPG_UDP_DATA_PING)) {
			return -ENOTSUP;
		}

		uh = (struct dpg_udp_hdr *)l4_hdr;
	
		if (memcmp(uh + 1, DPG_UDP_DATA_PING, sizeof(DPG_UDP_DATA_PING))) {
			return -ENOTSUP;
		}

		DPG_SWAP(uh->src_port, uh->dst_port);
		memcpy(uh + 1, DPG_UDP_DATA_PONG, sizeof(DPG_UDP_DATA_PONG));
		uh->dgram_cksum = 0;
		uh->dgram_cksum = dpg_ipv4_udp_cksum(ih, uh, ih_total_length - hl);
		break;

	default:
		return -ENOTSUP;
	}

	DPG_SWAP(ih->src_addr, ih->dst_addr);
	ih->hdr_checksum = 0;
	ih->hdr_checksum = dpg_cksum(ih, hl);

	dpg_log_packet(task, DPG_TX, NULL, ih6, ih, l4_hdr);

	return 0;
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

	ih->payload_len = rte_cpu_to_be_16(len);
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
	int rc, hl, len, proto;
	uint8_t *ptr;
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

	if (m->pkt_len < sizeof(*eh) + sizeof(*ih6)) {
		goto malformed;
	}

	len = rte_be_to_cpu_16(ih6->payload_len);
	if (m->pkt_len < sizeof(*eh) + sizeof(*ih6) + len) {
		goto malformed;
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

			if (port->verbose[DPG_RX]) {
				inet_ntop(AF_INET6, ns->target, tgtbuf, sizeof(tgtbuf));
				snprintf(desc, sizeof(desc), "Neighbour Solicitation (target=%s)",
						tgtbuf);
				dpg_log_ipv6(task, DPG_RX, eh, ih6, desc);
			}

			target = dpg_ipv6_to_uint128(ns->target);
			rc = dpg_container_find(&port->addresses6, target);
			if (!rc) {
				return -EINVAL;
			}

			dpg_create_neighbour_advertisment(port, m, ih6, ns);

			dpg_log_ipv6(task, DPG_TX, NULL, ih6, "Neighbour Advertisment");

			return 0;

		case IPPROTO_IPIP:
			rc = dpg_ip_input(task, eh, ih6, ptr, len);
			if (rc == -EINVAL) {
				goto out;
			}
			return -EINVAL;

		default:
			goto out;
		}
	}

out:
	if (port->verbose[DPG_RX]) {
		snprintf(desc, sizeof(desc), "proto %d", proto);
		dpg_log_ipv6(task, DPG_RX, eh, ih6, desc);
	}
	return -EINVAL;

malformed:
	dpg_log_custom(task, eh, "Malformed IPv6");
	return -EINVAL;
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

	if (ah->arp_opcode != RTE_BE16(DPG_ARP_OP_REQUEST)) {
		return -EINVAL;
	}

	ah->arp_opcode = RTE_BE16(DPG_ARP_OP_REPLY);
	ah->arp_tha = port->dst_eth_addr;
	ah->arp_sha = port->src_eth_addr;
	DPG_SWAP(ah->arp_tip, ah->arp_sip);

	dpg_log_arp(task, DPG_TX, NULL, ah);

	return 0;
}

static void
dpg_add_tx(struct dpg_task *task, struct rte_mbuf *m)
{
	task->tx_bytes += m->pkt_len;
	task->tx_pkts[task->n_tx_pkts++] = m;
}

static int
dpg_rps_ratelimit(struct dpg_task *task, int rate)
{
	int n_reqs, room, dp;
	uint64_t tsc, dt;

	if (rate == 0) {
		return 0;
	}

	room = DPG_TXBUF_SIZE - task->n_tx_pkts;

	tsc = dpg_rdtsc();
	dt = tsc - task->req_tx_time;

	dp = rate * dt / g_dpg_hz;

	n_reqs = DPG_MIN(dp, room);

	task->req_tx_time += n_reqs * g_dpg_hz / rate;

	return n_reqs;
}

static void
dpg_do_task(struct dpg_task *task)
{
	int i, rc, n_rx, n_reqs, room, txed, rx_bytes, tx_bytes;
	char proto[32];
	struct dpg_eth_hdr *eh;
	struct dpg_port *port;
	struct rte_mbuf *m, *rx_pkts[DPG_MAX_PKT_BURST];

	port = dpg_port_get(task->port_id);

	rx_bytes = 0;
	n_rx = rte_eth_rx_burst(task->port_id, task->queue_id, rx_pkts, DPG_ARRAY_SIZE(rx_pkts));

	for (i = 0; i < n_rx; ++i) {
		m = rx_pkts[i];
		eh = rte_pktmbuf_mtod(m, struct dpg_eth_hdr *);
		rx_bytes += m->data_len;
		if (m->pkt_len < sizeof(*eh)) {
			goto drop;
		}

		switch (eh->eth_type) {
		case RTE_BE16(DPG_ETH_TYPE_IPV4):
			rc = dpg_ip_input(task, eh, NULL, eh + 1, m->pkt_len - sizeof(*eh));
			if (rc == -EINVAL) {
				dpg_log_custom(task, eh, "IP");
			}
			if (rc < 0) {
				goto drop;
			}
			break;

		case RTE_BE16(DPG_ETH_TYPE_IPV6):
			rc = dpg_ipv6_input(task, m);
			if (rc < 0) {
				goto drop;
			}
			break;
		
		case RTE_BE16(DPG_ETH_TYPE_ARP):
			rc = dpg_arp_input(task, m);
			if (rc < 0) {
				goto drop;
			}
			break;

		default:
			if (port->verbose[DPG_RX]) {
				snprintf(proto, sizeof(proto), "proto 0x%04hx",
						rte_be_to_cpu_16(eh->eth_type));
				dpg_log_custom(task, eh, proto);
			}
			goto drop;
		}

		dpg_set_eth_hdr_addresses(port, eh);

		if (task->n_tx_pkts < DPG_TXBUF_SIZE) {
			dpg_add_tx(task, m);
			continue;
		}
drop:
		rte_pktmbuf_free(m);
	}

	room = DPG_TXBUF_SIZE - task->n_tx_pkts;
	if (port->Rflag && room) {
		if (task->rps == 0) {
			n_reqs = 0;
		} else if (task->rps > 0) {
			n_reqs = dpg_rps_ratelimit(task, task->rps);
		} else {
			n_reqs = room;
		}

		for (i = 0; i < n_reqs; ++i) {
			m = dpg_create_request(task);
			dpg_add_tx(task, m);
		}
	}

	if (task->n_tx_pkts) {
		txed = rte_eth_tx_burst(task->port_id, task->queue_id, task->tx_pkts, task->n_tx_pkts);
		memmove(task->tx_pkts, task->tx_pkts + txed,
				(task->n_tx_pkts - txed) * sizeof (struct rte_mbuf *));
		task->n_tx_pkts -= txed;
	} else {
		txed = 0;
	}

	if (port->software_counters) {
		tx_bytes = task->tx_bytes;
		task->tx_bytes = 0;

		for (i = 0; i < task->n_tx_pkts; ++i) {
			task->tx_bytes += task->tx_pkts[i]->pkt_len;
		}

		port = g_dpg_ports[task->port_id];

		dpg_counter_add(&port->ipackets, n_rx);
		dpg_counter_add(&port->ibytes, rx_bytes);

		dpg_counter_add(&port->opackets, txed);
		dpg_counter_add(&port->obytes, tx_bytes - task->tx_bytes);
	}
}

static int
dpg_compute_rps(struct dpg_port *port, uint64_t ipps, uint64_t opps)
{
	int rps;
	char port_name[RTE_ETH_NAME_MAX_LEN];
	char rps_buf[32], rps_prev_buf[32], rps_lo_buf[32], rps_step_buf[32];

	if (port->rps_max <= DPG_NO_DROP_RPS_MIN || !port->no_drop) {
		return port->rps_max;
	}

	if (port->rps_cur < DPG_NO_DROP_RPS_MIN) {
		return DPG_NO_DROP_RPS_MIN;
	}

	port->rps_tries++;

	if (ipps + 1 >= opps ||  (opps - ipps) < port->no_drop_percent * opps / 100) {
		port->rps_seq++;
	} else {
		port->rps_seq = 0;
	}

	rps = port->rps_cur;
	
	if (port->rps_seq == port->no_drop_seq) {
		port->rps_seq = port->rps_tries = 0;

		port->rps_lo = port->rps_cur;
		if (port->rps_step == 0) {
			rps = port->rps_cur * 10;
		} else {
			port->rps_step *= 2;
			rps = port->rps_lo + port->rps_step;
		}
	} else if (port->rps_tries == port->no_drop_tries) {
		port->rps_seq = port->rps_tries = 0;

		if (port->rps_step == 0) {
			port->rps_step = port->rps_lo;
		} else {
			port->rps_step /= 2;
		}
		rps = port->rps_lo + port->rps_step;
	}

	rps = DPG_MIN(rps, port->rps_max);

	if (rps != port->rps_cur) {
		rte_eth_dev_get_name_by_port(port->id, port_name);

		dpg_print_human_readable(rps_prev_buf, sizeof(rps_prev_buf), port->rps_cur, 1);
		dpg_print_human_readable(rps_buf, sizeof(rps_buf), rps, 1);
		dpg_print_human_readable(rps_lo_buf, sizeof(rps_lo_buf), port->rps_lo, 1);
		dpg_print_human_readable(rps_step_buf, sizeof(rps_step_buf), port->rps_step, 1);

		printf("%s: RPS: %s->%s (lo=%s, step=%s)\n",
				port_name, rps_prev_buf, rps_buf, rps_lo_buf, rps_step_buf);
	}

	return rps;
}

static void
dpg_update_rps(struct dpg_port *port, uint64_t ipps, uint64_t opps)
{
	int rps_per_task, rps_rem, rps_cur;
	struct dpg_task *task;

	rps_cur = dpg_compute_rps(port, ipps, opps);

	if (port->rps_cur == rps_cur) {
		return;
	}

	port->rps_cur = rps_cur;
	rps_per_task = rps_cur/port->n_queues;
	rps_rem = rps_cur % port->n_queues;

	DPG_DLIST_FOREACH(task, &port->task_head, plist) {
		task->rps = rps_per_task + rps_rem;
		rps_rem = 0;
	}
}

static void
dpg_get_stats(uint64_t *ipps_accum, uint64_t *ibps_accum,
		uint64_t *opps_accum, uint64_t *obps_accum)
{
	int port_id;
	uint64_t ip, ib, op, ob;
	uint64_t ipps, ibps, opps, obps;
	struct rte_eth_stats stats;
	struct dpg_port *port;

	*ipps_accum = 0;
	*ibps_accum = 0;
	*opps_accum = 0;
	*obps_accum = 0;

	RTE_ETH_FOREACH_DEV(port_id) {
		port = g_dpg_ports[port_id];

		if (!dpg_port_is_configured(port)) {
			continue;
		}

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

		ipps = ip - port->ipackets_prev;
		port->ipackets_prev = ip;

		ibps = ib - port->ibytes_prev;
		port->ibytes_prev = ib;

		opps = op - port->opackets_prev;
		port->opackets_prev = op;

		obps = ob - port->obytes_prev;
		port->obytes_prev = ob;

		dpg_update_rps(port, ipps, opps);

		*ipps_accum += ipps;
		*ibps_accum += ibps;
		*opps_accum += opps;
		*obps_accum += obps;
	}
}

static void
dpg_print_report(double d_tsc)
{
	uint64_t ipps, ibps, opps, obps;
	char ipps_b[40], ibps_b[40], opps_b[40], obps_b[40];
	static int reports;

	dpg_get_stats(&ipps, &ibps, &opps, &obps);

	if (reports == 20) {
		reports = 0;
	}
	if (reports == 0) {
		printf("%-12s", "ipps");
		if (g_dpg_bflag) {
			printf("%-12s", "ibps");
		}
		printf("%-12s", "opps");
		if (g_dpg_bflag) {
			printf("%-12s", "obps");
		}
		printf("\n");
	}

	dpg_print_human_readable(ipps_b, sizeof(ipps_b), ipps, 1);
	dpg_print_human_readable(ibps_b, sizeof(ibps_b), ibps, 1);
	dpg_print_human_readable(opps_b, sizeof(opps_b), opps, 1);
	dpg_print_human_readable(obps_b, sizeof(obps_b), obps, 1);

	printf("%-12s", ipps_b);
	if (g_dpg_bflag) {
		printf("%-12s", ibps_b);
	}
	printf("%-12s", opps_b);
	if (g_dpg_bflag) {
		printf("%-12s", obps_b);
	}
	printf("\n");

	reports++;
}

static void
dpg_print_port_stat_counter(const char *name, uint64_t val, int n_queues, uint64_t *val_per_queue)
{
	int i;

	printf("\t%s: %"PRIu64, name, val);
	if (1) {
		printf("\n");
	} else {
		printf(" (");
		for (i = 0; i < n_queues; ++i) {
			if (i != 0) {
				printf(", ");
			}
			printf("%"PRIu64, val_per_queue[i]);
		}
		printf(")\n");
	}
}

static void
dpg_print_port_stat(int port_id)
{
	struct rte_eth_stats stats;
	char port_name[RTE_ETH_NAME_MAX_LEN];
	struct dpg_port *port;

	port = g_dpg_ports[port_id];

	rte_eth_dev_get_name_by_port(port_id, port_name);

	rte_eth_stats_get(port_id, &stats);

	printf("%s:\n", port_name);
	dpg_print_port_stat_counter("ipackets", stats.ipackets, port->n_queues, stats.q_ipackets);
	dpg_print_port_stat_counter("opackets", stats.opackets, port->n_queues, stats.q_opackets);
	dpg_print_port_stat_counter("ibytes", stats.ibytes, port->n_queues, stats.q_ibytes);
	dpg_print_port_stat_counter("obytes", stats.obytes, port->n_queues, stats.q_obytes);
	dpg_print_port_stat_counter("imissed", stats.imissed, 0, NULL);
	dpg_print_port_stat_counter("ierrors", stats.ierrors, 0, NULL);
	dpg_print_port_stat_counter("oerrors", stats.oerrors, 0, NULL);
	dpg_print_port_stat_counter("rx_nombuf", stats.rx_nombuf, 0, NULL);
}

static void
dpg_sighandler(int signum)
{
	g_dpg_done = 1;
}

static int
dpg_lcore_loop(void *dummy)
{
	uint64_t stat_time, tsc;
	struct dpg_lcore *lcore;
	struct dpg_task *task;

	lcore = g_dpg_lcores + rte_lcore_id();

	tsc = rte_rdtsc();
	stat_time = tsc;

	DPG_DLIST_FOREACH(task, &lcore->task_head, llist) {
		task->req_tx_time = tsc;
	}

	while (!g_dpg_done) {
		lcore->tsc = rte_rdtsc();

		DPG_DLIST_FOREACH(task, &lcore->task_head, llist) {
			dpg_do_task(task);
		}

		if (lcore->is_first) {
			tsc = lcore->tsc;
			if (tsc - stat_time >= g_dpg_hz) {
				dpg_print_report(tsc - stat_time);
				stat_time = tsc;
			}
		}
	}

	return 0;
}

int
main(int argc, char **argv)
{
	int i, rc, port_id, n_rxq, n_txq, n_mbufs, main_lcore, first_lcore;
	char port_name[RTE_ETH_NAME_MAX_LEN];
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

	RTE_ETH_FOREACH_DEV(port_id) {
		port = g_dpg_ports[port_id];
		if (!dpg_port_is_configured(port)) {
			continue;
		}

		rte_eth_dev_get_name_by_port(port_id, port_name);

		dpg_eth_dev_info_get(port_id, &dev_info);

		port->conf = port_conf;
		if (dev_info.tx_offload_capa & DPG_ETH_TX_OFFLOAD_MBUF_FAST_FREE) {
			port->conf.txmode.offloads |= DPG_ETH_TX_OFFLOAD_MBUF_FAST_FREE;
		}
		if (port->n_queues > 1) {
			port->conf.rxmode.mq_mode = DPG_ETH_MQ_RX_RSS;
			port->conf.rx_adv_conf.rss_conf.rss_hf =
					DPG_ETH_RSS_IP | DPG_ETH_RSS_TCP | DPG_ETH_RSS_UDP;

			port->conf.rx_adv_conf.rss_conf.rss_hf &= dev_info.flow_type_rss_offloads;
		}

		n_rxq = n_txq = port->n_queues;
		rc = rte_eth_dev_configure(port_id, n_rxq, n_txq, &port->conf);
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

	RTE_ETH_FOREACH_DEV(port_id) {
		port = g_dpg_ports[port_id];
		if (!dpg_port_is_configured(port)) {
			continue;
		}

		rte_eth_dev_get_name_by_port(port_id, port_name);

		dpg_eth_dev_info_get(port_id, &dev_info);

		for (i = 0; i < port->n_queues; ++i) {
			rxq_conf = dev_info.default_rxconf;
			rxq_conf.offloads = port->conf.rxmode.offloads;
			rc = rte_eth_rx_queue_setup(port_id, i, port->n_rxd,
					rte_eth_dev_socket_id(port_id),
					&rxq_conf,
					g_dpg_pktmbuf_pool);
			if (rc < 0) {
				dpg_die("rte_eth_rx_queue_setup('%s', %d, %d) failed (%d:%s)\n",
						port_name, port_id, i, -rc, rte_strerror(-rc));
			}

			txq_conf = dev_info.default_txconf;
			txq_conf.offloads = port->conf.txmode.offloads;
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

		rc = rte_eth_dev_set_link_up(port_id);
		if (rc < 0) {
			printf("rte_eth_dev_set_link_up('%s') failed (%d:%s)\n",
					port_name, -rc, rte_strerror(-rc));
		}

		dpg_update_rps(port, 0, 0);
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

	printf("\n");
	RTE_ETH_FOREACH_DEV(port_id) {
		dpg_print_port_stat(port_id);
	}

	return 0;
}
