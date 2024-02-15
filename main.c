// SPDX-License-Identifier: GPL-2.0-only

#include <arpa/inet.h>
#include <assert.h>
#include <ctype.h>
#include <getopt.h>
#include <math.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <signal.h>
#include <sys/socket.h>

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

#define DPG_RPS_DEFAULT 200*1000*1000
#define DPG_SRC_IP_DEFAULT "1.1.1.1"
#define DPG_DST_IP_DEFAULT "2.2.2.2"
#define DPG_ICMP_ID_DEFAULT "1"
#define DPG_ICMP_SEQ_DEFAULT "1"

#define DPG_LOG_BUFSIZE 512

#define DPG_SLOWSTART_RPS_MIN 5

#define DPG_PKT_LEN_MIN 60

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
	dpg_uint128_t size;

	struct dpg_darray array;

	dpg_uint128_t begin;
	dpg_uint128_t end;

	dpg_uint128_t (*get)(struct dpg_container *, dpg_uint128_t);
	int (*find)(struct dpg_container *, dpg_uint128_t);
};

struct dpg_iterator {
	dpg_uint128_t current;
	dpg_uint128_t step;

	struct dpg_container *container;
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

struct dpg_ipv6_pseudohdr {
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

struct dpg_task {
	struct dpg_dlist llist;
	struct dpg_dlist plist;

	bool do_req;
	bool do_echo;

	uint8_t verbose[2];

	uint8_t port_id;
	uint8_t queue_id;

	int lcore_id;

	volatile int rps;
	uint64_t req_tx_time;

	dpg_eth_addr_t dst_eth_addr;

	struct dpg_container src_ip;
	struct dpg_iterator src_ip_it;

	struct dpg_container dst_ip;
	struct dpg_iterator dst_ip_it;

	struct dpg_container icmp_id;
	struct dpg_iterator icmp_id_it;

	struct dpg_container icmp_seq;
	struct dpg_iterator icmp_seq_it;

	int srv6;
	uint8_t srv6_src[DPG_IPV6_ADDR_SIZE];
	struct dpg_container srv6_dst;
	struct dpg_iterator srv6_dst_it;

	uint16_t pkt_len;

	struct dpg_container addresses4;
	struct dpg_container addresses6;

	int tx_bytes;
	int n_tx_pkts;
	struct rte_mbuf *tx_pkts[DPG_TXBUF_SIZE];
};

struct dpg_port {
	dpg_eth_addr_t mac_addr;

	int id;

	int rps_max;
	int rps_cur;
	int rps_lo;
	int rps_step;
	uint8_t rps_seq;
	uint8_t rps_tries;

	struct dpg_counter ipackets;
	struct dpg_counter opackets;
	struct dpg_counter ibytes;
	struct dpg_counter obytes;

	uint64_t ipackets_prev;
	uint64_t opackets_prev;
	uint64_t ibytes_prev;
	uint64_t obytes_prev;

	struct dpg_dlist task_head;

	uint16_t n_rxd;
	uint16_t n_txd;
	int n_queues;
	int n_tasks;

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
static struct rte_eth_conf g_dpg_port_conf;
static bool g_dpg_bflag;
static bool g_dpg_software_counters = false;
static bool g_dpg_no_drop = false;
static double g_dpg_no_drop_percent = 2.0;
static u_int g_dpg_no_drop_tries = 30;
static u_int g_dpg_no_drop_seq = 10;

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

static void *
dpg_xmemdup(void *ptr, int size)
{
	void *cp;

	cp = dpg_xmalloc(size);
	memcpy(cp, ptr, size);
	return cp;
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

static void
dpg_darray_copy(struct dpg_darray *dst, struct dpg_darray *src)
{
	dst->size = src->size;
	dst->cap = src->cap;
	dst->item_size = src->item_size;

	free(dst->data);
	
	dst->data = dpg_xmemdup(src->data, dst->cap * dst->item_size);
}

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
dpg_iter_array_get(struct dpg_container *c, dpg_uint128_t i)
{
	dpg_uint128_t *val;

	val = dpg_darray_get(&c->array, i);
	return *val;
}

static int
dpg_iter_array_find(struct dpg_container *c, dpg_uint128_t val)
{
	int rc;

	rc = dpg_darray_find(&c->array, &val);

	return rc < 0 ? rc : 0;
}

static void
dpg_iter_array_init(struct dpg_container *c)
{
	dpg_darray_init(&c->array, sizeof(dpg_uint128_t));

	c->get = dpg_iter_array_get;
	c->find = dpg_iter_array_find;
}

static dpg_uint128_t
dpg_iter_interval_get(struct dpg_container *c, dpg_uint128_t i)
{
	assert(i < c->size);
	return c->begin + i;
}

static int
dpg_iter_interval_find(struct dpg_container *c, dpg_uint128_t val)
{
	if (val >= c->begin && val <= c->end) {
		return 0;
	} else {
		return -ESRCH;
	}
}

static void
dpg_iter_interval_init(struct dpg_container *c)
{
	c->get = dpg_iter_interval_get;
	c->find = dpg_iter_interval_find;
}

static dpg_uint128_t
dpg_container_get(struct dpg_container *c, dpg_uint128_t i)
{
	assert(c->size);
	return (*c->get)(c, i);
}

static bool
dpg_iterator_shift(struct dpg_iterator *it, dpg_uint128_t shift)
{
	dpg_uint128_t size;
	bool overflow;

	size = it->container->size;
	assert(size);

	overflow = false;

	it->current += shift;
	while (it->current >= size) {
		it->current = it->current - size;
		overflow = true;
	}

	return overflow;
}

static void
dpg_iterator_init(struct dpg_iterator *it, struct dpg_container *c,
		dpg_uint128_t step, dpg_uint128_t off)
{
	it->container = c;
	it->step = step;
	it->current = 0;

	dpg_iterator_shift(it, off);
}

static bool
dpg_iterator_next(struct dpg_iterator *it)
{
	return dpg_iterator_shift(it, it->step);
}

static dpg_uint128_t
dpg_iterator_get(struct dpg_iterator *it)
{
	return dpg_container_get(it->container, it->current);
}

static void
dpg_container_copy(struct dpg_container *dst, struct dpg_container *src)
{
	dst->size = src->size;

	dst->begin = src->begin;
	dst->end = src->end;

	dst->get = src->get;
	dst->find = src->find;

	dst->begin = src->begin;
	dpg_darray_copy(&dst->array, &src->array);
}

static int
dpg_container_find(struct dpg_container *c, dpg_uint128_t val)
{
	return (*c->find)(c, val);
}

static void
dpg_container_deinit(struct dpg_container *c)
{
	dpg_darray_deinit(&c->array);
	c->size = 0;
}

static int
dpg_container_parse(char *str, struct dpg_container *c, int (*parse)(char *, dpg_uint128_t *))
{
	int rc;
	dpg_uint128_t *val;
	char *s, *d;

	d = strchr(str, '-');
	if (d == NULL) {
		dpg_iter_array_init(c);

		for (s = strtok(str, ","); s != NULL; s = strtok(NULL, ",")) {
			val = dpg_darray_add(&c->array);
			rc = (*parse)(s, val);
			if (rc < 0) {
				goto err;
			}
		}

		c->size = c->array.size;
	} else {
		*d = '\0';

		dpg_iter_interval_init(c);

		rc = (*parse)(str, &c->begin);
		if (rc < 0) {
			goto err;
		}
		rc = (*parse)(d + 1, &c->end);
		if (rc < 0) {
			goto err;
		}
		*d = '-';
	
		if (c->begin > c->end) {
			rc = -EINVAL;
			goto err;
		}

		c->size = c->end - c->begin + 1;
	}

	return 0;

err:
	dpg_container_deinit(c);
	return rc;
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
	rc = rte_eth_macaddr_get(port_id, mac_addr);
#else
	// 19.11.0.99
	rte_eth_macaddr_get(port_id, mac_addr);
	rc = 0;
#endif

	return rc;
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

static void
dpg_norm2(char *buf, double val, char *fmt, int normalize)
{
	char *units[] = { "", "k", "m", "g", "t" };
	int i;

	if (normalize) {
		for (i = 0; val >=1000 && i < DPG_ARRAY_SIZE(units) - 1; i++) {
			val /= 1000;
		}
	} else {
		i = 0;
	}

	sprintf(buf, fmt, val, units[i]);
}

static int64_t
dpg_unnorm(const char *s)
{
	double val;
	char *endptr, *unit;
	const char *units = "kmgt";

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
dpg_norm(char *buf, double val, int normalize)
{
	if (normalize) {
		dpg_norm2(buf, val, "%.3f%s", normalize);
	} else {
		dpg_norm2(buf, val, "%.0f%s", normalize);
	}
}

static const char *
dpg_icmp_type_string(int icmp_type)
{
	return icmp_type == DPG_IP_ICMP_ECHO_REQUEST ? "request" : "reply";
}

static void
dpg_log_port(struct dpg_task *task, struct dpg_strbuf *sb)
{
	char port_name[RTE_ETH_NAME_MAX_LEN];

	rte_eth_dev_get_name_by_port(task->port_id, port_name);

	dpg_strbuf_adds(sb, port_name);
}

static void
dpg_log_hwaddr(struct dpg_task *task, struct dpg_strbuf *sb, struct dpg_eth_hdr *eh)
{
	char shbuf[DPG_ETH_ADDRSTRLEN];
	char dhbuf[DPG_ETH_ADDRSTRLEN];

	if (task->verbose[DPG_RX] < 2 || eh == NULL) {
		return;
	}

	dpg_eth_format_addr(shbuf, sizeof(shbuf), &eh->src_addr);
	dpg_eth_format_addr(dhbuf, sizeof(dhbuf), &eh->dst_addr);

	dpg_strbuf_addf(sb, " %s->%s", shbuf, dhbuf);
}

static void
dpg_log_icmp(struct dpg_task *task, int dir, struct dpg_eth_hdr *eh, struct dpg_ipv6_hdr *ih6,
		struct dpg_ipv4_hdr *ih, struct dpg_icmp_hdr *ich)
{
	char sabuf[INET6_ADDRSTRLEN];
	char dabuf[INET6_ADDRSTRLEN];
	char logbuf[DPG_LOG_BUFSIZE];
	struct dpg_strbuf sb;

	if (!task->verbose[dir]) {
		return;
	}

	dpg_strbuf_init(&sb, logbuf, sizeof(logbuf));

	dpg_log_port(task, &sb);
	dpg_log_hwaddr(task, &sb, eh);

	dpg_strbuf_addf(&sb, ": %s ", dir == DPG_TX ? "Sent" : "Recv");
	if (ih6 != NULL) {
		inet_ntop(AF_INET6, &ih6->src_addr, sabuf, sizeof(sabuf));
		inet_ntop(AF_INET6, &ih6->dst_addr, dabuf, sizeof(dabuf));
		dpg_strbuf_addf(&sb, "%s->%s\n\t", sabuf, dabuf);
	}

	inet_ntop(AF_INET, &ih->src_addr, sabuf, sizeof(sabuf));
	inet_ntop(AF_INET, &ih->dst_addr, dabuf, sizeof(dabuf));


	dpg_strbuf_addf(&sb, "ICMP echo %s: %s->%s, id=%d, seq=%d",
			dpg_icmp_type_string(ich->icmp_type),
			sabuf, dabuf,
			rte_be_to_cpu_16(ich->icmp_ident),
			rte_be_to_cpu_16(ich->icmp_seq_nb));

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

	if (!task->verbose[dir]) {
		return;
	}

	dpg_strbuf_init(&sb, logbuf, sizeof(logbuf));

	dpg_log_port(task, &sb);
	dpg_log_hwaddr(task, &sb, eh);

	is_req = ah->arp_opcode == RTE_BE16(DPG_ARP_OP_REQUEST);
	inet_ntop(AF_INET, &ah->arp_tip, tibuf, sizeof(tibuf));
	inet_ntop(AF_INET, &ah->arp_sip, sibuf, sizeof(sibuf));
	dpg_eth_format_addr(thbuf, sizeof(thbuf), &ah->arp_tha);
	dpg_eth_format_addr(shbuf, sizeof(shbuf), &ah->arp_sha);

	dpg_strbuf_addf(&sb, ": %s ARP %s %s(%s)->%s(%s)",
			dir == DPG_TX ? "Sent" : "Recv",
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

	if (!task->verbose[dir]) {
		return;
	}

	dpg_strbuf_init(&sb, logbuf, sizeof(logbuf));

	dpg_log_port(task, &sb);
	dpg_log_hwaddr(task, &sb, eh);

	inet_ntop(AF_INET6, ih->src_addr, srcbuf, sizeof(srcbuf));
	inet_ntop(AF_INET6, ih->dst_addr, dstbuf, sizeof(dstbuf));

	dpg_strbuf_addf(&sb, ": %s %s->%s: %s", dir == DPG_RX ? "Recv" : "Sent",
			srcbuf, dstbuf, desc);

	printf("%s\n", dpg_strbuf_cstr(&sb));
}

static void
dpg_log_custom(struct dpg_task *task, struct dpg_eth_hdr *eh, const char *proto)
{
	char logbuf[DPG_LOG_BUFSIZE];
	struct dpg_strbuf sb;

	if (!task->verbose[DPG_RX]) {
		return;
	}

	dpg_strbuf_init(&sb, logbuf, sizeof(logbuf));

	dpg_log_port(task, &sb);
	dpg_log_hwaddr(task, &sb, eh);

	dpg_strbuf_addf(&sb, ": Recv %s packet", proto);

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
dpg_task_copy(struct dpg_task *dst, struct dpg_task *src)
{
	dst->do_req = src->do_req;
	dst->do_echo = src->do_echo;
	memcpy(dst->verbose, src->verbose, sizeof(dst->verbose));
	dst->port_id = src->port_id;
	dst->queue_id = src->queue_id;
	dst->lcore_id = src->lcore_id;
	dst->dst_eth_addr = src->dst_eth_addr;

	dpg_container_copy(&dst->src_ip, &src->src_ip);
	dpg_container_copy(&dst->dst_ip, &src->dst_ip);
	dpg_container_copy(&dst->icmp_id, &src->icmp_id);
	dpg_container_copy(&dst->icmp_seq, &src->icmp_seq);

	dst->srv6 = src->srv6;
	memcpy(dst->srv6_src, src->srv6_src, sizeof(dst->srv6_src));

	dpg_container_copy(&dst->srv6_dst, &src->srv6_dst);

	dst->pkt_len = src->pkt_len;

	dpg_container_copy(&dst->addresses4, &src->addresses4);
	dpg_container_copy(&dst->addresses6, &src->addresses6);
}

static void
dpg_print_usage(struct dpg_task *def)
{
	int rc, port_id;
	dpg_eth_addr_t mac_addr;
	char rate_buf[32];
	char eth_addr_buf[DPG_ETH_ADDRSTRLEN];
	char port_name[RTE_ETH_NAME_MAX_LEN];

	dpg_eth_format_addr(eth_addr_buf, sizeof(eth_addr_buf), &def->dst_eth_addr);
	dpg_norm(rate_buf, DPG_RPS_DEFAULT, 1);

	printf("Usage: dpdk-ping [DPDK options] -- task [-- task [-- task ...]]\n"
	"\n"
	"Task:\n"
	"\t-h|--help:  Print this help\n"
	"\t-V {level}:  Be verbose (default: 0)\n"
	"\t-b {bool}:  Print bits/sec in report (default: %s)\n"
	"\t-l {lcore id}:  Lcore to run on (default: %d)\n"
	"\t-p {port name}:  Port to run on\n"
	"\t-q {queue id}:  RSS queue id to run on (default: %d)\n"
	"\t-R {bool}:  Send ICMP echo requests (default: %s)\n"
	"\t-E {bool}:  Send ICMP echo reply on incoming ICMP echo requests (default: %s)\n"
	"\t-4 {IP..}:  Interaface IP address iterator\n"
	"\t-6 {IPv6..}:  Interface IPv6 address iterator\n"
	"\t-B {packets per second}:  ICMP requests bandwidth (default:%s)\n"
	"\t-H {ether address}:  Destination ethernet address (default: %s)\n"
	"\t-s {IP..}:  Source ip addresses iterator (default: %s)\n"
	"\t-d {IP..}:  Destination ip addresses iterator (default: %s)\n"
	"\t-L {bytes}:  Packet size (default: %d)\n"
	"\t--rx-verbose {level}:  Be verbose on rx path (default: %d)\n"
	"\t--tx-verbose {level}:  Be verbose on tx path (default: %d)\n"
	"\t--icmp-id {id..}:  ICMP request id iterator (default: %s)\n"
	"\t--icmp-seq {seq..}:  ICMP request sequence iterator (default: %s)\n"
	"\t--srv6-src {IPv6}:  SRv6 tunnel source address\n"
	"\t--srv6-dst {IPv6..}:  SRv6 tunnel destination address iterator\n"
	"\t--software-counters {bool}:  Use software counters for reports (default: %s)\n"
	"\t--no-drop {%%[,T[,t]]}:  Specify no-drop rate search algorithm parameters (default: %f,%u,%u)\n"
	"\tIterator (it) of values x (x..):\n"
	"\t\tit = {x|x-x}\n"
	"\t\tit = {it[,it]}\n"
	"Ports:\n",
		dpg_bool_str(g_dpg_bflag),
		def->lcore_id,
		def->queue_id,
		dpg_bool_str(def->do_req),
		dpg_bool_str(def->do_echo),
		rate_buf,
		eth_addr_buf,
		DPG_SRC_IP_DEFAULT,
		DPG_DST_IP_DEFAULT,
		def->pkt_len,
		def->verbose[DPG_RX],
		def->verbose[DPG_TX],
		DPG_ICMP_ID_DEFAULT,
		DPG_ICMP_SEQ_DEFAULT,
		dpg_bool_str(g_dpg_software_counters),
		g_dpg_no_drop_percent,
		g_dpg_no_drop_tries,
		g_dpg_no_drop_seq
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
dpg_parse_task(struct dpg_task **ptask, struct dpg_task *tmpl, struct dpg_task *def,
		int argc, char **argv)
{
	int opt, option_index, rps_max;
	bool Rflag, Eflag;
	int64_t rc;
	uint16_t port_id;
	char *endptr;
	const char *optname;
	char port_name[RTE_ETH_NAME_MAX_LEN];
	struct dpg_task *task, *tmp;
	struct dpg_lcore *lcore;
	struct dpg_port *port;

	static struct option long_options[] = {
		{ "help", no_argument, 0, 'h' },
		{ "rx-verbose", required_argument, 0, 0 },
		{ "tx-verbose", required_argument, 0, 0 },
		{ "icmp-id", required_argument, 0, 0 },
		{ "icmp-seq", required_argument, 0, 0 },
		{ "srv6-src", required_argument, 0, 0 },
		{ "srv6-dst", required_argument, 0, 0 },
		{ "software-counters", required_argument, 0, 0 },
		{ "no-drop",  required_argument, 0, 0 },
		{ NULL, 0, 0, 0 },
	};

	task = dpg_xmalloc(sizeof(*task));
	memset(task, 0, sizeof(*task));

	dpg_task_copy(task, tmpl);

	Rflag = Eflag = false;
	rps_max = -1;

	while ((opt = getopt_long(argc, argv, "hV:b:l:p:q:R:E:4:6:B:H:s:d:L:",
			long_options, &option_index)) != -1) {
		switch (opt) {
		case 0:
			optname = long_options[option_index].name;
			if (!strcmp(optname, "rx-verbose")) {
				task->verbose[DPG_RX] = strtoul(optarg, NULL, 10);
			} else if (!strcmp(optname, "tx-verbose")) {
				task->verbose[DPG_TX] = strtoul(optarg, NULL, 10);
			} else if (!strcmp(optname, "icmp-id")) {
				rc = dpg_container_parse_u16(optarg, &task->icmp_id);
				if (rc < 0) {
					dpg_invalid_argument(0, optname);
				}
			} else if (!strcmp(optname, "icmp-seq")) {
				rc = dpg_container_parse_u16(optarg, &task->icmp_seq);
				if (rc < 0) {
					dpg_invalid_argument(0, optname);
				}
			} else if (!strcmp(optname, "srv6-src")) {
				rc = inet_pton(AF_INET6, optarg, task->srv6_src);
				if (rc != 1) {
					dpg_invalid_argument(0, optname);
				}
				task->srv6 = 1;
			} else if (!strcmp(optname, "srv6-dst")) {
				rc = dpg_container_parse_ipv6(optarg, &task->srv6_dst);
				if (rc < 0) {
					dpg_invalid_argument(0, optname);
				}
				task->srv6 = 1;
			} else if (!strcmp(optname, "software-counters")) {
				rc = dpg_parse_bool(optarg, &g_dpg_software_counters);
				if (rc < 0) {
					dpg_invalid_argument(0, optname);
				}
			} else if (!strcmp(optname, "no-drop")) {
				rc = sscanf(optarg, "%lf,%u,%u",
						&g_dpg_no_drop_percent,
						&g_dpg_no_drop_tries,
						&g_dpg_no_drop_seq);
				if (rc == 0 || rc == EOF) {
					dpg_invalid_argument(0, optname);
				} else if (rc == 2) {
					g_dpg_no_drop_seq = DPG_MAX(1, g_dpg_no_drop_tries / 3);
				}

				if (g_dpg_no_drop_percent <= 0 || g_dpg_no_drop_percent >= 100) {
					dpg_invalid_argument(0, optname);
				}

				if (g_dpg_no_drop_tries < 2 ||
				    g_dpg_no_drop_tries < g_dpg_no_drop_seq) {
					dpg_invalid_argument(0, optname);
				}

				g_dpg_no_drop = true;
			}
			break;

		case 'h':
			dpg_print_usage(def);
			break;

		case 'V':
			task->verbose[DPG_RX] = task->verbose[DPG_TX] = strtoul(optarg, NULL, 10);
			break;

		case 'b':
			rc = dpg_parse_bool(optarg, &g_dpg_bflag);
			if (rc < 0) {
				dpg_invalid_argument(opt, NULL);
			}
			break;

		case 'l':
			task->lcore_id = strtoul(optarg, &endptr, 10);
			if (*endptr != '\0') {
				dpg_invalid_argument(opt, NULL);
			}
			rc = rte_lcore_is_enabled(task->lcore_id);
			if (!rc) {
				dpg_die("DPDK doesn't run on lcore %d\n", task->lcore_id);
			}
			break;

		case 'p':
			task->port_id = RTE_MAX_ETHPORTS;
			RTE_ETH_FOREACH_DEV(port_id) {
				rte_eth_dev_get_name_by_port(port_id, port_name);
				if (!strcmp(optarg, port_name)) {
					task->port_id = port_id;
					break;
				}
			}
			if (task->port_id == RTE_MAX_ETHPORTS) {
				dpg_die("DPDK doesn't run on port '%s'\n", optarg);		
			}

			if (g_dpg_ports[task->port_id] == NULL) {
				port = dpg_xmalloc(sizeof(*port));
				memset(port, 0, sizeof(*port));
				port->id = task->port_id;
				port->rps_max = DPG_RPS_DEFAULT;
				dpg_dlist_init(&port->task_head);

				g_dpg_ports[task->port_id] = port;
			}
			break;

		case 'q':
			task->queue_id = strtoul(optarg, &endptr, 10);
			if (*endptr != '\0') {
				dpg_invalid_argument(opt, NULL);
			}
			break;

		case 'R':
			Rflag = 1;
			rc = dpg_parse_bool(optarg, &task->do_req);
			if (rc < 0) {
				dpg_invalid_argument(opt, NULL);
			}
			break;

		case 'E':
			Eflag = 1;
			rc = dpg_parse_bool(optarg, &task->do_echo);
			if (rc < 0) {
				dpg_invalid_argument(opt, NULL);
			}
			break;

		case '4':
			rc = dpg_container_parse_ipv4(optarg, &task->addresses4);
			if (rc < 0) {
				dpg_invalid_argument(opt, NULL);
			}
			break;

		case '6':
			rc = dpg_container_parse_ipv6(optarg, &task->addresses6);
			if (rc < 0) {
				dpg_invalid_argument(opt, NULL);
			}
			break;

		case 'B':
			rc = dpg_unnorm(optarg);
			if (rc < 0) {
				dpg_invalid_argument(opt, NULL);
			}
			rps_max = rc;
			break;

		case 'H':
			rc = dpg_eth_unformat_addr(optarg, &task->dst_eth_addr);
			if (rc != 0) {
				dpg_invalid_argument(opt, NULL);
			}
			break;

		case 's':
			rc = dpg_container_parse_ipv4(optarg, &task->src_ip);
			if (rc < 0) {
				dpg_invalid_argument(opt, NULL);
			}
			break;

		case 'd':
			rc = dpg_container_parse_ipv4(optarg, &task->dst_ip);
			if (rc < 0) {
				dpg_invalid_argument(opt, NULL);
			}
			break;

		case 'L':
			task->pkt_len = strtoul(optarg, &endptr, 10);
			if (*endptr != '\0' || task->pkt_len < DPG_PKT_LEN_MIN) {
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

	lcore = g_dpg_lcores + task->lcore_id;
	DPG_DLIST_INSERT_HEAD(&lcore->task_head, task, llist);

	if (task->port_id == tmpl->port_id) {
		if (!Rflag) {
			task->do_req = tmpl->do_req;
		}
		if (!Eflag) {
			task->do_echo = tmpl->do_echo;
		}
	} else {
		if (!Rflag) {
			task->do_req = false;
		}
		if (!Eflag) {
			task->do_echo = false;
		}
	}

	if (task->srv6) {
		if (dpg_is_zero(&task->srv6_src, sizeof(task->srv6_src))) {
			dpg_argument_not_specified(0, "srv6-src");
		}
		if (task->srv6_dst.size == 0) {
			dpg_argument_not_specified(0, "srv6-dst");
		}

		dpg_iterator_init(&task->srv6_dst_it, &task->srv6_dst, 1, 0);
	}

	dpg_iterator_init(&task->src_ip_it, &task->src_ip, 1, 0);
	dpg_iterator_init(&task->dst_ip_it, &task->dst_ip, 1, 0);
	dpg_iterator_init(&task->icmp_id_it, &task->icmp_id, 1, 0);
	dpg_iterator_init(&task->icmp_seq_it, &task->icmp_seq, 1, 0);

	port = g_dpg_ports[task->port_id];
	DPG_DLIST_FOREACH(tmp, &port->task_head, plist) {
		if (task->queue_id == tmp->queue_id) {
			rte_eth_dev_get_name_by_port(task->port_id, port_name);
			dpg_die("Duplicate task for port '%s' queue %d\n",
					port_name, task->queue_id);
		}
	}
	DPG_DLIST_INSERT_HEAD(&port->task_head, task, plist);

	port->n_queues = DPG_MAX(port->n_queues, task->queue_id + 1);
	port->n_tasks++;

	if (rps_max >= 0) {
		port->rps_max = rps_max;
	}
	
	*ptask = task;

	return optind;
}

static void
dpg_set_eth_hdr_addresses(struct dpg_task *task, struct dpg_eth_hdr *eh)
{
	eh->dst_addr = task->dst_eth_addr;
	eh->src_addr = g_dpg_ports[task->port_id]->mac_addr;
}

static struct rte_mbuf *
dpg_create_icmp_request(struct dpg_task *task)
{
	bool overflow;
	int ih_total_length, pkt_len;
	dpg_uint128_t srv6_dst, src_ip, dst_ip, icmp_id, icmp_seq;
	struct rte_mbuf *m;
	struct dpg_eth_hdr *eh;
	struct dpg_ipv4_hdr *ih;
	struct dpg_ipv6_hdr *ih6;
	struct dpg_icmp_hdr *ich;
	struct dpg_srv6_hdr *srh;

	m = rte_pktmbuf_alloc(g_dpg_pktmbuf_pool);
	if (m == NULL) {
		dpg_die("rte_pktmbuf_alloc() failed\n");
	}

	eh = rte_pktmbuf_mtod(m, struct dpg_eth_hdr *);

	pkt_len = sizeof(*eh) + sizeof(*ih) + sizeof(*ich);

	if (task->srv6) {
		pkt_len += sizeof(*ih6) + sizeof(*srh);

		m->pkt_len = DPG_MAX(task->pkt_len, pkt_len);
		ih_total_length = m->pkt_len - (sizeof(*eh) + sizeof(*ih6) + sizeof(*srh));

		eh->eth_type = RTE_BE16(DPG_ETH_TYPE_IPV6);
		ih6 = (struct dpg_ipv6_hdr *)(eh + 1);
		srh = (struct dpg_srv6_hdr *)(ih6 + 1);
		ih = (struct dpg_ipv4_hdr *)(srh + 1);

		srv6_dst = dpg_iterator_get(&task->srv6_dst_it);

		ih6->vtc_flow = rte_cpu_to_be_32(0x60000000);
		ih6->payload_len = rte_cpu_to_be_16(m->pkt_len - (sizeof(*eh) + sizeof(*ih6)));
		ih6->proto = IPPROTO_ROUTING;
		ih6->hop_limits = 64;
		memcpy(ih6->src_addr, task->srv6_src, sizeof(ih6->src_addr));
		dpg_uint128_to_ipv6(ih6->dst_addr, srv6_dst);

		srh->next_header = IPPROTO_IPIP;
		srh->hdr_ext_len = sizeof(*srh) / 8 - 1;
		srh->routing_type = 4; // Segment Routing v6
		srh->segments_left = 0;
		srh->last_entry = 0;
		srh->flags = 0;
		srh->tag = 0;
		memcpy(srh->localsid, ih6->dst_addr, DPG_IPV6_ADDR_SIZE);

		overflow = dpg_iterator_next(&task->srv6_dst_it);
	} else {
		m->pkt_len = DPG_MAX(task->pkt_len, pkt_len);
		ih_total_length = m->pkt_len - sizeof(*eh);

		eh->eth_type = RTE_BE16(DPG_ETH_TYPE_IPV4);
		ih = (struct dpg_ipv4_hdr *)(eh + 1);

		ih6 = NULL;

		overflow = true;
	}

	m->next = NULL;
	m->data_len = m->pkt_len;

	ich = (struct dpg_icmp_hdr *)(ih + 1);

	dpg_set_eth_hdr_addresses(task, eh);

	ih->version = 4;
	ih->ihl = sizeof(*ih) / sizeof(uint32_t);
	ih->type_of_service = 0;
	ih->total_length = rte_cpu_to_be_16(ih_total_length);
	ih->packet_id = 0;
	ih->fragment_offset = 0;
	ih->time_to_live = 64;
	ih->next_proto_id = IPPROTO_ICMP;
	ih->hdr_checksum = 0;

	src_ip = dpg_iterator_get(&task->src_ip_it);
	ih->src_addr = rte_cpu_to_be_32(src_ip);

	dst_ip = dpg_iterator_get(&task->dst_ip_it);
	ih->dst_addr = rte_cpu_to_be_32(dst_ip);

	ich->icmp_type = DPG_IP_ICMP_ECHO_REQUEST;
	ich->icmp_code = 0;
	ich->icmp_cksum = 0;

	icmp_id = dpg_iterator_get(&task->icmp_id_it);
	ich->icmp_ident = rte_cpu_to_be_16(icmp_id);

	icmp_seq = dpg_iterator_get(&task->icmp_seq_it);
	ich->icmp_seq_nb = rte_cpu_to_be_16(icmp_seq);

	ih->hdr_checksum = dpg_cksum(ih, sizeof(*ih));
	ich->icmp_cksum = dpg_cksum(ich, ih_total_length - sizeof(*ih));

	if (overflow) {
		overflow = dpg_iterator_next(&task->icmp_id_it);
		if (overflow) {
			overflow = dpg_iterator_next(&task->src_ip_it);
			if (overflow) {
				overflow = dpg_iterator_next(&task->dst_ip_it);
				if (overflow) {
					dpg_iterator_next(&task->icmp_seq_it);
				}
			}
		}
	}

	dpg_log_icmp(task, DPG_TX, NULL, ih6, ih, ich);

	return m;
}

static int
dpg_ip_input(struct dpg_task *task, struct dpg_eth_hdr *eh, struct dpg_ipv6_hdr *ih6,
		void *ptr, int len)
{
	int hl, ih_total_length;
	struct dpg_ipv4_hdr *ih;
	struct dpg_icmp_hdr *ich;

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

	if (ih->next_proto_id != IPPROTO_ICMP) {
		return -EINVAL;
	}

	if (len < hl + sizeof(*ich)) {
		return -EINVAL;
	}

	ih_total_length = rte_be_to_cpu_16(ih->total_length);

	if (ih_total_length > len) {
		return -EINVAL;
	} 

	ich = (struct dpg_icmp_hdr *)((uint8_t *)ih + hl);

	dpg_log_icmp(task, DPG_RX, eh, ih6, ih, ich);

	if (ich->icmp_type != DPG_IP_ICMP_ECHO_REQUEST || !task->do_echo || ih6 != NULL) {
		return -ENOTSUP;
	}

	ich->icmp_type = DPG_IP_ICMP_ECHO_REPLY;
	DPG_SWAP(ih->src_addr, ih->dst_addr);

	ich->icmp_cksum = 0;
	ich->icmp_cksum = dpg_cksum(ich, ih_total_length - hl);
	ih->hdr_checksum = 0;
	ih->hdr_checksum = dpg_cksum(ih, hl);

	dpg_log_icmp(task, DPG_TX, NULL, ih6, ih, ich);

	return 0;
}

static void
dpg_create_neighbour_advertisment(struct dpg_task *task, struct rte_mbuf *m,
		struct dpg_ipv6_hdr *ih, struct dpg_icmpv6_neigh_solicitaion *ns)
{
	int len;
	uint64_t sum;
	uint16_t target[DPG_IPV6_ADDR_SIZE];
	struct dpg_icmpv6_neigh_advertisment *na;
	struct dpg_target_link_layer_address_option *opt;
	struct dpg_ipv6_pseudohdr pseudo;

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
	opt->address = g_dpg_ports[task->port_id]->mac_addr;

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

			if (task->verbose[DPG_RX]) {
				inet_ntop(AF_INET6, ns->target, tgtbuf, sizeof(tgtbuf));
				snprintf(desc, sizeof(desc), "Neighbour Solicitation (target=%s)",
						tgtbuf);
				dpg_log_ipv6(task, DPG_RX, eh, ih6, desc);
			}

			target = dpg_ipv6_to_uint128(ns->target);
			rc = dpg_container_find(&task->addresses6, target);
			if (rc < 0) {
				return -EINVAL;
			}

			dpg_create_neighbour_advertisment(task, m, ih6, ns);

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
	if (task->verbose[DPG_RX]) {
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
	ah->arp_tha = task->dst_eth_addr;
	ah->arp_sha = g_dpg_ports[task->port_id]->mac_addr;
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
	struct dpg_eth_hdr *eh;
	struct dpg_port *port;
	struct rte_mbuf *m, *rx_pkts[DPG_MAX_PKT_BURST];
	char proto[32];

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
			if (task->verbose[DPG_RX]) {
				snprintf(proto, sizeof(proto), "proto 0x%04hx",
						rte_be_to_cpu_16(eh->eth_type));
				dpg_log_custom(task, eh, proto);
			}
			goto drop;
		}

		dpg_set_eth_hdr_addresses(task, eh);

		if (task->n_tx_pkts < DPG_TXBUF_SIZE) {
			dpg_add_tx(task, m);
			continue;
		}
drop:
		rte_pktmbuf_free(m);
	}

	room = DPG_TXBUF_SIZE - task->n_tx_pkts;
	if (task->do_req && room) {
		if (task->rps == 0) {
			n_reqs = 0;
		} else if (task->rps > 0) {
			n_reqs = dpg_rps_ratelimit(task, task->rps);
		} else {
			n_reqs = room;
		}

		for (i = 0; i < n_reqs; ++i) {
			m = dpg_create_icmp_request(task);
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

	if (g_dpg_software_counters) {
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

	if (port->rps_max <= DPG_SLOWSTART_RPS_MIN || !g_dpg_no_drop) {
		return port->rps_max;
	}

	if (port->rps_cur < DPG_SLOWSTART_RPS_MIN) {
		return DPG_SLOWSTART_RPS_MIN;
	}

	port->rps_tries++;

	if (ipps + 1 >= opps ||  (opps - ipps) < g_dpg_no_drop_percent * opps / 100) {
		port->rps_seq++;
	} else {
		port->rps_seq = 0;
	}

	rps = port->rps_cur;
	
	if (port->rps_seq == g_dpg_no_drop_seq) {
		port->rps_seq = port->rps_tries = 0;

		port->rps_lo = port->rps_cur;
		if (port->rps_step == 0) {
			rps = port->rps_cur * 10;
		} else {
			port->rps_step *= 2;
			rps = port->rps_lo + port->rps_step;
		}
	} else if (port->rps_tries == g_dpg_no_drop_tries) {
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
		dpg_norm(rps_prev_buf, port->rps_cur, 1);
		dpg_norm(rps_buf, rps, 1);
		dpg_norm(rps_lo_buf, port->rps_lo, 1);
		dpg_norm(rps_step_buf, port->rps_step, 1);

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
	rps_per_task = rps_cur/port->n_tasks;
	rps_rem = rps_cur % port->n_tasks;

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

		if (g_dpg_software_counters) {
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
	dpg_norm(ipps_b, ipps, 1);
	dpg_norm(ibps_b, ibps, 1);
	dpg_norm(opps_b, opps, 1);
	dpg_norm(obps_b, obps, 1);

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
	struct rte_eth_dev_info dev_info;
	struct rte_eth_rxconf rxq_conf;
	struct rte_eth_txconf txq_conf;
	struct dpg_task tmpl_instance, *task, *tmpl;
	struct dpg_port *port;
	struct dpg_lcore *lcore;

	assert(RTE_MAX_ETHPORTS <= UINT8_MAX);

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

	g_dpg_port_conf.txmode.mq_mode = DPG_ETH_MQ_TX_NONE;

	main_lcore = rte_lcore_id();
	tmpl = &tmpl_instance;
	memset(tmpl, 0, sizeof(*tmpl));
	tmpl->lcore_id = main_lcore;
	for (i = 0; i < DPG_ARRAY_SIZE(tmpl->dst_eth_addr.addr_bytes); ++i) {
		tmpl->dst_eth_addr.addr_bytes[i] = 0xFF;
	}

	dpg_container_parse_ipv4(DPG_SRC_IP_DEFAULT, &tmpl->src_ip);
	dpg_container_parse_ipv4(DPG_DST_IP_DEFAULT, &tmpl->dst_ip);
	dpg_container_parse_u16(DPG_ICMP_ID_DEFAULT, &tmpl->icmp_id);
	dpg_container_parse_u16(DPG_ICMP_SEQ_DEFAULT, &tmpl->icmp_seq);

	tmpl->pkt_len = DPG_PKT_LEN_MIN;

	while (argc > 1) {
		rc = dpg_parse_task(&task, tmpl, &tmpl_instance, argc, argv);

		argc -= (rc - 1);
		argv += (rc - 1);
		optind = 1;

		tmpl = task;
	}

	n_mbufs = DPG_MEMPOOL_CACHE_SIZE;

	RTE_ETH_FOREACH_DEV(port_id) {
		port = g_dpg_ports[port_id];
		if (!dpg_port_is_configured(port)) {
			continue;
		}

		rte_eth_dev_get_name_by_port(port_id, port_name);

		rc = rte_eth_dev_info_get(port_id, &dev_info);
		if (rc < 0) {
			dpg_die("rte_eth_dev_info_get('%s') failed (%d:%s)\n",
					port_name, -rc, rte_strerror(-rc));
		}

		port->conf = g_dpg_port_conf;
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

		rc = dpg_eth_macaddr_get(port_id, &port->mac_addr);
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

		rc = rte_eth_dev_info_get(port_id, &dev_info);
		if (rc < 0) {
			dpg_die("rte_eth_dev_info_get('%s') failed (%d:%s)\n",
					port_name, -rc, rte_strerror(-rc));
		}

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
