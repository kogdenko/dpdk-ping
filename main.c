// SPDX-License-Identifier: GPL-2.0-only

#include <arpa/inet.h>
#include <assert.h>
#include <getopt.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <sys/socket.h>

#include <rte_bus.h>
#include <rte_common.h>
#include <rte_cycles.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include <rte_pci.h>
#include <rte_version.h>

#define DPG_USE_HARDWARE_COUNTERS

#define DPG_ETHER_ADDR_FMT_SIZE 18

#define DPG_IP_ICMP_ECHO_REPLY 0
#define DPG_IP_ICMP_ECHO_REQUEST 8

#define DPG_ICMP_SEQ_NB_START 1
#define DPG_ICMP_SEQ_NB_END 50000

#define DPG_ETHER_TYPE_ARP 0x0806
#define DPG_ETHER_TYPE_IPV4 0x0800

#define DPG_IPV4_HDR_DF_FLAG (1 << 6)

#define	DPG_ARP_OP_REQUEST 1
#define	DPG_ARP_OP_REPLY 2

#define DPG_MEMPOOL_CACHE_SIZE 128
#define DPG_MAX_PKT_BURST 128

#define DPG_PPSTR(x) DPG_PPXSTR(x)
#define DPG_PPXSTR(x) #x

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
typedef struct ether_addr dpg_ether_addr_t;
#define dpg_ether_format_addr ether_format_addr
#else
// 19, 8, 0, 99
typedef struct rte_ether_addr dpg_ether_addr_t;
#define dpg_ether_format_addr rte_ether_format_addr
#endif

#if RTE_VERSION <= RTE_VERSION_NUM(22, 7, 0, 99)
#define dpg_dev_name(dev) ((dev)->name)
#else
// 22.11.0.99
#define dpg_dev_name(dev) rte_dev_name(dev)
#endif

struct dpg_counter {
	uint64_t per_lcore[RTE_MAX_LCORE];
};

struct dpg_ether_hdr {
	dpg_ether_addr_t dst_addr;
	dpg_ether_addr_t src_addr;
	uint16_t ether_type;
}  __attribute__((aligned(2)));

struct dpg_arp_hdr {
	rte_be16_t arp_hardware;
	rte_be16_t arp_protocol;
	uint8_t arp_hlen;
	uint8_t arp_plen;
	rte_be16_t arp_opcode;
	dpg_ether_addr_t arp_sha;
	rte_be32_t arp_sip;
	dpg_ether_addr_t arp_tha;
	rte_be32_t arp_tip;
} __attribute__((aligned(2)));

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
} __attribute__((aligned(2)));

struct dpg_icmp_hdr {
	uint8_t  icmp_type;
	uint8_t  icmp_code;
	rte_be16_t icmp_cksum;
	rte_be16_t icmp_ident;
	rte_be16_t icmp_seq_nb;
} __attribute__((aligned(2)));

struct dpg_job {
	struct dpg_job *lcore_next;
	struct dpg_job *port_next;

	int request;
	int echo;

	int port_id;
	int queue_id;

	int lcore_id;

	uint64_t bandwidth;
	uint64_t last_tx_time;

	dpg_ether_addr_t dst_eth_addr;

	uint32_t icmp_seq_nb;

	uint32_t src_ip_current;
	uint32_t src_ip_start;
	uint32_t src_ip_end;

	uint32_t dst_ip_current;
	uint32_t dst_ip_start;
	uint32_t dst_ip_end;

	uint16_t icmp_id_current;
	uint16_t icmp_id_start;
	uint16_t icmp_id_end;

	int n_tx_pkts;
	struct rte_mbuf *tx_pkts[DPG_MAX_PKT_BURST];
};

struct dpg_port {
	uint16_t n_rxd;
	uint16_t n_txd;
	int n_queues;
	dpg_ether_addr_t mac_addr;
	struct dpg_job *jobs;
	struct rte_eth_conf conf;
};

struct dpg_lcore {
	struct dpg_job *jobs;
	int is_first;
};

static volatile uint64_t g_microseconds;
static uint64_t g_hz;
static struct dpg_port g_ports[RTE_MAX_ETHPORTS];
static struct dpg_lcore g_lcores[RTE_MAX_LCORE];
static struct rte_mempool *g_pktmbuf_pool;
struct dpg_counter g_ipackets;
struct dpg_counter g_opackets;
static struct rte_eth_conf g_port_conf = {
	.txmode = {
		.mq_mode = DPG_ETH_MQ_TX_NONE,
	},
};

#define DPG_SWAP(a, b) do { \
	typeof(a) tmp = a; \
	a = b; \
	b = tmp; \
} while (0)

#define DPG_MAX(a, b) ((a) > (b) ? (a) : (b))

#define DPG_ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))

#define dpg_die(...) \
	rte_exit(EXIT_FAILURE, ##__VA_ARGS__);

#ifdef DPG_USE_HARDWARE_COUNTERS
#define dpg_counter_add(c, add)
#define dpg_counter_get(c) 0
#else
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
#endif

static int
dpg_ether_unformat_addr(const char *s, dpg_ether_addr_t *a)
{
	int rc;

	rc = sscanf(s, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
			(a)->addr_bytes + 0, a->addr_bytes + 1, a->addr_bytes + 2,
			(a)->addr_bytes + 3, a->addr_bytes + 4, a->addr_bytes + 5);

	return rc == 6 ? 0 : -EINVAL;
}

static int
dpg_eth_macaddr_get(uint16_t port_id, dpg_ether_addr_t *mac_addr)
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
dpg_invalid_argument(int arg)
{
	dpg_die("Invalid argument: '-%c'", arg);
}

static void
dpg_print_usage()
{
	int port_id;
	char port_name[RTE_ETH_NAME_MAX_LEN];

	printf("Usage: dpdk-ping [DPDK options] -- job [-- job [-- job ...]]\n"
	"\n"
	"Job:\n"
	"\t-h:  Print this help\n"
	"\t-l {lcore id}:  Lcore to run on\n"
	"\t-p {port name}:  Port to run on\n"
	"\t-q {queue id}:  RSS queue id to run on\n"
	"\t-R:  Send ICMP echo requests\n"
	"\t-E:  Send ICMP echo reply on incoming ICMP echo requests\n"
	"\t-B {packets per second}:  ICMP requests bandwidth\n"
	"\t-A {ether address}:  Destination ethernet address\n"
	"\t-s {ip[-ip]}:  Source ip addresses interval\n"
	"\t-d {ip[-ip]}:  Destination ip addresses interval\n"
	"\t-i {icmp id[-icmp id]}:  ICMP request id interval\n"
	"Ports:\n"
	);

	RTE_ETH_FOREACH_DEV(port_id) {
		rte_eth_dev_get_name_by_port(port_id, port_name);
		printf("%s\n", port_name);
	}

	rte_exit(EXIT_SUCCESS, "\n");
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
dpg_cksum_raw(const u_char *b, int size)
{
	uint64_t sum;

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

uint16_t
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
		for (i = 0; val >=1000 && i < sizeof(units)/sizeof(char *) - 1; i++) {
			val /= 1000;
		}
	} else {
		i = 0;
	}
	sprintf(buf, fmt, val, units[i]);
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

static int
dpg_port_is_configured(struct dpg_port *port)
{
	return port->n_queues != 0;
}

static int
dpg_parse_ip_interval(char *str, uint32_t *ip_start, uint32_t *ip_end)
{
	int rc;
	char *delim;
	struct in_addr addr;

	delim = strchr(str, '-');
	if (delim != NULL) {
		*delim = '\0';
	}

	rc = inet_aton(str, &addr);
	if (rc == 0) {
		return -EINVAL;
	}
	*ip_start = rte_be_to_cpu_32(addr.s_addr);

	if (delim == NULL) {
		*ip_end = *ip_start;
	} else {
		rc = inet_aton(delim + 1, &addr);
		if (rc == 0) {
			return -EINVAL;
		}
		*ip_end = rte_be_to_cpu_32(addr.s_addr);
		if (*ip_end < *ip_start) {
			return -EINVAL;
		}
	}

	return 0;
}

static int
dpg_parse_icmp_id_interval(char *str, uint16_t *id_start, uint16_t *id_end)
{
	unsigned long ul;
	char *delim, *endptr;

	delim = strchr(str, '-');
	if (delim != NULL) {
		*delim = '\0';
	}

	ul = strtoul(str, &endptr, 10);
	if (*endptr != '\0' || ul > UINT16_MAX) {
		return -EINVAL;
	}
	*id_start = ul;

	if (delim == NULL) {
		*id_end = *id_start;
	} else {
		ul = strtoul(delim + 1, &endptr, 10);
		if (*endptr != '\0' || ul > UINT16_MAX || ul < *id_start) {
			return -EINVAL;
		}
		*id_end = ul;
	}

	return 0;
}

static int
dpg_parse_job(struct dpg_job **pjob, struct dpg_job *tmpl, int argc, char **argv)
{
	int rc, opt; 
	uint16_t port_id;
	char *endptr;
	char port_name[RTE_ETH_NAME_MAX_LEN];
	struct dpg_job *job, *tmp;
	struct dpg_lcore *lcore;
	struct dpg_port *port;

	job = malloc(sizeof(*job));
	memcpy(job, tmpl, sizeof(*job));

	while ((opt = getopt(argc, argv, "hl:p:q:REB:A:s:d:i:")) != -1) {
		switch (opt) {
		case 'h':
			dpg_print_usage();
			break;

		case 'l':
			job->lcore_id = strtoul(optarg, &endptr, 10);
			if (*endptr != '\0') {
				dpg_invalid_argument(opt);
			}
			rc = rte_lcore_is_enabled(job->lcore_id);
			if (!rc) {
				dpg_die("DPDK doesn't run on lcore %d\n", job->lcore_id);
			}
			break;

		case 'p':
			job->port_id = -1;
			RTE_ETH_FOREACH_DEV(port_id) {
				rte_eth_dev_get_name_by_port(port_id, port_name);
				if (!strcmp(optarg, port_name)) {
					job->port_id = port_id;
					break;
				}
			}
			if (job->port_id < 0) {
				dpg_die("DPDK doesn't run on port '%s'\n", optarg);		
			}
			break;

		case 'q':
			job->queue_id = strtoul(optarg, &endptr, 10);
			if (*endptr != '\0') {
				dpg_invalid_argument(opt);
			}
			break;

		case 'R':
			job->request = 1;
			break;

		case 'E':
			job->echo = 1;
			break;

		case 'B':
			job->bandwidth = strtoull(optarg, &endptr, 10);
			if (*endptr != '\0') {
				dpg_invalid_argument(opt);
			}
			break;

		case 'A':
			rc = dpg_ether_unformat_addr(optarg, &job->dst_eth_addr);
			if (rc != 0) {
				dpg_invalid_argument(opt);
			}
			break;

		case 's':
			rc = dpg_parse_ip_interval(optarg, &job->src_ip_start, &job->src_ip_end);
			if (rc < 0) {
				dpg_invalid_argument(opt);
			}
			break;

		case 'd':
			rc = dpg_parse_ip_interval(optarg, &job->dst_ip_start, &job->dst_ip_end);
			if (rc < 0) {
				dpg_invalid_argument(opt);
			}
			break;

		case 'i':
			rc = dpg_parse_icmp_id_interval(optarg, &job->icmp_id_start,
					&job->icmp_id_end);
			if (rc < 0) {
				dpg_invalid_argument(opt);
			}
			break;

		default:
			dpg_die("Unknown argument: '-%c'\n", opt);
			break;
		}
	}

	lcore = g_lcores + job->lcore_id;
	tmp = lcore->jobs;
	lcore->jobs = job;
	job->lcore_next = tmp;

	port = g_ports + job->port_id;
	for (tmp = port->jobs; tmp != NULL; tmp = tmp->port_next) {
		if (job->queue_id == tmp->queue_id) {
			rte_eth_dev_get_name_by_port(job->port_id, port_name);
			dpg_die("Duplicate job for port '%s' queue %d\n",
					port_name, job->queue_id);
		}
	}
	port->n_queues = DPG_MAX(port->n_queues, job->queue_id + 1);
	tmp = port->jobs;
	port->jobs = job;
	job->port_next = tmp;

	*pjob = job;

	return optind;
}

static void
dpg_set_ether_hdr_addresses(struct dpg_job *job, struct dpg_ether_hdr *eh)
{
	eh->dst_addr = job->dst_eth_addr;
	eh->src_addr = g_ports[job->port_id].mac_addr;
}

static struct rte_mbuf *
dpg_create_icmp_request(struct dpg_job *job)
{
	struct rte_mbuf *m;
	struct dpg_ether_hdr *eh;
	struct dpg_ipv4_hdr *ih;
	struct dpg_icmp_hdr *ich;

	m = rte_pktmbuf_alloc(g_pktmbuf_pool);
	if (m == NULL) {
		dpg_die("rte_pktmbuf_alloc() failed\n");
	}

	m->next = NULL;
	m->data_len = sizeof(*eh) + sizeof(*ih) + sizeof(*ich);
	m->pkt_len = m->data_len;

	eh = rte_pktmbuf_mtod(m, struct dpg_ether_hdr *);
	ih = (struct dpg_ipv4_hdr *)(eh + 1);
	ich = (struct dpg_icmp_hdr *)(ih + 1);

	eh->ether_type = RTE_BE16(DPG_ETHER_TYPE_IPV4);
	dpg_set_ether_hdr_addresses(job, eh);

	ih->version = 4;
	ih->ihl = sizeof(*ih) / sizeof(uint32_t);
	ih->type_of_service = 0;
	ih->total_length = rte_cpu_to_be_16(sizeof(*ih) + sizeof(*ich));
	ih->packet_id = 0;
	ih->fragment_offset = RTE_BE16(DPG_IPV4_HDR_DF_FLAG);
	ih->time_to_live = 64;
	ih->next_proto_id = IPPROTO_ICMP;
	ih->hdr_checksum = 0;
	ih->src_addr = rte_cpu_to_be_32(job->src_ip_current);
	ih->dst_addr = rte_cpu_to_be_32(job->dst_ip_current);

	ich->icmp_type = DPG_IP_ICMP_ECHO_REQUEST;
	ich->icmp_code = 0;
	ich->icmp_cksum = 0;

	ich->icmp_ident = rte_cpu_to_be_16(job->icmp_id_current);
	ich->icmp_seq_nb = rte_cpu_to_be_16(job->icmp_seq_nb);

	ih->hdr_checksum = dpg_cksum(ih, sizeof(*ih));
	ich->icmp_cksum = dpg_cksum(ich, sizeof(*ich));

	if (job->icmp_id_current < job->icmp_id_end) {
		job->icmp_id_current++;
	} else {
		job->icmp_id_current = job->icmp_id_start;
		if (job->src_ip_current < job->src_ip_end) {
			job->src_ip_current++;
		} else {
			job->src_ip_current = job->src_ip_start;
			if (job->dst_ip_current < job->dst_ip_end) {
				job->dst_ip_current++;
			} else {
				job->dst_ip_current = job->dst_ip_start;
				if (job->icmp_seq_nb < DPG_ICMP_SEQ_NB_END) {
					job->icmp_seq_nb++;
				} else {
					job->icmp_seq_nb = DPG_ICMP_SEQ_NB_START;
				}
			}
		}
	}

	return m;
}

static int
dpg_ip_input(struct dpg_job *job, struct rte_mbuf *m)
{
	int hl;
	struct dpg_ether_hdr *eh;
	struct dpg_ipv4_hdr *ih;
	struct dpg_icmp_hdr *ich;

	eh = rte_pktmbuf_mtod(m, struct dpg_ether_hdr *);
	ih = (struct dpg_ipv4_hdr *)(eh + 1);
	if (m->pkt_len < sizeof(*eh) + sizeof(*ih)) {
		return -EINVAL;
	}

	hl = ih->ihl * sizeof(uint32_t);
	if (hl < sizeof(*ih)) {
		return -EINVAL;
	}
	if (m->pkt_len < sizeof(*eh) + hl) {
		return -EINVAL;
	}

	if (ih->next_proto_id != IPPROTO_ICMP) {
		return -EINVAL;
	}

	ich = (struct dpg_icmp_hdr *)((uint8_t *)ih + hl);
	if (ich->icmp_type != DPG_IP_ICMP_ECHO_REQUEST) {
		return -EINVAL;
	}

	ich->icmp_type = DPG_IP_ICMP_ECHO_REPLY;
	DPG_SWAP(ih->src_addr, ih->dst_addr);
	DPG_SWAP(eh->src_addr, eh->dst_addr);

	ich->icmp_cksum = 0;
	ich->icmp_cksum = dpg_cksum(ich, sizeof(*ich));
	ih->hdr_checksum = 0;
	ih->hdr_checksum = dpg_cksum(ih, hl);

	return 0;
}

static int
dpg_arp_input(struct dpg_job *job, struct rte_mbuf *m)
{
	struct dpg_ether_hdr *eh;
	struct dpg_arp_hdr *ah;

	eh = rte_pktmbuf_mtod(m, struct dpg_ether_hdr *);
	if (m->pkt_len < sizeof(*eh) + sizeof(*ah)) {
		return -EINVAL;
	}

	ah = (struct dpg_arp_hdr *)(eh + 1);
	if (ah->arp_opcode != RTE_BE16(DPG_ARP_OP_REQUEST)) {
		return -EINVAL;
	}

	ah->arp_opcode = RTE_BE16(DPG_ARP_OP_REPLY);
	ah->arp_tha = job->dst_eth_addr;
	ah->arp_sha = g_ports[job->port_id].mac_addr;
	DPG_SWAP(ah->arp_tip, ah->arp_sip);

	return 0;
}

static void
dpg_do_job(struct dpg_job *job)
{
	int i, rc, n_rx, n_reqs, tx_burst, txed;
	uint64_t now, dt;
	struct dpg_ether_hdr *eh;
	struct rte_mbuf *m, *rx_pkts[DPG_MAX_PKT_BURST];

	n_rx = rte_eth_rx_burst(job->port_id, job->queue_id, rx_pkts, DPG_ARRAY_SIZE(rx_pkts));

	dpg_counter_add(&g_ipackets, n_rx);

	for (i = 0; i < n_rx; ++i) {
		m = rx_pkts[i];
		eh = rte_pktmbuf_mtod(m, struct dpg_ether_hdr *);
		if (m->pkt_len < sizeof(*eh)) {
			goto drop;
		}

		switch (eh->ether_type) {
		case RTE_BE16(DPG_ETHER_TYPE_IPV4):
			if (job->echo == 0) {
				goto drop;
			}

			rc = dpg_ip_input(job, m);
			if (rc < 0) {
				goto drop;
			}
			break;
		
		case RTE_BE16(DPG_ETHER_TYPE_ARP):
			rc = dpg_arp_input(job, m);
			if (rc < 0) {
				goto drop;
			}
			break;

		default:
			goto drop;
		}

		dpg_set_ether_hdr_addresses(job, eh);

		if (job->n_tx_pkts < DPG_ARRAY_SIZE(job->tx_pkts)) {
			job->tx_pkts[job->n_tx_pkts++] = m;
			continue;
		}
drop:
		rte_pktmbuf_free(m);
	}

	if (job->request && job->n_tx_pkts < DPG_ARRAY_SIZE(job->tx_pkts)) {
		now = g_microseconds;
		dt = now - job->last_tx_time;
		n_reqs = job->bandwidth * dt / 1000000;

		if (n_reqs >= DPG_ARRAY_SIZE(job->tx_pkts) - job->n_tx_pkts) {
			n_reqs = DPG_ARRAY_SIZE(job->tx_pkts) - job->n_tx_pkts;
			job->last_tx_time = now;
			
		} else {
			job->last_tx_time += n_reqs * 1000000 / job->bandwidth;
		}

		tx_burst = job->n_tx_pkts + n_reqs;

		while (job->n_tx_pkts < tx_burst) {
			job->tx_pkts[job->n_tx_pkts++] = dpg_create_icmp_request(job);
		}
	}

	if (!job->n_tx_pkts) {
		return;
	}
	
	txed = rte_eth_tx_burst(job->port_id, job->queue_id, job->tx_pkts, job->n_tx_pkts);
	memmove(job->tx_pkts, job->tx_pkts + txed,
			(job->n_tx_pkts - txed) * sizeof (struct rte_mbuf *));
	job->n_tx_pkts -= txed;

	dpg_counter_add(&g_opackets, txed);
}

static void
dpg_set_microseconds(void)
{
	g_microseconds = 1000000 * rte_rdtsc() / g_hz;
}

#ifdef DPG_USE_HARDWARE_COUNTERS
static void
dpg_get_stats(uint64_t *ipackets, uint64_t *opackets)
{
	int port_id;
	struct rte_eth_stats stats;

	*ipackets = 0;
	*opackets = 0;

	RTE_ETH_FOREACH_DEV(port_id) {
		if (!dpg_port_is_configured(g_ports + port_id)) {
			continue;
		}

		rte_eth_stats_get(port_id, &stats);

		*ipackets += stats.ipackets;
		*opackets += stats.opackets;
	}
}
#else // DPG_USE_HARDWARE_COUNTERS
static void
dpg_get_stats(uint64_t *ipackets, uint64_t *opackets)
{
	*ipackets = dpg_counter_get(&g_ipackets);
	*opackets = dpg_counter_get(&g_opackets);
}
#endif // DPG_USE_HARDWARE_COUNTERS

static int
lcore_loop(void *dummy)
{
	int p, reports;
	char ipps_b[40], opps_b[40];
	uint64_t last_stats_time;
	uint64_t ipackets[2], opackets[2];
	uint64_t ipps, opps;
	double dt;
	struct dpg_lcore *lcore;
	struct dpg_job *job;

	lcore = g_lcores + rte_lcore_id();

	for (job = lcore->jobs; job != NULL; job = job->lcore_next) {
		job->last_tx_time = g_microseconds;

		job->icmp_seq_nb = DPG_ICMP_SEQ_NB_START;
		job->src_ip_current = job->src_ip_start;
		job->dst_ip_current = job->dst_ip_start;
		job->icmp_id_current = job->icmp_id_start;
	}
	
	if (lcore->is_first) {
		reports = 0;
		p = 0;
		dpg_get_stats(&ipackets[p], &opackets[p]);
		p = 1 - p;
	}

	last_stats_time = g_microseconds;

	for (;;) {
		if (lcore->is_first) {
			dpg_set_microseconds();
		}

		for (job = lcore->jobs; job != NULL; job = job->lcore_next) {
			dpg_do_job(job);
		}

		if (lcore->is_first && g_microseconds - last_stats_time >= 1000000) {
			dt = g_microseconds - last_stats_time;
			last_stats_time = g_microseconds;
			dpg_get_stats(&ipackets[p], &opackets[p]);
			ipps = (ipackets[p] - ipackets[1 - p]) / dt * 1000000;
			opps = (opackets[p] - opackets[1 - p]) / dt * 1000000;
			p = 1 - p;

			if (reports == 20) {
				reports = 0;
			}
			if (reports == 0) {
				printf("%-12s%-12s\n", "ipps", "opps");
			}
			dpg_norm(ipps_b, ipps, 1);
			dpg_norm(opps_b, opps, 1);
			printf("%-12s%-12s\n", ipps_b, opps_b);
			reports++;
		}
	}

	return 0;
}

int
main(int argc, char **argv)
{
	int i, rc, port_id, n_rxq, n_txq, n_mbufs, main_lcore, first_lcore;
	char mac_addr_buf[DPG_ETHER_ADDR_FMT_SIZE];
	char port_name[RTE_ETH_NAME_MAX_LEN];
	struct rte_eth_dev_info dev_info;
	struct rte_eth_rxconf rxq_conf;
	struct rte_eth_txconf txq_conf;
	struct dpg_job tmpl_instance, *job, *tmpl;
	struct dpg_port *port;
	struct dpg_lcore *lcore;

	rc = rte_eal_init(argc, argv);
	if (rc < 0) {
		dpg_die("rte_eal_init() failed (%d:%s)\n", -rc, rte_strerror(-rc));
	}

	argc -= rc;
	argv += rc;

	main_lcore = rte_lcore_id();
	tmpl = &tmpl_instance;
	memset(tmpl, 0, sizeof(*tmpl));
	tmpl->lcore_id = main_lcore;
	tmpl->bandwidth = 100000000llu; // 100 mpps
	for (i = 0; i < DPG_ARRAY_SIZE(tmpl->dst_eth_addr.addr_bytes); ++i) {
		tmpl->dst_eth_addr.addr_bytes[i] = 0xFF;
	}
	dpg_parse_ip_interval("1.1.1.1", &tmpl->src_ip_start, &tmpl->src_ip_end);
	dpg_parse_ip_interval("2.2.2.2", &tmpl->dst_ip_start, &tmpl->dst_ip_end);
	tmpl->icmp_id_start = tmpl->icmp_id_end = 1;

	while (argc > 1) {
		rc = dpg_parse_job(&job, tmpl, argc, argv);

		argc -= (rc - 1);
		argv += (rc - 1);
		optind = 1;

		tmpl = job;
	}

	n_mbufs = DPG_MEMPOOL_CACHE_SIZE;

	RTE_ETH_FOREACH_DEV(port_id) {
		port = g_ports + port_id;
		if (!dpg_port_is_configured(port)) {
			continue;
		}

		rte_eth_dev_get_name_by_port(port_id, port_name);

		rc = rte_eth_dev_info_get(port_id, &dev_info);
		if (rc < 0) {
			dpg_die("rte_eth_dev_info_get('%s') failed (%d:%s)\n",
					port_name, -rc, rte_strerror(-rc));
		}

		port->conf = g_port_conf;
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

		dpg_ether_format_addr(mac_addr_buf, sizeof(mac_addr_buf), &port->mac_addr);
		printf("Port '%s': %s\n", port_name, mac_addr_buf);

		n_mbufs += n_rxq * port->n_rxd;
		n_mbufs += n_txq * (port->n_txd + DPG_MAX_PKT_BURST);
	}

	n_mbufs *= 2;
	n_mbufs = DPG_MAX(n_mbufs, 8192);

	g_pktmbuf_pool = rte_pktmbuf_pool_create("mbuf_pool", n_mbufs,
			DPG_MEMPOOL_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());

	if (g_pktmbuf_pool == NULL) {
		dpg_die("rte_pktmbuf_pool_create(%d) failed\n", n_mbufs);
	}

	RTE_ETH_FOREACH_DEV(port_id) {
		port = g_ports + port_id;
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
					g_pktmbuf_pool);
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
	}

	g_hz = rte_get_tsc_hz();
	dpg_set_microseconds();

	first_lcore = -1;
	RTE_LCORE_FOREACH(i) {
		lcore = g_lcores + i;
		if (lcore->jobs == NULL) {
			continue;
		}
		if (first_lcore < 0) {
			first_lcore = i;
			lcore->is_first = 1;
		}
		if (i != main_lcore) {
			rte_eal_remote_launch(lcore_loop, NULL, i);
		}
	}

	lcore = g_lcores + main_lcore;
	if (lcore->jobs != NULL) {
		lcore_loop(NULL);
	}

	RTE_LCORE_FOREACH(i) {
		lcore = g_lcores + i;
		if (lcore->jobs == NULL) {
			continue;
		}
		if (i != main_lcore) {
			rte_eal_wait_lcore(i);
		}
	}

	return 0;
}
