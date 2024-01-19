// SPDX-License-Identifier: GPL-2.0-only

#include <arpa/inet.h>
#include <assert.h>
#include <getopt.h>
#include <math.h>
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

#define DPG_PKT_LEN_MIN 60

#define DPG_ETHER_ADDR_FMT_SIZE 18

#define DPG_IP_ICMP_ECHO_REPLY 0
#define DPG_IP_ICMP_ECHO_REQUEST 8

#define DPG_IPPROTO_ICMPV6 56

#define DPG_ETHER_TYPE_ARP 0x0806
#define DPG_ETHER_TYPE_IPV4 0x0800
#define DPG_ETHER_TYPE_IPV6 0x86DD

#define DPG_IPV4_HDR_DF_FLAG (1 << 6)

#define	DPG_ARP_OP_REQUEST 1
#define	DPG_ARP_OP_REPLY 2

#define DPG_MEMPOOL_CACHE_SIZE 128
#define DPG_MAX_PKT_BURST 128
#define DPG_TXBUF_SIZE DPG_MAX_PKT_BURST

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
} __attribute__((packed)) __attribute__((aligned(2)));

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
} __attribute__((packed)) __attribute__((aligned(2)));

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
} __attribute__((packed)) __attribute__((aligned(2)));

struct dpg_icmp_hdr {
	uint8_t icmp_type;
	uint8_t icmp_code;
	rte_be16_t icmp_cksum;
	rte_be16_t icmp_ident;
	rte_be16_t icmp_seq_nb;
} __attribute__((packed)) __attribute__((aligned(2)));

struct dpg_ipv6_hdr {
	rte_be32_t vtc_flow;
	rte_be16_t payload_len;
	uint8_t proto;
	uint8_t hop_limits;
	uint8_t src_addr[16];
	uint8_t  dst_addr[16];
} __attribute__((packed)) __attribute__((aligned(2)));

struct dpg_srv6_hdr {
	uint8_t next_header;
	uint8_t hdr_ext_len;
	uint8_t routing_type;
	uint8_t segments_left;
	uint8_t last_entry;
	uint8_t flags;
	rte_be16_t tag;
	uint8_t localsid[16];
} __attribute__((packed)) __attribute__((aligned(2)));

struct dpg_job {
	struct dpg_job *lcore_next;
	struct dpg_job *port_next;

	int do_req;
	int do_echo;

	int verbose;

	int port_id;
	int queue_id;

	int lcore_id;

	int req_rate;
	uint64_t req_tx_time;

	dpg_ether_addr_t dst_eth_addr;

	uint32_t src_ip_current;
	uint32_t src_ip_start;
	uint32_t src_ip_end;

	uint32_t dst_ip_current;
	uint32_t dst_ip_start;
	uint32_t dst_ip_end;

	uint16_t icmp_id_current;
	uint16_t icmp_id_start;
	uint16_t icmp_id_end;

	uint16_t icmp_seq_current;
	uint16_t icmp_seq_start;
	uint16_t icmp_seq_end;

	int tunnel;
	uint8_t tunnel_src[16];
	uint8_t tunnel_dst[16];
	uint8_t srv6_localsid[16];
	uint16_t pkt_len;

	int tx_bytes;
	int n_tx_pkts;
	struct rte_mbuf *tx_pkts[DPG_TXBUF_SIZE];
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
	uint64_t tsc;
	int is_first;
};

static uint64_t g_hz;
static struct dpg_port g_ports[RTE_MAX_ETHPORTS];
static struct dpg_lcore g_lcores[RTE_MAX_LCORE];
static struct rte_mempool *g_pktmbuf_pool;
static struct rte_eth_conf g_port_conf;
static int g_bflag;
static int g_Hflag;
struct dpg_counter g_ipackets;
struct dpg_counter g_opackets;
struct dpg_counter g_ibytes;
struct dpg_counter g_obytes;

#define DPG_SWAP(a, b) do { \
	typeof(a) tmp = a; \
	a = b; \
	b = tmp; \
} while (0)

#define DPG_MIN(a, b) ((a) < (b) ? (a) : (b))
#define DPG_MAX(a, b) ((a) > (b) ? (a) : (b))

#define DPG_ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))

#define dpg_die(...) \
	rte_exit(EXIT_FAILURE, ##__VA_ARGS__);

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

static int
dpg_memcmpz(const void *ptr, size_t n)
{
	uint8_t rc;
	size_t i;

	for (i = 0; i < n; ++i) {
		rc = ((const uint8_t *)ptr)[i];
		if (rc) {
			return rc;
		}
	}
	return 0;
}

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
dpg_invalid_argument(int short_name, const char *long_name)
{
	if (long_name != NULL) {
		dpg_die("Invalid argument: '--%s'", long_name);
	} else {
		dpg_die("Invalid argument: '-%c'", short_name);
	}
}

static void
dpg_argument_not_specified(int short_name, const char *long_name)
{
	if (long_name != NULL) {
		dpg_die("Argument '--%s' not specified", long_name);
	} else {
		dpg_die("Argument '-%c' not specified", short_name);
	}
}

static void
dpg_print_usage()
{
	int rc, port_id;
	dpg_ether_addr_t mac_addr;
	char mac_addr_buf[DPG_ETHER_ADDR_FMT_SIZE];
	char port_name[RTE_ETH_NAME_MAX_LEN];

	printf("Usage: dpdk-ping [DPDK options] -- job [-- job [-- job ...]]\n"
	"\n"
	"Job:\n"
	"\t-h:  Print this help\n"
	"\t-V:  Be verbose\n"
	"\t-Q:  Be quiet\n"
	"\t-b:  Print bits/sec in report\n"
	"\t-l {lcore id}:  Lcore to run on\n"
	"\t-p {port name}:  Port to run on\n"
	"\t-q {queue id}:  RSS queue id to run on\n"
	"\t-R:  Send ICMP echo requests\n"
	"\t-E:  Send ICMP echo reply on incoming ICMP echo requests\n"
	"\t-B {packets per second}:  ICMP requests bandwidth\n"
	"\t-A {ether address}:  Destination ethernet address\n"
	"\t-s {ip[-ip]}:  Source ip addresses interval\n"
	"\t-d {ip[-ip]}:  Destination ip addresses interval\n"
	"\t-L { bytes }:  Packet size\n"
	"\t-H:  Use hardware statistics\n"
	"\t--icmp-id {id[-id]}:  ICMP request id interval\n"
	"\t--icmp-seq {seq[-seq]}:  ICMP request sequence interval\n"
	"\t--srv6-tunnel: Encapsulate packet to srv6\n"
	"\t--tunnel-src {ipv6}:  Tunnel source address\n"
	"\t--tunnel-dst {ipv6}:  Tunnel destination address\n"
	"\t--srv6-localsid:  Localsid for srv6 tunnel\n"
	"Ports:\n"
	);

	RTE_ETH_FOREACH_DEV(port_id) {
		rte_eth_dev_get_name_by_port(port_id, port_name);
		printf("%s", port_name);

		rc = dpg_eth_macaddr_get(port_id, &mac_addr);
		if (rc == 0) {
			dpg_ether_format_addr(mac_addr_buf, sizeof(mac_addr_buf), &mac_addr);
			printf("  %s", mac_addr_buf);
		}
		printf("\n");
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
dpg_cksum_raw(const uint8_t *b, int size)
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
dpg_log_icmp(struct dpg_job *job, int tx, int tunnel,
		struct dpg_ipv4_hdr *ih, struct dpg_icmp_hdr *ich)
{
	char port_name[RTE_ETH_NAME_MAX_LEN];
	char sabuf[INET_ADDRSTRLEN];
	char dabuf[INET_ADDRSTRLEN];

	rte_eth_dev_get_name_by_port(job->port_id, port_name);
	inet_ntop(AF_INET, &ih->src_addr, sabuf, sizeof(sabuf));
	inet_ntop(AF_INET, &ih->dst_addr, dabuf, sizeof(dabuf));

	printf("%s (txq=%d): %s %sicmp echo %s: %s->%s, id=%d, seq=%d\n",
			port_name, job->queue_id,
			tx ? "Sent" : "Recv",
			tunnel ? "encap " : "",
			dpg_icmp_type_string(ich->icmp_type),
			sabuf, dabuf,
			rte_be_to_cpu_16(ich->icmp_ident),
			rte_be_to_cpu_16(ich->icmp_seq_nb));
}

static void
dpg_log_custom(struct dpg_job *job, const char *proto)
{
	char port_name[RTE_ETH_NAME_MAX_LEN];

	rte_eth_dev_get_name_by_port(job->port_id, port_name);
	printf("%s (txq=%d): Recv %s packet\n", port_name, job->queue_id, proto);
}

static uint64_t
dpg_rdtsc(void)
{
	return g_lcores[rte_lcore_id()].tsc;
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
dpg_parse_uint16_interval(char *str, uint16_t *id_start, uint16_t *id_end)
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
	int opt, option_index, do_echo, do_req, queue_id;
	int64_t rc;
	uint16_t port_id;
	char *endptr;
	const char *optname;
	char port_name[RTE_ETH_NAME_MAX_LEN];
	struct dpg_job *job, *tmp;
	struct dpg_lcore *lcore;
	struct dpg_port *port;

	static struct option long_options[] = {
		{ "help", no_argument, 0, 'h' },
		{ "icmp-id", required_argument, 0, 0 },
		{ "icmp-seq", required_argument, 0, 0 },
		{ "no-tunnel", no_argument, 0, 0 },
		{ "tunnel-src", required_argument, 0, 0 },
		{ "tunnel-dst", required_argument, 0, 0 },
		{ "srv6-tunnel", no_argument, 0, 0 },
		{ "srv6-localsid", required_argument, 0, 0 },
	};

	job = malloc(sizeof(*job));
	memcpy(job, tmpl, sizeof(*job));
	do_echo = do_req = queue_id = -1;

	while ((opt = getopt_long(argc, argv, "hVQbl:p:q:REB:A:s:d:L:H",
			long_options, &option_index)) != -1) {
		switch (opt) {
		case 0:
			optname = long_options[option_index].name;
			if (!strcmp(optname, "icmp-id")) {
				rc = dpg_parse_uint16_interval(optarg, &job->icmp_id_start,
						&job->icmp_id_end);
				if (rc < 0) {
					dpg_invalid_argument(0, optname);
				}
			} else if (!strcmp(optname, "icmp-seq")) {
				rc = dpg_parse_uint16_interval(optarg, &job->icmp_seq_start,
						&job->icmp_seq_end);
				if (rc < 0) {
					dpg_invalid_argument(0, optname);
				}
			} else if (!strcmp(optname, "no-tunnel")) {
				job->tunnel = 0;
			} else if (!strcmp(optname, "tunnel-src")) {
				if (inet_pton(AF_INET6, optarg, job->tunnel_src) != 1) {
					dpg_invalid_argument(0, optname);
				}
			} else if (!strcmp(optname, "tunnel-dst")) {
				if (inet_pton(AF_INET6, optarg, job->tunnel_dst) != 1) {
					dpg_invalid_argument(0, optname);
				}
			} else if (!strcmp(optname, "srv6-tunnel")) {
				job->tunnel = 1;
			} else if (!strcmp(optname, "srv6-localsid")) {
				if (inet_pton(AF_INET6, optarg, job->srv6_localsid) != 1) {
					dpg_invalid_argument(0, optname);
				}
			}
			break;

		case 'h':
			dpg_print_usage();
			break;

		case 'V':
			job->verbose = 1;
			break;

		case 'Q':
			job->verbose = 0;
			break;

		case 'b':
			g_bflag = 1;
			break;

		case 'l':
			job->lcore_id = strtoul(optarg, &endptr, 10);
			if (*endptr != '\0') {
				dpg_invalid_argument(opt, NULL);
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
			queue_id = strtoul(optarg, &endptr, 10);
			if (*endptr != '\0') {
				dpg_invalid_argument(opt, NULL);
			}
			break;

		case 'R':
			do_req = 1;
			break;

		case 'E':
			do_echo = 1;
			break;

		case 'B':
			rc = dpg_unnorm(optarg);
			if (rc < 0) {
				dpg_invalid_argument(opt, NULL);
			}
			job->req_rate = rc;
			break;

		case 'A':
			rc = dpg_ether_unformat_addr(optarg, &job->dst_eth_addr);
			if (rc != 0) {
				dpg_invalid_argument(opt, NULL);
			}
			break;

		case 's':
			rc = dpg_parse_ip_interval(optarg, &job->src_ip_start, &job->src_ip_end);
			if (rc < 0) {
				dpg_invalid_argument(opt, NULL);
			}
			break;

		case 'd':
			rc = dpg_parse_ip_interval(optarg, &job->dst_ip_start, &job->dst_ip_end);
			if (rc < 0) {
				dpg_invalid_argument(opt, NULL);
			}
			break;

		case 'L':
			job->pkt_len = strtoul(optarg, &endptr, 10);
			if (*endptr != '\0' || job->pkt_len < DPG_PKT_LEN_MIN) {
				dpg_invalid_argument(opt, NULL);
			}
			break;

		case 'H':
			g_Hflag = 1;
			break;

		default:
			dpg_die("Unknown argument: '-%c'\n", opt);
			break;
		}
	}

	if (optind < argc && strcmp(argv[optind - 1], "--")) {
		dpg_die("Unknown input: '%s'\n", argv[optind]);
	}

	lcore = g_lcores + job->lcore_id;
	tmp = lcore->jobs;
	lcore->jobs = job;
	job->lcore_next = tmp;

	if (job->port_id == tmpl->port_id) {
		if (do_req < 0) {
			do_req = tmpl->do_req;
		}
		if (do_echo < 0) {
			do_echo = tmpl->do_echo;
		}
		if (queue_id < 0) {
			queue_id = tmpl->queue_id;
		}
	} else {
		if (do_req < 0) {
			do_req = 0;
		}
		if (do_echo < 0) {
			do_echo = 0;
		}
		if (queue_id < 0) {
			queue_id = 0;
		}
	}
	job->do_req = do_req;
	job->do_echo = do_echo;
	job->queue_id = queue_id;

	if (job->tunnel) {
		if (!dpg_memcmpz(job->tunnel_src, sizeof(job->tunnel_src))) {
			dpg_argument_not_specified(0, "tunnel-src");
		}
		if (!dpg_memcmpz(job->tunnel_dst, sizeof(job->tunnel_src))) {
			dpg_argument_not_specified(0, "tunnel-dst");
		}
		if (!dpg_memcmpz(job->srv6_localsid, sizeof(job->srv6_localsid))) {
			dpg_argument_not_specified(0, "srv6-localsid");
		}
	}

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
	int ih_total_length, pkt_len;
	struct rte_mbuf *m;
	struct dpg_ether_hdr *eh;
	struct dpg_ipv4_hdr *ih;
	struct dpg_ipv6_hdr *ih6;
	struct dpg_icmp_hdr *ich;
	struct dpg_srv6_hdr *srh;

	m = rte_pktmbuf_alloc(g_pktmbuf_pool);
	if (m == NULL) {
		dpg_die("rte_pktmbuf_alloc() failed\n");
	}

	eh = rte_pktmbuf_mtod(m, struct dpg_ether_hdr *);

	pkt_len = sizeof(*eh) + sizeof(*ih) + sizeof(*ich);

	if (job->tunnel) {
		pkt_len += sizeof(*ih6) + sizeof(*srh);

		m->pkt_len = DPG_MAX(job->pkt_len, pkt_len);
		ih_total_length = m->pkt_len - (sizeof(*eh) + sizeof(*ih6) + sizeof(*srh));

		eh->ether_type = RTE_BE16(DPG_ETHER_TYPE_IPV6);
		ih6 = (struct dpg_ipv6_hdr *)(eh + 1);
		srh = (struct dpg_srv6_hdr *)(ih6 + 1);
		ih = (struct dpg_ipv4_hdr *)(srh + 1);

		ih6->vtc_flow = rte_cpu_to_be_32(0x60000000);
		ih6->payload_len = rte_cpu_to_be_16(m->pkt_len - (sizeof(*eh) + sizeof(*ih6)));
		ih6->proto = IPPROTO_ROUTING;
		ih6->hop_limits = 64;
		memcpy(ih6->src_addr, job->tunnel_src, sizeof(ih6->src_addr));
		memcpy(ih6->dst_addr, job->tunnel_dst, sizeof(ih6->dst_addr));

		srh->next_header = IPPROTO_IPIP;
		srh->hdr_ext_len = sizeof(*srh) / 8 - 1;
		srh->routing_type = 4; // Segment Routing v6
		srh->segments_left = 0;
		srh->last_entry = 0;
		srh->flags = 0;
		srh->tag = 0;
		memcpy(srh->localsid, job->srv6_localsid, sizeof(srh->localsid));
	} else {
		m->pkt_len = DPG_MAX(job->pkt_len, pkt_len);
		ih_total_length = m->pkt_len - sizeof(*eh);

		eh->ether_type = RTE_BE16(DPG_ETHER_TYPE_IPV4);
		ih = (struct dpg_ipv4_hdr *)(eh + 1);
	}

	m->next = NULL;
	m->data_len = m->pkt_len;

	ich = (struct dpg_icmp_hdr *)(ih + 1);

	dpg_set_ether_hdr_addresses(job, eh);

	ih->version = 4;
	ih->ihl = sizeof(*ih) / sizeof(uint32_t);
	ih->type_of_service = 0;
	ih->total_length = rte_cpu_to_be_16(ih_total_length);
	ih->packet_id = 0;
	ih->fragment_offset = 0;
	ih->time_to_live = 64;
	ih->next_proto_id = IPPROTO_ICMP;
	ih->hdr_checksum = 0;
	ih->src_addr = rte_cpu_to_be_32(job->src_ip_current);
	ih->dst_addr = rte_cpu_to_be_32(job->dst_ip_current);

	ich->icmp_type = DPG_IP_ICMP_ECHO_REQUEST;
	ich->icmp_code = 0;
	ich->icmp_cksum = 0;

	ich->icmp_ident = rte_cpu_to_be_16(job->icmp_id_current);
	ich->icmp_seq_nb = rte_cpu_to_be_16(job->icmp_seq_current);

	ih->hdr_checksum = dpg_cksum(ih, sizeof(*ih));
	ich->icmp_cksum = dpg_cksum(ich, sizeof(*ich));

	m->pkt_len = DPG_MAX(pkt_len, job->pkt_len);
	m->data_len = m->pkt_len;

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
				if (job->icmp_seq_current < job->icmp_seq_end) {
					job->icmp_seq_current++;
				} else {
					job->icmp_seq_current = job->icmp_seq_start;
				}
			}
		}
	}

	if (job->verbose) {
		dpg_log_icmp(job, 1, job->tunnel, ih, ich);
	}

	return m;
}

static int
dpg_ip_input(struct dpg_job *job, int tunnel, void *ptr, int len)
{
	int hl;
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
	ich = (struct dpg_icmp_hdr *)((uint8_t *)ih + hl);
	if (ich->icmp_type != DPG_IP_ICMP_ECHO_REQUEST) {
		return -EINVAL;
	}

	if (job->verbose) {
		dpg_log_icmp(job, 0, tunnel, ih, ich);
	}

	if (!job->do_echo) {
		return -ENOTSUP;
	}

	ich->icmp_type = DPG_IP_ICMP_ECHO_REPLY;
	DPG_SWAP(ih->src_addr, ih->dst_addr);

	ich->icmp_cksum = 0;
	ich->icmp_cksum = dpg_cksum(ich, sizeof(*ich));
	ih->hdr_checksum = 0;
	ih->hdr_checksum = dpg_cksum(ih, hl);

	if (job->verbose) {
		dpg_log_icmp(job, 1, tunnel, ih, ich);
	}

	return 0;
}

static void
dpg_ipv6_input(struct dpg_job *job, struct rte_mbuf *m)
{
	int rc, hl, len, proto;
	uint8_t *ptr;
	char name[64];
	struct dpg_ether_hdr *eh;
	struct dpg_ipv6_hdr *ih;
	struct dpg_srv6_hdr *srh;

	eh = rte_pktmbuf_mtod(m, struct dpg_ether_hdr *);
	ih = (struct dpg_ipv6_hdr *)(eh + 1);

	if (m->pkt_len < sizeof(*eh) + sizeof(*ih)) {
		goto malformed;
	}

	len = rte_be_to_cpu_16(ih->payload_len);
	if (m->pkt_len < sizeof(*eh) + sizeof(*ih) + len) {
		goto malformed;
	}

	ptr = (uint8_t *)(ih + 1);
	proto = ih->proto;

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
			// TODO: NDP
			goto out;	

		case IPPROTO_IPIP:
			rc = dpg_ip_input(job, 1, ptr, len);
			if (rc == -EINVAL) {
				goto out;
			}
			return;

		default:
			goto out;
		}
	}

out:
	if (job->verbose) {
		snprintf(name, sizeof(name), "IPv6 (proto=%d)", proto);
		dpg_log_custom(job, name);
	}
	return;

malformed:
	if (job->verbose) {
		dpg_log_custom(job, "Malformed IPv6");
	}
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
dpg_add_tx(struct dpg_job *job, struct rte_mbuf *m)
{
	job->tx_bytes += m->pkt_len;
	job->tx_pkts[job->n_tx_pkts++] = m;
}

static int
dpg_req_ratelimit(struct dpg_job *job, int rate)
{
	int n_reqs, room, dp;
	uint64_t tsc, dt;

	room = DPG_TXBUF_SIZE - job->n_tx_pkts;

	tsc = dpg_rdtsc();
	dt = tsc - job->req_tx_time;

	dp = rate * dt / g_hz;

	n_reqs = DPG_MIN(dp, room);

	job->req_tx_time += n_reqs * g_hz / rate;

	return n_reqs;
}

static void
dpg_do_job(struct dpg_job *job)
{
	int i, rc, n_rx, n_reqs, room, txed, rx_bytes, tx_bytes;
	struct dpg_ether_hdr *eh;
	struct rte_mbuf *m, *rx_pkts[DPG_MAX_PKT_BURST];
	char proto[32];

	rx_bytes = 0;
	n_rx = rte_eth_rx_burst(job->port_id, job->queue_id, rx_pkts, DPG_ARRAY_SIZE(rx_pkts));

	for (i = 0; i < n_rx; ++i) {
		m = rx_pkts[i];
		eh = rte_pktmbuf_mtod(m, struct dpg_ether_hdr *);
		rx_bytes += m->data_len;
		if (m->pkt_len < sizeof(*eh)) {
			goto drop;
		}

		switch (eh->ether_type) {
		case RTE_BE16(DPG_ETHER_TYPE_IPV4):
			rc = dpg_ip_input(job, 0, eh + 1, m->pkt_len - sizeof(*eh));
			if (rc == -EINVAL) {
				if (job->verbose) {
					dpg_log_custom(job, "IP");
				}
			}
			if (rc < 0) {
				goto drop;
			}
			break;

		case RTE_BE16(DPG_ETHER_TYPE_IPV6):
			dpg_ipv6_input(job, m);
			goto drop;
		
		case RTE_BE16(DPG_ETHER_TYPE_ARP):
			if (job->verbose) {
				dpg_log_custom(job, "ARP");
			}
			rc = dpg_arp_input(job, m);
			if (rc < 0) {
				goto drop;
			}
			break;

		default:
			if (job->verbose) {
				snprintf(proto, sizeof(proto), "proto_0x%04hx",
						rte_be_to_cpu_16(eh->ether_type));
				dpg_log_custom(job, proto);
			}
			goto drop;
		}

		dpg_set_ether_hdr_addresses(job, eh);

		if (job->n_tx_pkts < DPG_TXBUF_SIZE) {
			dpg_add_tx(job, m);
			continue;
		}
drop:
		rte_pktmbuf_free(m);
	}

	room = DPG_TXBUF_SIZE - job->n_tx_pkts;
	if (job->do_req && room) {
		if (job->req_rate) {
			n_reqs = dpg_req_ratelimit(job, job->req_rate);
		} else {
			n_reqs = room;
		}

		for (i = 0; i < n_reqs; ++i) {
			m = dpg_create_icmp_request(job);
			dpg_add_tx(job, m);
		}
	}

	if (job->n_tx_pkts) {
		txed = rte_eth_tx_burst(job->port_id, job->queue_id, job->tx_pkts, job->n_tx_pkts);
		memmove(job->tx_pkts, job->tx_pkts + txed,
				(job->n_tx_pkts - txed) * sizeof (struct rte_mbuf *));
		job->n_tx_pkts -= txed;
	} else {
		txed = 0;
	}

	if (!g_Hflag) {
		tx_bytes = job->tx_bytes;
		job->tx_bytes = 0;

		for (i = 0; i < job->n_tx_pkts; ++i) {
			job->tx_bytes += job->tx_pkts[i]->pkt_len;
		}

		dpg_counter_add(&g_ipackets, n_rx);
		dpg_counter_add(&g_ibytes, rx_bytes);

		dpg_counter_add(&g_opackets, txed);
		dpg_counter_add(&g_obytes, tx_bytes - job->tx_bytes);
	}
}

static void
dpg_get_stats(uint64_t *ipackets, uint64_t *ibytes, uint64_t *opackets, uint64_t *obytes)
{
	int port_id;
	struct rte_eth_stats stats;

	*ipackets = 0;
	*ibytes = 0;
	*opackets = 0;
	*obytes = 0;

	if (g_Hflag) {
		RTE_ETH_FOREACH_DEV(port_id) {
			if (!dpg_port_is_configured(g_ports + port_id)) {
				continue;
			}

			rte_eth_stats_get(port_id, &stats);

			*ipackets += stats.ipackets;
			*ibytes += stats.ibytes;
			*opackets += stats.opackets;
			*obytes += stats.obytes;
		}
	} else {
		*ipackets = dpg_counter_get(&g_ipackets);
		*ibytes = dpg_counter_get(&g_ibytes);
		*opackets = dpg_counter_get(&g_opackets);
		*obytes = dpg_counter_get(&g_obytes);
	}
}

static void
dpg_print_stat(double d_tsc)
{
	uint64_t dip, ipps, dib, ibps, dop, opps, dob, obps;
	char ipps_b[40], ibps_b[40], opps_b[40], obps_b[40];
	static uint64_t ipackets[2], ibytes[2], opackets[2], obytes[2];
	static int p, reports;

	dpg_get_stats(&ipackets[p], &ibytes[p], &opackets[p], &obytes[p]);
	dip = ipackets[p] - ipackets[1 - p];
	dib = ibytes[p] - ibytes[1 - p];
	dop = opackets[p] - opackets[1 - p];
	dob = obytes[p] - obytes[1 - p];

	if (0) {
		ipps = ceil(dip * g_hz / d_tsc);
		ibps = ceil(8 * dip * g_hz / d_tsc);
		opps = ceil(dop * g_hz / d_tsc);
		obps = ceil(8 * dob * g_hz / d_tsc);
	} else {
		ipps = dip;
		ibps = dib;
		opps = dop;
		obps = dob;
	}

	p = 1 - p;

	if (reports == 20) {
		reports = 0;
	}
	if (reports == 0) {
		printf("%-12s", "ipps");
		if (g_bflag) {
			printf("%-12s", "ibps");
		}
		printf("%-12s", "opps");
		if (g_bflag) {
			printf("%-12s", "obps");
		}
		printf("\n");
	}
	dpg_norm(ipps_b, ipps, 1);
	dpg_norm(ibps_b, ibps, 1);
	dpg_norm(opps_b, opps, 1);
	dpg_norm(obps_b, obps, 1);

	printf("%-12s", ipps_b);
	if (g_bflag) {
		printf("%-12s", ibps_b);
	}
	printf("%-12s", opps_b);
	if (g_bflag) {
		printf("%-12s", obps_b);
	}
	printf("\n");

	reports++;
}

static int
dpg_lcore_loop(void *dummy)
{
	uint64_t stat_time, tsc;
	struct dpg_lcore *lcore;
	struct dpg_job *job;

	lcore = g_lcores + rte_lcore_id();

	tsc = rte_rdtsc();
	stat_time = tsc;

	for (job = lcore->jobs; job != NULL; job = job->lcore_next) {
		job->src_ip_current = job->src_ip_start;
		job->dst_ip_current = job->dst_ip_start;
		job->icmp_id_current = job->icmp_id_start;
		job->icmp_seq_current = job->icmp_seq_start;
		job->req_tx_time = tsc;
	}

	for (;;) {
		lcore->tsc = rte_rdtsc();

		for (job = lcore->jobs; job != NULL; job = job->lcore_next) {
			dpg_do_job(job);
		}

		if (lcore->is_first) {
			tsc = lcore->tsc;
			if (tsc - stat_time >= g_hz) {
				dpg_print_stat(tsc - stat_time);
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
	struct dpg_job tmpl_instance, *job, *tmpl;
	struct dpg_port *port;
	struct dpg_lcore *lcore;

	rc = rte_eal_init(argc, argv);
	if (rc < 0) {
		dpg_die("rte_eal_init() failed (%d:%s)\n", -rc, rte_strerror(-rc));
	}

	argc -= rc;
	argv += rc;

	g_hz = rte_get_tsc_hz();

	g_port_conf.txmode.mq_mode = DPG_ETH_MQ_TX_NONE;

	main_lcore = rte_lcore_id();
	tmpl = &tmpl_instance;
	memset(tmpl, 0, sizeof(*tmpl));
	tmpl->lcore_id = main_lcore;
	for (i = 0; i < DPG_ARRAY_SIZE(tmpl->dst_eth_addr.addr_bytes); ++i) {
		tmpl->dst_eth_addr.addr_bytes[i] = 0xFF;
	}
	dpg_parse_ip_interval("1.1.1.1", &tmpl->src_ip_start, &tmpl->src_ip_end);
	dpg_parse_ip_interval("2.2.2.2", &tmpl->dst_ip_start, &tmpl->dst_ip_end);
	tmpl->icmp_id_start = tmpl->icmp_id_end = 1;
	tmpl->icmp_seq_start = tmpl->icmp_seq_end = 1;
	tmpl->pkt_len = DPG_PKT_LEN_MIN;

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
			rte_eal_remote_launch(dpg_lcore_loop, NULL, i);
		}
	}

	lcore = g_lcores + main_lcore;
	if (lcore->jobs != NULL) {
		dpg_lcore_loop(NULL);
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
