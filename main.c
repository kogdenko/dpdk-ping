#include <getopt.h>
#include <stdlib.h>

#include <rte_bus.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_common.h>
#include <rte_mbuf.h>
#include <rte_pci.h>

#define DPG_ICMP_SEQ_NB_START 1
#define DPG_ICMP_SEQ_NB_END 50000

#define DPG_MEMPOOL_CACHE_SIZE 128
#define DPG_MAX_PKT_BURST 256

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

	struct rte_ether_addr dst_eth_addr;

	uint32_t icmp_seq_nb;

	uint32_t src_ip_current;
	uint32_t src_ip_start;
	uint32_t src_ip_end;

	uint32_t dst_ip_current;
	uint32_t dst_ip_start;
	uint32_t dst_ip_end;
};

struct dpg_port {
	uint16_t n_rxd;
	uint16_t n_txd;
	int n_queues;
	struct rte_ether_addr mac_addr;
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
static struct rte_eth_conf g_port_conf = {
	.rxmode = {
		.split_hdr_size = 0,
	},
	.txmode = {
		.mq_mode = RTE_ETH_MQ_TX_NONE,
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

static void
dpg_invalid_argument(int arg)
{
	dpg_die("Invalid argument: '-%c'", arg);
}

static void
dpg_print_usage()
{
	rte_exit(EXIT_SUCCESS,
	"Usage: dpdk-ping [DPDK options] -- job [-- job [-- job ...]]\n"
	"\n"
	"Job:\n"
	"\t-h:  Print this help\n"
	"\t-l {lcore id}:  Lcore to run on\n"
	"\t-p {port name}:  Port to run on\n"
	"\t-q {queue id}:  RSS queue id to run on\n"
	"\t-R:  Send ICMP echo requests\n"
	"\t-E:  Send ICMP echo reply on incoming ICMP echo requests\n"
	"\t-B {packets per second}:  ICMP requests bandwidth\n"
	"\t-D {ether address}:  Destination etherne address\n"
	"\t-s {ip[-ip]}:  Source ip addresses interval\n"
	"\t-d {ip[-ip]}:  Destination ip addresses interval\n"
	"\n"
	);
}

/*static char *
dpg_strzcpy(char *dest, const char *src, size_t n)
{
	size_t i;

	for (i = 0; i < n - 1; ++i) {
		if (src[i] == '\0') {
			break;
		}
		dest[i] = src[i];
	}

	dest[i] = '\0';
	return dest;
}*/

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
	char *ptr;
	struct in_addr addr;

	ptr = strchr(str, '-');
	if (ptr != NULL) {
		*ptr = '\0';
	}

	rc = inet_aton(str, &addr);
	if (rc == 0) {
		return -EINVAL;
	}
	*ip_start = rte_be_to_cpu_32(addr.s_addr);

	if (ptr == NULL) {
		*ip_end = *ip_start;
	} else {
		rc = inet_aton(ptr + 1, &addr);
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

static const char *
dpg_port_name(struct dpg_port *port, struct rte_eth_dev_info *dev_info)
{
	int port_id;

	port_id = port - g_ports;
	rte_eth_dev_info_get(port_id, dev_info);
	if (dev_info->device == NULL) {
		return "???";
	}

	return dev_info->device->name;
}

static int
dpg_parse_job(struct dpg_job **pjob, struct dpg_job *tmpl, int argc, char **argv)
{
	int rc, opt; 
	uint16_t port_id;
	char *endptr;
	struct rte_eth_dev_info dev_info;
	struct dpg_job *job, *tmp;
	struct dpg_lcore *lcore;
	struct dpg_port *port;

	job = malloc(sizeof(*job));
	memcpy(job, tmpl, sizeof(*job));

	while ((opt = getopt(argc, argv, "hl:p:q:REB:D:s:d:")) != -1) {
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
			rc = rte_eth_dev_get_port_by_name(optarg, &port_id);
			if (rc != 0) {
				dpg_die("DPDK doesn't run on port '%s'\n", optarg);		
			}
			job->port_id = port_id;
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

		case 'D':
			rc = rte_ether_unformat_addr(optarg, &job->dst_eth_addr);
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
			dpg_die("Duplicate job for port '%s' queue %d\n",
					dpg_port_name(port, &dev_info), job->queue_id);
		}
	}
	port->n_queues = DPG_MAX(port->n_queues, job->queue_id + 1);
	tmp = port->jobs;
	port->jobs = job;
	job->port_next = tmp;

	*pjob = job;

	return optind;
}

static struct rte_mbuf *
dpg_create_icmp_request(struct dpg_job *job)
{
	struct rte_mbuf *m;
	struct rte_ether_hdr *eh;
	struct rte_ipv4_hdr *ih;
	struct rte_icmp_hdr *ich;
	struct dpg_port *port;

	port = g_ports + job->port_id;

	m = rte_pktmbuf_alloc(g_pktmbuf_pool);
	if (m == NULL) {
		dpg_die("rte_pktmbuf_alloc() failed\n");
	}

	m->next = NULL;
	m->data_len = sizeof(*eh) + sizeof(*ih) + sizeof(*ich);
	m->pkt_len = m->data_len;

	eh = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
	ih = (struct rte_ipv4_hdr *)(eh + 1);
	ich = (struct rte_icmp_hdr *)(ih + 1);

	eh->ether_type = RTE_BE16(RTE_ETHER_TYPE_IPV4);
	rte_ether_addr_copy(&job->dst_eth_addr, &eh->dst_addr);
	rte_ether_addr_copy(&port->mac_addr, &eh->src_addr);

	ih->version = 4;
	ih->ihl = sizeof(*ih) / sizeof(uint32_t);
	ih->type_of_service = 0;
	ih->total_length = rte_cpu_to_be_16(sizeof(*ih) + sizeof(*ich));
	ih->packet_id = 0;
	ih->fragment_offset = RTE_BE16(RTE_IPV4_HDR_DF_FLAG);
	ih->time_to_live = 64;
	ih->next_proto_id = IPPROTO_ICMP;
	ih->hdr_checksum = 0;
	ih->src_addr = rte_cpu_to_be_32(job->src_ip_current);
	ih->dst_addr = rte_cpu_to_be_32(job->dst_ip_current);

	ich->icmp_type = RTE_IP_ICMP_ECHO_REQUEST;
	ich->icmp_code = 0;
	ich->icmp_cksum = 0;
	ich->icmp_ident = RTE_BE16(1);
	ich->icmp_seq_nb = rte_cpu_to_be_16(job->icmp_seq_nb);

	ich->icmp_cksum = rte_raw_cksum(&ich, sizeof(ich));
	ih->hdr_checksum = rte_ipv4_cksum(ih);

	if (job->icmp_seq_nb < DPG_ICMP_SEQ_NB_END) {
		job->icmp_seq_nb++;
	} else {
		job->icmp_seq_nb = DPG_ICMP_SEQ_NB_START;
		if (job->src_ip_current < job->src_ip_end) {
			job->src_ip_current++;
		} else {
			job->src_ip_current = job->src_ip_start;
			if (job->dst_ip_current < job->dst_ip_end) {
				job->dst_ip_current++;
			} else {
				job->dst_ip_current = job->dst_ip_start;
			}
		}
	}

	return m;
}

static void
dpg_do_job(struct dpg_job *job)
{
	int i, n_rx, n_tx, n_reqs, tx_burst, txed;
	uint64_t now, dt;
	struct rte_ether_hdr *eh;
	struct rte_ipv4_hdr *ih;
	struct rte_icmp_hdr *ich;
	struct rte_mbuf *m, *rx_pkts[DPG_MAX_PKT_BURST], *tx_pkts[DPG_MAX_PKT_BURST];

	n_tx = 0;
	n_rx = rte_eth_rx_burst(job->port_id, job->queue_id, rx_pkts, DPG_ARRAY_SIZE(rx_pkts));
	for (i = 0; i < n_rx; ++i) {
		m = rx_pkts[i];
		if (job->echo == 0) {
			goto drop;
		}
		eh = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
		if (eh->ether_type != RTE_BE16(RTE_ETHER_TYPE_IPV4)) {
			goto drop;
		} 

		ih = (struct rte_ipv4_hdr *)(eh + 1);
		if (ih->next_proto_id != IPPROTO_ICMP) {
			goto drop;
		}

		ich = (struct rte_icmp_hdr *)(ih + 1);
		if (ich->icmp_type != RTE_IP_ICMP_ECHO_REQUEST) {
			goto drop;
		}

		ich->icmp_type = RTE_IP_ICMP_ECHO_REPLY;
		DPG_SWAP(ih->src_addr, ih->dst_addr);
		DPG_SWAP(eh->src_addr, eh->dst_addr);

		ich->icmp_cksum = 0;
		ich->icmp_cksum = rte_raw_cksum(&ich, sizeof(ich));
		ih->hdr_checksum = 0;
		ih->hdr_checksum = rte_ipv4_cksum(ih);

		tx_pkts[n_tx++] = m;
		continue;
drop:
		rte_pktmbuf_free(m);
	}

	if (job->request) {
		now = g_microseconds;
		dt = now - job->last_tx_time;
		n_reqs = job->bandwidth * dt / 1000000;

		if (n_reqs >= DPG_ARRAY_SIZE(tx_pkts) - n_tx) {
			n_reqs = DPG_ARRAY_SIZE(tx_pkts) - n_tx;
			job->last_tx_time = now;
			
		} else {
			job->last_tx_time += n_reqs * 1000000 / job->bandwidth;
		}

		tx_burst = n_tx + n_reqs;

		while (n_tx < tx_burst) {
			tx_pkts[n_tx++] = dpg_create_icmp_request(job);
		}
	}

	txed = 0;
	while (txed < n_tx) {
		txed += rte_eth_tx_burst(job->port_id, job->queue_id,
				tx_pkts + txed, n_tx - txed);
	}
}

static void
dpg_set_microseconds(void)
{
	g_microseconds = 1000000 * rte_rdtsc() / g_hz;
}

static void
dpg_get_stats(uint64_t *ipackets, uint64_t *opackets)
{
	int i;
	struct rte_eth_stats stats;

	*ipackets = 0;
	*opackets = 0;
	for (i = 0; i < DPG_ARRAY_SIZE(g_ports); ++i) {
		if (!dpg_port_is_configured(g_ports + i)) {
			continue;
		}

		rte_eth_stats_get(i, &stats);

		*ipackets += stats.ipackets;
		*opackets += stats.opackets;
	}
}

static int
lcore_loop(void *dummy)
{
	int p, reports;
	char ipps_b[40], opps_b[40];
	uint64_t last_stats_time;
	uint64_t ipackets[2], opackets[2];
	uint64_t ipps, opps;
	struct dpg_lcore *lcore;
	struct dpg_job *job;

	lcore = g_lcores + rte_lcore_id();

	for (job = lcore->jobs; job != NULL; job = job->lcore_next) {
		job->last_tx_time = g_microseconds;

		job->icmp_seq_nb = DPG_ICMP_SEQ_NB_START;
		job->src_ip_current = job->src_ip_start;
		job->dst_ip_current = job->dst_ip_start;
	}
	
	if (lcore->is_first) {
		reports = 0;
		p = 0;
		dpg_get_stats(&ipackets[p], &opackets[p]);
		p = 1 - p;
		last_stats_time = g_microseconds;
	}

	for (;;) {
		if (lcore->is_first) {
			dpg_set_microseconds();
		}

		for (job = lcore->jobs; job != NULL; job = job->lcore_next) {
			dpg_do_job(job);
		}

		if (lcore->is_first && g_microseconds - last_stats_time >= 1000000) {
			last_stats_time = g_microseconds;
			dpg_get_stats(&ipackets[p], &opackets[p]);
			ipps = ipackets[p] - ipackets[1 - p];
			opps = opackets[p] - opackets[1 - p];
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
	int i, j, rc, n_rxq, n_txq, n_mbufs, main_lcore, first_lcore;
	const char *port_name;
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

	tmpl = &tmpl_instance;
	memset(tmpl, 0, sizeof(*tmpl));
	tmpl->lcore_id = rte_get_main_lcore();
	tmpl->bandwidth = 100000000llu; // 100 mpps
	for (i = 0; i < DPG_ARRAY_SIZE(tmpl->dst_eth_addr.addr_bytes); ++i) {
		tmpl->dst_eth_addr.addr_bytes[i] = 0xFF;
	}
	dpg_parse_ip_interval("1.1.1.1", &tmpl->src_ip_start, &tmpl->src_ip_end);
	dpg_parse_ip_interval("2.2.2.2", &tmpl->dst_ip_start, &tmpl->dst_ip_end);

	while (argc > 1) {
		rc = dpg_parse_job(&job, tmpl, argc, argv);

		argc -= (rc - 1);
		argv += (rc - 1);
		optind = 1;

		tmpl = job;
	}

	n_mbufs = DPG_MEMPOOL_CACHE_SIZE;

	for (i = 0; i < DPG_ARRAY_SIZE(g_ports); ++i) {
		port = g_ports + i;
		if (!dpg_port_is_configured(port)) {
			continue;
		}

		port_name = dpg_port_name(port, &dev_info);

		port->conf = g_port_conf;
		if (dev_info.tx_offload_capa & RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE) {
			port->conf.txmode.offloads |= RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE;
		}
		if (port->n_queues > 1) {
			port->conf.rxmode.mq_mode = RTE_ETH_MQ_RX_RSS;
			port->conf.rx_adv_conf.rss_conf.rss_hf =
					RTE_ETH_RSS_IP | RTE_ETH_RSS_TCP | RTE_ETH_RSS_UDP;
			port->conf.rx_adv_conf.rss_conf.rss_hf &= dev_info.flow_type_rss_offloads;
		}

		n_rxq = n_txq = port->n_queues;
		rc = rte_eth_dev_configure(i, n_rxq, n_txq, &port->conf);
		if (rc < 0) {
			dpg_die("rte_eth_dev_configure('%s', %d, %d) failed (%d:%s)\n",
					port_name, n_rxq, n_txq,
					-rc, rte_strerror(-rc));
		}

		port->n_rxd = 4096;
		port->n_txd = 4096;
		rc = rte_eth_dev_adjust_nb_rx_tx_desc(i, &port->n_rxd, &port->n_txd);
		if (rc < 0) {
			dpg_die("rte_eth_dev_adjust_nb_rx_tx_desc('%s') failed (%d:%s)\n",
					port_name, -rc, rte_strerror(-rc));
		}

		rc = rte_eth_macaddr_get(i, &port->mac_addr);
		if (rc < 0) {
			dpg_die("rte_eth_macaddr_get('%s') failed (%d:%s)\n",
					port_name, -rc, rte_strerror(-rc));
		}

		n_mbufs += n_rxq * port->n_rxd;
		n_mbufs += n_txq * (port->n_txd + DPG_MAX_PKT_BURST);
	}

	n_mbufs = DPG_MAX(n_mbufs, 8192);

	g_pktmbuf_pool = rte_pktmbuf_pool_create("mbuf_pool", n_mbufs,
			DPG_MEMPOOL_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());

	if (g_pktmbuf_pool == NULL) {
		dpg_die("rte_pktmbuf_pool_create(%d) failed\n", n_mbufs);
	}

	for (i = 0; i < DPG_ARRAY_SIZE(g_ports); ++i) {
		port = g_ports + i;
		if (!dpg_port_is_configured(port)) {
			continue;
		}

		port_name = dpg_port_name(port, &dev_info);

		for (j = 0; j < port->n_queues; ++j) {
			rxq_conf = dev_info.default_rxconf;
			rxq_conf.offloads = port->conf.rxmode.offloads;
			rc = rte_eth_rx_queue_setup(i, j, port->n_rxd,
					rte_eth_dev_socket_id(i),
					&rxq_conf,
					g_pktmbuf_pool);
			if (rc < 0) {
				dpg_die("rte_eth_rx_queue_setup('%s', %d, %d) failed (%d:%s)\n",
						port_name, i, j, -rc, rte_strerror(-rc));
			}

			txq_conf = dev_info.default_txconf;
			txq_conf.offloads = port->conf.txmode.offloads;
			rc = rte_eth_tx_queue_setup(i, j, port->n_txd,
					rte_eth_dev_socket_id(i),
					&txq_conf);
			if (rc < 0) {
				dpg_die("rte_eth_tx_queue_setup('%s', %d, %d) failed (%d:%s)\n",
						port_name, i, j, -rc, rte_strerror(-rc));
			}
		}

		rc = rte_eth_dev_start(i);
		if (rc < 0) {
			dpg_die("rte_eth_dev_start('%s') failed (%d:%s)\n",
					port_name, -rc, rte_strerror(-rc));
		}

		rc = rte_eth_promiscuous_enable(i);
		if (rc < 0) {
			dpg_die("rte_eth_promiscuous_enable('%s') failed (%d:%s)\n",
					port_name, -rc, rte_strerror(-rc));
		}

		rc = rte_eth_dev_set_link_up(i);
		if (rc < 0) {
			dpg_die("rte_eth_dev_set_link_up('%s') failed (%d:%s)\n",
					port_name, -rc, rte_strerror(-rc));
		}
	}

	g_hz = rte_get_tsc_hz();
	dpg_set_microseconds();

	first_lcore = -1;
	main_lcore = rte_get_main_lcore();
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
