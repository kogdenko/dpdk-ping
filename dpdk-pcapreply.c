#define _GNU_SOURCE
#include <sched.h>
#include <unistd.h>
#include <pthread.h>
#include <pcap/dlt.h>
#include <pcap/pcap.h>

#include "dpdk.h"

static uint16_t g_dpg_rport_id = RTE_MAX_ETHPORTS;
static uint16_t g_dpg_wport_id = RTE_MAX_ETHPORTS;
static int g_dpg_n_packets;
static uint64_t g_dpg_timeout;
static pcap_t *g_dpg_rpcap;
static pcap_t *g_dpg_wpcap;
static pcap_dumper_t *g_dpg_dump;

static void
dpg_invalid_argument(int short_name, const char *long_name)
{
	if (long_name != NULL) {
		dpg_die("Invalid argument: '--%s'\n", long_name);
	} else {
		dpg_die("Invalid argument: '-%c'\n", short_name);
	}
}

#ifdef __linux__
typedef cpu_set_t cpuset_t;
#endif

static int
dpg_set_affinity(int cpu_id)
{
	int rc;
	cpuset_t x;

	CPU_ZERO(&x);
	CPU_SET(cpu_id, &x);
	rc = pthread_setaffinity_np(pthread_self(), sizeof(x), &x);
	if (rc) {
		dpg_die("pthread_setaffinity_np(%d) failed\n", cpu_id);
		return -rc;
	}
	return 0;
}

static void
dpg_rpcap_close(void)
{
	if (g_dpg_rpcap != NULL) {
		pcap_close(g_dpg_rpcap);
		g_dpg_rpcap = NULL;
	}
}

static void
dpg_wpcap_close(void)
{
	if (g_dpg_wpcap != NULL) {
		pcap_dump_close(g_dpg_dump);
		pcap_close(g_dpg_wpcap);
		g_dpg_wpcap = NULL;
	}
}

static int
dpg_rpcap_read(struct pcap_pkthdr **pkt_hdr, const u_char **pkt_dat)
{
	int rc;

	if (g_dpg_rpcap == NULL) {
		return 0;
	}
	rc = pcap_next_ex(g_dpg_rpcap, pkt_hdr, pkt_dat);
	if (rc == PCAP_ERROR_BREAK) {
		dpg_rpcap_close();
		return 0;
	} else if (rc == PCAP_ERROR) {
		dpg_die("pcap_next_ex() failed (%s)\n", pcap_geterr(g_dpg_rpcap));
	} else if (rc == 1) {
		return 1;
	} else {
	 	dpg_die("pcap_next_ex() unknown return %d\n", rc);
	}
	return 0;
}

static int
dpg_loop(void *dummy)
{
	int rc, n_packets;
	uint64_t t0, elapsed;
	const u_char *pkt_dat;
	struct pcap_pkthdr out_pkt_hdr, *in_pkt_hdr;
	struct rte_mbuf *m, *burst[1];

	n_packets = 0;
	t0 = rte_rdtsc();

	while (g_dpg_rpcap != NULL || g_dpg_wpcap != NULL) {
		elapsed = rte_rdtsc() - t0;
		if (elapsed >= g_dpg_timeout) {
			dpg_wpcap_close();
		}

		if (g_dpg_wpcap != NULL) {
			rc = rte_eth_rx_burst(g_dpg_rport_id, 0, burst, 1);
			if (rc == 1) {
				m = burst[0];
				gettimeofday(&out_pkt_hdr.ts, NULL);
				out_pkt_hdr.len = out_pkt_hdr.caplen = m->pkt_len;
				dpg_dbg("dpdk->pcap: %d", m->pkt_len);
				pkt_dat = rte_pktmbuf_mtod(m, void *);
				pcap_dump((u_char *)g_dpg_dump, &out_pkt_hdr, pkt_dat);
				n_packets++;
				if (n_packets == g_dpg_n_packets) {
					dpg_wpcap_close();
				}
				rte_pktmbuf_free(m);
			}
		}

		if (g_dpg_rpcap != NULL) {
			rc = dpg_rpcap_read(&in_pkt_hdr, &pkt_dat);
			if (rc == 1) {
				m = dpg_pktmbuf_alloc();
				m->pkt_len = m->data_len = in_pkt_hdr->len;
				dpg_dbg("pcap->dpdk: %u %u", in_pkt_hdr->len, in_pkt_hdr->caplen);
				memcpy(rte_pktmbuf_mtod(m, void *), pkt_dat, m->pkt_len);
				burst[0] = m;
				do {
					rc = rte_eth_tx_burst(g_dpg_wport_id, 0, burst, 1);
				} while (rc < 1);
			}
		}
	}

	return 0;
}

static void
dpg_print_usage(void)
{
	printf("Usage: dpdk-pcapreply [DPDK options] -- [-r file.pcap] [-w file.pcap] \n"
		"\t[-t timeout_ms] [-n packets] [-a cpu]\n");
}

int
main(int argc, char **argv)
{
	int i, rc, opt, lcore_id, socket_id, n_mbufs;
	uint16_t port_id, n_rxd, n_txd;
	uint64_t hz;
	char *endptr;
	const char *rpath, *wpath, *port_name;
	struct rte_eth_conf port_conf;
	struct rte_eth_dev_info dev_info;
	struct rte_eth_rxconf rxq_conf;
	struct rte_eth_txconf txq_conf;
	char errbuf[PCAP_ERRBUF_SIZE];

	rc = rte_eal_init(argc, argv);
	if (rc < 0) {
		dpg_die("rte_eal_init() failed (%d:%s)\n", -rc, rte_strerror(-rc));
	}

	argc -= rc;
	argv += rc;

	rpath = wpath = NULL;
	g_dpg_n_packets = 0;

	while ((opt = getopt(argc, argv, "hr:w:t:n:a:")) != -1) {
		switch (opt) {
		case 'h':
			dpg_print_usage();
			return 0;

		case 'r':
			rpath = optarg;
			break;

		case 'w':
			wpath = optarg;
			break;

		case 't':
			hz = rte_get_tsc_hz();
			g_dpg_timeout = strtoul(optarg, &endptr, 10) * hz / 1000;
			if (*endptr != '\0') {
				dpg_invalid_argument(opt, NULL);
			}	
			break;

		case 'n':
			g_dpg_n_packets = strtoul(optarg, &endptr, 10);
			if (*endptr != '\0') {
				dpg_invalid_argument(opt, NULL);
			}
			break;

		case 'a':
			rc = strtoul(optarg, &endptr, 10);
			if (*endptr != '\0') {
				dpg_invalid_argument(opt, NULL);
			}
			dpg_set_affinity(rc);
			break;	
		}
	}

	if (rpath != NULL) {
		g_dpg_rpcap = pcap_open_offline(rpath, errbuf);
		if (g_dpg_rpcap == NULL) {
			dpg_die("pcap_open_offline('%s') failed (%s)\n", rpath, errbuf);
		}
	}

	if (wpath != NULL && g_dpg_n_packets > 0) {
		g_dpg_wpcap = pcap_open_dead(DLT_EN10MB, 65536);
		if (g_dpg_wpcap == NULL) {
			dpg_die("pcap_open_dead() failed\n");
		}

		g_dpg_dump = pcap_dump_open(g_dpg_wpcap, wpath);
		if (g_dpg_dump == NULL) {
			dpg_die("pcap_dump_open('%s') failed (%s)\n",
					wpath, pcap_geterr(g_dpg_wpcap));
		}
	}

	n_mbufs = 2 * 2 * 4096;
	g_dpg_pktmbuf_pool = rte_pktmbuf_pool_create("mbuf_pool", n_mbufs,
			DPG_MEMPOOL_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
	if (g_dpg_pktmbuf_pool == NULL) {
		dpg_die("rte_pktmbuf_pool_create(%d) failed\n", n_mbufs);
	}

	i = 0;
	RTE_ETH_FOREACH_DEV(port_id) {
		if (i == 0) {
			g_dpg_rport_id = port_id;
		} else if (i == 1) {
			g_dpg_wport_id = port_id;
		} else {
			break;
		}
		i++;
		
		memset(&port_conf, 0, sizeof(port_conf));
		port_conf.txmode.mq_mode = DPG_ETH_MQ_TX_NONE;

		port_name = dpg_get_port_name(port_id);
		socket_id = rte_eth_dev_socket_id(port_id);

		dpg_eth_dev_info_get(port_id, &dev_info);
		if (dev_info.tx_offload_capa & DPG_ETH_TX_OFFLOAD_MBUF_FAST_FREE) {
			port_conf.txmode.offloads |= DPG_ETH_TX_OFFLOAD_MBUF_FAST_FREE;
		}
		rc = rte_eth_dev_configure(port_id, 1, 1, &port_conf);
		if (rc < 0) {
			dpg_die("rte_eth_dev_configure('%s') failed (%d:%s)\n",
					port_name, -rc, rte_strerror(-rc));
		}

		n_rxd = n_txd = 4096;
		rc = rte_eth_dev_adjust_nb_rx_tx_desc(port_id, &n_rxd, &n_txd);
		if (rc < 0) {
			dpg_die("rte_eth_dev_adjust_nb_rx_tx_desc('%s') failed (%d:%s)\n",
					port_name, -rc, rte_strerror(-rc));
		}

		rxq_conf = dev_info.default_rxconf;
		rxq_conf.offloads = port_conf.rxmode.offloads;
		rc = rte_eth_rx_queue_setup(port_id, 0, n_rxd, socket_id,
				&rxq_conf, g_dpg_pktmbuf_pool);
		if (rc < 0) {
			dpg_die("rte_eth_rx_queue_setup('%s', %d, %d) failed (%d:%s)\n",
					port_name, port_id, 0, -rc, rte_strerror(-rc));
		}

		txq_conf = dev_info.default_txconf;
		txq_conf.offloads = port_conf.txmode.offloads;
		rc = rte_eth_tx_queue_setup(port_id, 0, n_txd, socket_id, &txq_conf);
		if (rc < 0) {
			dpg_die("rte_eth_tx_queue_setup('%s', %d, %d) failed (%d:%s)\n",
					port_name, port_id, 0, -rc, rte_strerror(-rc));
		}

		rc = rte_eth_dev_start(port_id);
		if (rc < 0) {
			dpg_die("rte_eth_dev_start('%s') failed (%d:%s)\n",
					port_name, -rc, rte_strerror(-rc));
		}

		rte_eth_promiscuous_enable(port_id);

		rte_eth_dev_set_link_up(port_id);
	}

	if (g_dpg_rport_id == RTE_MAX_ETHPORTS) {
		dpg_die("No ports specified");
	}

	if (g_dpg_wport_id == RTE_MAX_ETHPORTS) {
		g_dpg_wport_id = g_dpg_rport_id;
	}

	RTE_LCORE_FOREACH(lcore_id) {
		break;
	}

	dpg_loop(NULL);

	return 0;
}
