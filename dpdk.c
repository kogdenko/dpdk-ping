#include "dpdk.h"

struct rte_mempool *g_dpg_pktmbuf_pool;

const char *
dpg_get_port_name(uint16_t port_id)
{
	static char port_name[RTE_MAX_ETHPORTS][RTE_ETH_NAME_MAX_LEN];

	if (port_name[port_id][0] == '\0') {
		rte_eth_dev_get_name_by_port(port_id, port_name[port_id]);
	}
	return port_name[port_id];
}

void
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

struct rte_mbuf *
dpg_pktmbuf_alloc(void)
{
	struct rte_mbuf *m;

	m = rte_pktmbuf_alloc(g_dpg_pktmbuf_pool);
	if (m == NULL) {
		dpg_die("rte_pktmbuf_alloc() failed\n");
	}
	return m;
}
