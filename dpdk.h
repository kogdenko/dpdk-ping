#ifndef DPG_DPDK_H
#define DPG_DPDK_H

#include <rte_bus.h>
#include <rte_common.h>
#include <rte_cycles.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include <rte_pci.h>
#include <rte_version.h>

#define DPG_PACKED  __attribute__((packed)) __attribute__((aligned(2)))

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

#define DPG_MEMPOOL_CACHE_SIZE 128

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
#define dpg_die(...) \
	rte_exit(EXIT_FAILURE, ##__VA_ARGS__);

#define dpg_dbg(f, ...) do { \
	printf("%s:%u: ", __FILE__, __LINE__); \
	printf(f, ##__VA_ARGS__); \
	printf("\n"); \
	fflush(stdout); \
} while (0)

const char *dpg_get_port_name(uint16_t port_id);

void dpg_eth_dev_info_get(uint16_t port_id, struct rte_eth_dev_info *dev_info);

struct rte_mbuf *dpg_pktmbuf_alloc(void);

extern struct rte_mempool *g_dpg_pktmbuf_pool;

#endif
