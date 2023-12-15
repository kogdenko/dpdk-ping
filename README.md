# DPDK ping utility

# Examples
## Simple
dpdk-ping -- -B 10 -R -l 1 -p 0000:00:08.0 -q 0 -D 52:54:00:e0:50:95 -s 10.10.10.1 -d 10.10.10.2

## Memif
### Start server
dpdk-testpmd --proc-type=primary --file-prefix=pmd1 --vdev=net_memif,role=server,socket=/run/memif.sock,socket-abstract=no -- -i --txq=2 --rxq=2
> set fwd icmpecho
> start

### Start client
dpdk-ping --proc-type=primary --file-prefix=pmd2 --vdev=net_memif,socket=/run/memif.sock,socket-abstract=no -- -B 10 -R -l 1 -p net_memif -q 0 -D 72:55:0B:F5:5A:2D -- -q 1 -l 2 
