# DPDK ping utility
dpdk-ping is a network tool able to send ICMP/UDP packets with high bandwidth.  

# Usage examples
Simplest way to run dpdk-ping is to use memif interface  
Start dpdk-testpmd as memif server
```
dpdk-testpmd --proc-type=primary --file-prefix=pmd1 --vdev=net_memif,role=server,socket=/run/memif.sock,socket-abstract=no -- -i --txq=2 --rxq=2
> set fwd icmpecho
> start
```
Start dpdk-ping as memif client
```
./dpdk-ping --proc-type=primary --file-prefix=pmd2 --vdev=net_memif,socket=/run/memif.sock,socket-abstract=no -- -B 10 -R on -l 0,1 -p net_memif -H 72:55:0B:F5:5A:2D
```
