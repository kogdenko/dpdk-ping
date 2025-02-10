# DPDK ping utility
dpdk-ping is a network tool able to send ICMP/UDP/TCP(syn) packets with high bandwidth

# Usage examples
Simplest way to run dpdk-ping is to use memif interface  

dpdk-testpmd and dpdk-ping
--------------------------

Run dpdk-testpmd in server mode:
```
dpdk-testpmd --proc-type=primary --file-prefix=pmd1 --vdev=net_memif,role=server,socket=/run/memif.sock,socket-abstract=no -- -i --txq=2 --rxq=2
> set fwd icmpecho
> start
```
Run dpdk-ping:
```
./dpdk-ping --proc-type=primary --file-prefix=pmd2 --vdev=net_memif,socket=/run/memif.sock,socket-abstract=no -- -B 10 -R on -l 0,1 -p net_memif -H 72:55:0B:F5:5A:2D
```

Pair of dpdk-ping
-----------------
Find out hardware addresses:
```
./dpdk-ping --proc-type=primary --file-prefix=pmd1 --vdev=net_memif,role=server,socket=/run/memif.sock,socket-abstract=no -- -h
...
Ports:
net_memif  96:39:81:9A:CC:4B

./dpdk-ping --proc-type=primary --file-prefix=pmd2 --vdev=net_memif,socket=/run/memif.sock,socket-abstract=no -- -h
...
Ports:
net_memif  DE:7C:86:CE:91:AD
```
Run Server side:
```
unlink /run/memif.sock
./dpdk-ping --proc-type=primary --file-prefix=pmd1 --vdev=net_memif,role=server,socket=/run/memif.sock,socket-abstract=no -- -l 1 -p net_memif -E on
```
Run client side:
```
./dpdk-ping --proc-type=primary --file-prefix=pmd2 --vdev=net_memif,socket=/run/memif.sock,socket-abstract=no -- -l 2 -H CA:F8:4C:23:DA:EB -B 1 -p net_memif --pdr 0.001,20,5 -B 10m -R on
```

