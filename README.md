

EXAMPLE TO GENERATE 40M GTPV1

#sudo /home/cseadmin/GTP-TCPREPLAY/multithreaded/tcpreplay442/tcpreplay-4.4.2/src/tcpreplay --netmap  --preload-pcap -p 105000 --intf1=enp4s0f1 --intf2=eno4 --cachefile=out.cache 40M-gtpv1.cap
Switching network driver for enp4s0f1 to netmap bypass mode... done!
Switching network driver for eno4 to netmap bypass mode... done!
File Cache is enabled
^@^@^@^@^@^@^@^@^@^@^@^@^@Actual: 80000024 packets (11960003588 bytes) sent in 761.90 seconds
Rated: 15697520.4 Bps, 125.58 Mbps, 105000.13 pps
Flows: 104 flows, 0.13 fps, 80000024 flow packets, 0 non-flow
Statistics for network device: enp4s0f1
	Successful packets:        40000012
	Failed packets:            0
	Truncated packets:         0
	Retried packets (ENOBUFS): 0
	Retried packets (EAGAIN):  0
Statistics for network device: eno4
	Successful packets:        40000012
	Failed packets:            0
	Truncated packets:         0
	Retried packets (ENOBUFS): 0
	Retried packets (EAGAIN):  4496
Switching network driver for enp4s0f1 to normal mode... ^@done!
Switching network driver for eno4 to normal mode... done!
