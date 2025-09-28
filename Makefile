
cmd = sudo -E python3 main.py -i any -c 1 -f

icmp:
	$(cmd) icmp

udp:
	$(cmd) udp

tcp:
	$(cmd) tcp

dns:
	$(cmd) 'udp port 53 or tcp port 53'

icmp6:
	$(cmd) icmp6

tcp6:
	$(cmd) "tcp and ip6"

udp6:
	$(cmd) "udp and ip6"
