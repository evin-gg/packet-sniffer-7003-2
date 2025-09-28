
RUN = sudo -E python3 main.py -i any -c 3 -f
icmp:
	$(RUN) icmp

udp:
	$(RUN) udp

tcp:
	$(RUN) tcp

dns:
	$(RUN) 'udp port 53 or tcp port 53'
