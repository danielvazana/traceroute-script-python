from scapy.all import *
import time

first_packet = IP(dst = 'www.google.com')/ICMP(type = 'echo-request')/'Cyber Bagrut is cool!'
response_packet = sr1(first_packet, verbose = 0)/ICMP()
t = 1
flag = True
while flag:
	send_packet = IP(ttl = t, dst = 'www.google.com')/ICMP(type = 'echo-request')/'Cyber Bagrut is cool!'
	start = int(round(time.time() * 1000))
	packet_loop = sr1(send_packet, verbose = 0, timeout = 3)
	end = int(round(time.time() * 1000))
	if not packet_loop is None:
		print 'The ' + str(t) + ' router is: ' + packet_loop[IP].src + ', time: ' + str(end-start) 
		if packet_loop[IP].src == response_packet[IP].src:
			flag = False
	else:
		print '*'
	t += 1
	