import socket
import argparse
import sys
import logging

logging.getLogger('scapy.runtime').setLevel(logging.ERROR)
from scapy.all import ICMP, IP, conf, sr


# turn off verbosity
conf.verb = 0


def is_alive(ip):
	""" check whether a host is up before the scan
	"""

	# ping ip
	responses, unanswered = sr(IP(dst=ip)/ICMP(), timeout=0.2, retry=3)

	for s,r in responses:
		return (r[ICMP].type == 0)

	return False


def is_open_port(ip, port):

	is_open = False
	sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	sock.settimeout(0.5)
	try:
		sock.connect((ip, port))
		is_open = True
	except socket.error:
		pass
	finally:
		sock.close()

	return is_open


def scap_host(ip, ports):
	""" try connecting to each port
	"""

	scanned_ports = []

	for p in ports:

		if is_open_port(ip, p):
			scanned_ports.append(p)

	return scanned_ports


def get_ports(p_string):
	""" extract ports from the command line arguments
	"""

	ports = []

	for token in p_string.split(','):

		if '-' in token:
			# a range of ports, e.g., 60-100
			start, end = [ int(i) for i in token.split('-') ]
			[ ports.append(int(p)) for p in range(start, end + 1) ]
		else:
			ports.append(int(token))

	ports.sort()
	return ports


def get_hosts(h_string):
	""" get a list of hosts to scan, using the netmask provided
	"""

	if not '/' in h_string:
		return [ h_string ]


	start_ip  = h_string.split('/')[0]
	last_oct  = int(start_ip.split('.')[-1])
	first_oct = int(start_ip.split('.')[0]) 
	n_mask    = h_string.split('/')[1]

	# use this feature when scanning class C ips, or you will end up scanning the entire internet!
	if n_mask == '24' and first_oct >= 192:
		hosts  = []
		net    = start_ip[:start_ip.rfind('.')] + '.'
		for i in range(last_oct, 2**8 - 1):
			hosts.append(net + str(i))

		return hosts
	return [ start_ip ]



if __name__ == "__main__":

	# parse CLI arguments
	print('Initializing ...', end='')
	parser = argparse.ArgumentParser()
	parser.add_argument('-p', action="store", dest="ports", required=True, type=str, help="Specify ports, e.g.,\
		 -p 80, -p 80-120, -p 67,78-100")
	parser.add_argument('-i', action="store", dest="hosts", required=True, type=str, help="Specify the hosts/IPs to scan, e.g.,\
		 -i 192.168.1.1, -i 192.168.1.1/24")

	# parse command line arguments
	parse_res = parser.parse_args(sys.argv[1:])

	ports   = get_ports(parse_res.ports)
	hosts   = get_hosts(parse_res.hosts)
	#scanned = {}
	print('\r' + ' '*30 + '\rInitialized.\nScan started.\n')


	for index, host in enumerate(hosts):
		print('Scanning %d/%d' % (index + 1, len(hosts)), end='\r')
		if is_alive(host):
			open_ports = scap_host(host, ports)
			print(' ' * 30 + '\r-- %s --' % host)

			if len(ports) == 1:
				print('   %d/tcp' % ports[0], '-- %s' % ('open' if(len(open_ports)) else 'closed'))

			else:
				for p in open_ports:
					print('   %d/tcp -- %10s' % (p, 'open'))

	print(' ' * 50 + '\r\nScan complete')
