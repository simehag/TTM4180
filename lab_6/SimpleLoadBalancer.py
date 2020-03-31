from pox.core import core
from pox.openflow import *
import pox.openflow.libopenflow_01 as of
from pox.lib.packet.arp import arp
from pox.lib.packet.ipv4 import ipv4
from pox.lib.addresses import EthAddr, IPAddr
log = core.getLogger()
import time
import random
import pox.log.color


IDLE_TIMEOUT = 10
LOADBALANCER_MAC = EthAddr("00:00:00:00:00:FE")
ETHERNET_BROADCAST_ADDRESS=EthAddr("ff:ff:ff:ff:ff:ff")

class SimpleLoadBalancer(object):

	def __init__(self, service_ip, server_ips = []):
		core.openflow.addListeners(self)
		self.SERVERS = {} # IPAddr(SERVER_IP)]={'server_mac':EthAddr(SERVER_MAC),'port': PORT_TO_SERVER}
		self.CLIENTS = {}
		self.LOADBALANCER_MAP = {} # Mapping between clients and servers
		self.LOADBALANCER_IP = service_ip
		self.SERVER_IPS = server_ips
		self.ROBIN_COUNT = 0

	def _handle_ConnectionUp(self, event):
		self.connection = event.connection
		log.debug("FUNCTION: _handle_ConnectionUp")
		""" START: Edit this section

		# TODO_M: Send ARP Requests to learn the MAC address of all Backend Servers.

		END: Edit this section"""
		log.debug("Sent ARP Requests to all servers")

	def round_robin(self):
		log.debug("FUNCTION: round_robin")

		""" START: Edit this section

		# TODO_M: Implement logic to choose the next server according to 
		#         the Round Robin scheduling algorithm

		END: Edit this section"""

		log.info("Round robin selected: %s" % server)
		return server

	def update_lb_mapping(self, client_ip):
		log.debug("FUNCTION: update_lb_mapping")
		if client_ip in self.CLIENTS.keys():
			if client_ip not in self.LOADBALANCER_MAP.keys():
				""" START: Edit this section

				selected_server = # TODO: select the server which will handle the request
				
				self.LOADBALANCER_MAP[client_ip]=selected_server
				END: Edit this section"""


	def send_arp_reply(self, packet, connection, outport):
		log.debug("FUNCTION: send_arp_reply")

		""" START: Edit this section
		arp_rep= # TODO: Create an ARP reply
		arp_rep.hwtype = arp_rep.HW_TYPE_ETHERNET
		arp_rep.prototype = arp_rep.PROTO_TYPE_IP
		arp_rep.hwlen = 6
		arp_rep.protolen = arp_rep.protolen
		arp_rep.opcode = # TODO: Set the ARP TYPE to REPLY

		arp_rep.hwdst = # TODO: Set MAC destination
		arp_rep.hwsrc = # TODO: Set MAC source

		#Reverse the src, dest to have an answer
		arp_rep.protosrc = # TODO: Set IP source
		arp_rep.protodst = # TODO: Set IP destination

		
		eth = # TODO: Create an ethernet frame and set the arp_rep as it's payload.
		eth.type = # TODO: Set packet Typee
		eth.dst = # TODO: Set destination of the Ethernet Frame
		eth.src = # TODO: Set source of the Ethernet Frame
		eth.set_payload(arp_rep)
		
		msg = # TODO: create the necessary Openflow Message to make the switch send the ARP Reply
		msg.data = eth.pack()
		
		# TODO: Append the output port which the packet should be forwarded to.

		msg.in_port = outport
		connection.send(msg)
		END: Edit this section"""

	def send_arp_request(self, connection, ip):
		# Difficulties? https://en.wikipedia.org/wiki/Address_Resolution_Protocol#Example

		log.debug("FUNCTION: send_arp_request")

		""" START: Edit this section

		arp_req = # TODO: Create an instance of an ARP REQUEST PACKET
		arp_req.hwtype = arp_req.HW_TYPE_ETHERNET
		arp_req.prototype = arp_req.PROTO_TYPE_IP
		arp_req.hwlen = 6
		arp_req.protolen = arp_req.protolen
		arp_req.opcode = # TODO: Set the opcode
		arp_req.protodst = # TODO: IP the load balancer is looking for
		arp_req.hwsrc = # TODO: Set the MAC source of the ARP REQUEST
		arp_req.hwdst = # TODO: Set the MAC address in such a way that the packet is marked as a Broadcast
		arp_req.protosrc = # TODO: Set the IP source of the ARP REQUEST

		eth = # TODO: Create an ethernet frame and set the arp_req as it's payload.
		eth.type =  # TODO: Set packet Typee
		eth.dst = # TODO: Set the MAC address in such a way that the packet is marked as a Broadcast
		eth.set_payload(arp_req)

		msg = # TODO: create the necessary Openflow Message to make the switch send the ARP Request
		msg.data = eth.pack()
		msg.actions.append(of.ofp_action_nw_addr(of.OFPAT_SET_NW_DST,ip))

		TODO: append an action to the message which makes the switch flood the packet out

		connection.send(msg)
		
		END: Edit this section"""

	def install_flow_rule_client_to_server(self,event, connection, outport, client_ip, server_ip):
		log.debug("FUNCTION: install_flow_rule_client_to_server")
		self.install_flow_rule_server_to_client(connection, event.port, server_ip,client_ip)

		""" START: Edit this section
		msg = # TODO: Create an instance of the type of Openflow packet you need to install flow table entries
		msg.idle_timeout = IDLE_TIMEOUT

		msg.match.dl_type=ethernet.IP_TYPE
		# TODO: MATCH on destination and source IP
		# TODO: SET dl_addr source and destination addresses
		# TODO: SET nw_addr source and destination addresses
		# TODO: Set Port to send matching packets out

		 END: Edit this section"""
		self.connection.send(msg)
		log.info("Installed flow rule: %s -> %s" % (client_ip,server_ip))
		
	def install_flow_rule_server_to_client(self, connection, outport, server_ip, client_ip):
		log.debug("FUNCTION: install_flow_rule_server_to_client")

		""" START: Edit this section

		msg = # TODO: Create an instance of the type of Openflow packet you need to install flow table entries
		msg.idle_timeout = IDLE_TIMEOUT

		msg.match.dl_type=ethernet.IP_TYPE
		# TODO: MATCH on destination and source IP
		# TODO: SET dl_addr source and destination addresses
		# TODO: SET nw_addr source and destination addresses
		# TODO: Set Port to send matching packets out

		END: Edit this section"""

		self.connection.send(msg)
		log.info("Installed flow rule: %s -> %s" % (server_ip,client_ip))

	def _handle_PacketIn(self, event):
		log.debug("FUNCTION: _handle_PacketIn")
		packet = event.parsed
		connection = event.connection
		inport = event.port
		if packet.type == packet.LLDP_TYPE or packet.type == packet.IPV6_TYPE:
			log.info("Received LLDP or IPv6 Packet...")

		""" START: Edit this section

		elif # TODO: Handle ARP Packets
			log.debug("Received ARP Packet")
			response = packet.payload
			if # TODO: Handle ARP replies
				log.debug("ARP REPLY Received")
				if response.protosrc not in self.SERVERS.keys():
					# TODO: Add Servers MAC and port to SERVERS dict
		
			elif # TODO: Handle ARP requests
				log.debug("ARP REQUEST Received")
				if response.protosrc not in self.SERVERS.keys() and response.protosrc not in self.CLIENTS.keys():
					self.CLIENTS[response.protosrc]={'client_mac':EthAddr(packet.payload.hwsrc),'port':inport}		#insert client's ip  mac and port to a forwarding table
									
				if (response.protosrc in self.CLIENTS.keys()and response.protodst == self.LOADBALANCER_IP):
					log.info("Client %s sent ARP req to LB %s"%(response.protosrc,response.protodst))
					# Load Balancer intercepts ARP Client -> Server
					# TODO: Send ARP Reply to the client, include the event.connection object
				
				elif response.protosrc in self.SERVERS.keys() and response.protodst in self.CLIENTS.keys():
					log.info("Server %s sent ARP req to client"%response.protosrc)
					# Load Balancer intercepts ARP from Client <- Server
					# TODO: Send ARP Reply to the Server, include the event.connection object
				else:
					log.info("Invalid ARP request")

		elif # TODO: Handle IP Packets
			log.debug("Received IP Packet from %s" % packet.next.srcip)
			# Handle Requests from Clients to Servers
			# Install flow rule Client -> Server
			if # TODO: Check if the packet is destined for the LB and the source is not a server :

				self.update_lb_mapping(packet.next.srcip)
				client_ip = # TODO: Get client IP from the packet
				server_ip = self.LOADBALANCER_MAP.get(packet.next.srcip)
				outport = # TODO: Get Port of Server

				self.install_flow_rule_client_to_server(event,connection, outport, client_ip,server_ip)
				
				# TODO: Either use the code below to create a new Ethernet packet, or use Buffer_Id
				eth = ethernet()
				eth.type = # TODO: Set the correct Ethernet TYPE, to send an IP Packet
				eth.dst = # TODO: Set the MAC destination
				eth.src = # TODO: Set the MAC source
				eth.set_payload(packet.next)

				# Send the first packet (which was sent to the controller from the switch)
				# to the chosen server, so there is no packetloss
				msg= # TODO: Create an instance of a message which can be used to instruct the switch to send a packet
				msg.data = eth.pack()
				msg.in_port = # TODO: Set the correct in_port
				
				# TODO: Add an action which sets the MAC source to the LB's MAC
				# TODO: Add an action which sets the MAC destination to the intended destination...

				# TODO: Add an action which sets the IP source
				# TODO: Add an action which sets the IP destination
				# TODO: Add an action which sets the Outport

				connection.send(msg)

			# Handle traffic from Server to Client
			# Install flow rule Client <- Server
			elif packet.next.dstip in self.CLIENTS.keys(): #server to client
				log.info("Installing flow rule from Server -> Client")
				if packet.next.srcip in self.SERVERS.keys():

					server_ip = # TODO: Get the source IP from the IP Packet

					client_ip = self.LOADBALANCER_MAP.keys()[list(self.LOADBALANCER_MAP.values()).index(packet.next.srcip)]
					outport=int(self.CLIENTS[client_ip].get('port'))
					self.install_flow_rule_server_to_client(connection, outport, server_ip,client_ip)

					# TODO: Either use the code below to create a new Ethernet packet, or use Buffer_Id
					eth = ethernet()
					eth.type =  # TODO: Set the correct Ethernet TYPE, to send an IP Packet
					eth.dst =  # TODO: Set the MAC destination
					eth.src =  # TODO: Set the MAC source
					eth.set_payload(packet.next)

					# Send the first packet (which was sent to the controller from the switch)
					# to the chosen server, so there is no packetloss
					msg =  # TODO: Create an instance of a message which can be used to instruct the switch to send a packet
					msg.data = eth.pack()
					msg.in_port =  # TODO: Set the correct in_port

					# TODO: Add an action which sets the MAC source to the LB's MAC
					# TODO: Add an action which sets the MAC destination to the intended destination...

					# TODO: Add an action which sets the IP source
					# TODO: Add an action which sets the IP destination
					# TODO: Add an action which sets the Outport
		
					self.connection.send(msg)

		
		else:
			log.info("Unknown Packet type: %s" % packet.type)
			return
		END: Edit this section"""
		return

def launch(loadbalancer, servers):
	# Color-coding and pretty-printing the log output
	pox.log.color.launch()
	pox.log.launch(format="[@@@bold@@@level%(name)-23s@@@reset] " +
						  "@@@bold%(message)s@@@normal")
	log.info("Loading Simple Load Balancer module:\n\n-----------------------------------CONFIG----------------------------------\n")
	server_ips = servers.replace(","," ").split()
	server_ips = [IPAddr(x) for x in server_ips]
	loadbalancer_ip = IPAddr(loadbalancer)
	log.info("Loadbalancer IP: %s" % loadbalancer_ip)
	log.info("Backend Server IPs: %s\n\n---------------------------------------------------------------------------\n\n" % ', '.join(str(ip) for ip in server_ips))
	core.registerNew(SimpleLoadBalancer, loadbalancer_ip, server_ips)
