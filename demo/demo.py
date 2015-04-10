#! /usr/bin/env python

import sys
from time import time  
from scapy.all import *


#only need to send single packet to a open port
def send_raw_packet(dhost,dport):	
	packet=IP(dst=dhost,ttl=50,id=37649)/TCP(sport=5555,dport=dport,flags="S",window=63,options=[('MSS', 1460), ('SAckOK', ''), ('Timestamp',(10058221L, 0L)), ('NOP', None), ('WScale', 2)])
	rsp=sr1(packet,timeout=0.5)
	return rsp

def send_flagsnull_packet(dhost,dport):
	packet=IP(dst=dhost,flags=2)/TCP(sport=5556,dport=dport,window=128,flags=0,options=[('WScale', 2),('NOP',None),('MSS', 265), ('Timestamp',(10058221L, 0L)),('SAckOK','')])
	rsp=sr1(packet,timeout=0.5)
	return rsp
def send_flagsfin_packet(dhost,dport):
	packet=IP(dst=dhost,flags=0)/TCP(sport=5557,dport=dport,window=256,flags="F",options=[('WScale', 2),('NOP',None),('MSS', 265), ('Timestamp',(10058221L, 0L)),('SAckOK','')])
	rsp=sr1(packet,timeout=0.5)
	return rsp
def send_flagsack_packet(dhost,dport):
	packet=IP(dst=dhost,flags=2)/TCP(sport=5558,dport=dport,window=1024,flags="A",options=[('WScale', 2),('NOP',None),('MSS', 265), ('Timestamp',(10058221L, 0L)),('SAckOK','')])
	rsp=sr1(packet,timeout=0.5)
	return rsp
def send_flagsadd_packet(dhost,dport):
	packet=IP(dst=dhost,flags=0)/TCP(sport=5559,dport=dport,window=256,flags="SFUP",options=[('WScale', 2),('NOP',None),('MSS', 265), ('Timestamp',(10058221L, 0L)),('SAckOK','')])
	rsp=sr1(packet,timeout=0.5)
	return rsp
#ICMP 
def send_icmpecho1_packet(dhost):
	packet=IP(dst=dhost,flags=2,id=28303)/ICMP(type=8,code=9,id=8492)/(''*120)
	rsp=sr1(packet,timeout=0.5)
	return rsp
def send_icmpecho2_packet(dhost):
	packet=IP(dst=dhost,flags=0,tos=4,id=28304)/ICMP(type=8,code=0,id=8493)/('0'*150)
	rsp=sr1(packet,timeout=0.5)
	return rsp	
#send udp to closed port to triger icmp unreachable messsage
def send_udp_packet(dhost,dport):
	packet=IP(dst=dhost,flags=0,id=4162)/UDP(sport=6666,dport=dport)/('C'*300)
	rsp=sr1(packet,timeout=0.5)
	return rsp	

def main():
	#usage:
	t=time.time()
	total={'ttl_total':0,
			'DF_total':0,
			'IPID_total':0,
			#'tos_total':0,
			'len_total':0,
			'win_total':0,
			'acknum_total':0,
			'seqnum_total':0,
			'options_total':0,
			'flagsnull_total':0,
			'flagsfin_total':0,
			'flagsack_total':0,
			'flagsadd_total':0,
			'icmpecho1_total':0,
			'icmpecho2_total':0,
			'icmpintegrity_total':0
	}
	ip_total=0
	live=0
	fr = open("ip.txt",'r')
	win = []
	icmpecho1= []
	DF =[]
	camera=[]
	ttl = []
	options =[]
	IPID =[]
	acknum =[]
	#fw.writelines(arr)  
	for ip in fr:
		if(ip!='\n'):
			ip_total+=1
			if(ip_total)<= 10:
				camera.append(ip[0:len(ip)-1])
			response1=send_raw_packet(ip[0:len(ip)-1],80)
			if(str(type(response1)) != "<type 'NoneType'>"):
				live+=1
				if response1.ttl >= 64 and response1.ttl <= 128:
					total['ttl_total']+=1
					ttl.append(ip[0:len(ip)-1])
				if response1.flags == 2:
					total['DF_total']+=1
					DF.append(ip[0:len(ip)-1])
				if response1.id == 0:
					total['IPID_total']+=1
					IPID.append(ip[0:len(ip)-1])
				#if response1.tos == 64240:
				#	total['tos_total']+=1
				if response1.len == 48:
					total['len_total']+=1
				#TCP Header features
				if response1.window == 5840 or response1.window ==5792 or response1.window ==14480:
					total['win_total']+=1
					win.append(ip[0:len(ip)-1])
				if response1.ack== 1:
					total['acknum_total']+=1
					acknum.append(ip[0:len(ip)-1])
				if response1.seq==0:
					total['seqnum_total']+=1
				if response1.haslayer(TCP) and len(response1.getlayer(TCP).options)!= 0 :
					if response1.getlayer(TCP).options[len(response1.getlayer(TCP).options)-1][0]=='WScale':
						total['options_total']+=1
						options.append(ip[0:len(ip)-1])

			response2=send_flagsnull_packet(ip[0:len(ip)-1],80)
			if(str(type(response2)) == "<type 'NoneType'>"):
				total['flagsnull_total']+=1
			response3=send_flagsfin_packet(ip[0:len(ip)-1],80)
			if(str(type(response2)) == "<type 'NoneType'>"):
				total['flagsfin_total']+=1
			response4=send_flagsack_packet(ip[0:len(ip)-1],80)
			if(str(type(response4)) != "<type 'NoneType'>"):
				if response1.flags == 2L and response4.getlayer(TCP).flags==4L: #ip.flags="DF" and tcp.flags=="RST"
					total['flagsack_total']+=1
			response5=send_flagsadd_packet(ip[0:len(ip)-1],80)
			if(str(type(response5)) != "<type 'NoneType'>"):
				if response4.getlayer(TCP).flags==18L: #tcp.flags=="SA"
					total['flagsadd_total']+=1

			response6=send_icmpecho1_packet(ip[0:len(ip)-1])
			if(str(type(response6)) != "<type 'NoneType'>"):
				if(response6.getlayer(IP).flags==0 and response6.getlayer(ICMP).code==9):
					total['icmpecho1_total']+=1
					icmpecho1.append(ip[0:len(ip)-1])
			response7=send_icmpecho2_packet(ip[0:len(ip)-1])
			if(str(type(response7)) != "<type 'NoneType'>"):
				if(response7.getlayer(IP).tos==4 and response7.getlayer(ICMP).code==0):
					total['icmpecho2_total']+=1

			response8=send_udp_packet(ip[0:len(ip)-1],44190)
			if(str(type(response8)) != "<type 'NoneType'>"):
				if(response8.getlayer(IP).tos==192 and response8.getlayer(IPerror).len==328):
					total['icmpintegrity_total']+=1
			print ip


	print live
	print "training result: " 
	print total
	#
	print "camera in win: %d" %(len(set(win).intersection(set(camera))))
	print "camera in IPID: %d" %(len(set(IPID).intersection(set(camera))))
	print "camera in options: %d" %(len(set(options).intersection(set(camera))))
	print "camera in icmpecho1: %d" %(len(set(icmpecho1).intersection(set(camera))))
	print "camera in DF: %d" %(len(set(DF).intersection(set(camera))))
	print "camera in ttl: %d" %(len(set(ttl).intersection(set(camera))))
	print "camera in acknum: %d" %(len(set(acknum).intersection(set(camera))))
	#
	temp= set(win).intersection(set(IPID))
	temp1=temp.intersection(set(icmpecho1))
	temp2=temp1.intersection(set(camera))
	print "test result:"
	print "intersection total: %d" %(len(temp1))
	print temp1
	print "camera in intersection: %d" %(len(temp2))
	print temp2
	print time.time()-t

if __name__=="__main__":	
    main()
