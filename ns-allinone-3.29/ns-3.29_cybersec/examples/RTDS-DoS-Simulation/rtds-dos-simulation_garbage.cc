#include <iomanip>
#include "ns3/command-line.h"
#include "ns3/config.h"
#include "ns3/uinteger.h"
#include "ns3/boolean.h"
#include "ns3/double.h"
#include "ns3/string.h"
#include "ns3/log.h"
#include "ns3/internet-stack-helper.h"
#include "ns3/ipv4-address-helper.h"
#include "ns3/udp-client-server-helper.h"
#include "ns3/log.h"
#include "ns3/ipv4-address.h"
#include "ns3/nstime.h"
#include "ns3/inet-socket-address.h"
#include "ns3/inet6-socket-address.h"
#include "ns3/socket.h"
#include "ns3/simulator.h"
#include "ns3/socket-factory.h"
#include "ns3/packet.h"
#include "ns3/uinteger.h"
#include "ns3/netanim-module.h"
#include "ns3/data-rate.h"
#include "ns3/udp-socket-factory.h"
#include "ns3/packet-sink-helper.h"
#include "ns3/ipv4-global-routing-helper.h"
#include <fstream>
#include "ns3/core-module.h"
#include "ns3/internet-module.h"
#include "ns3/applications-module.h"
#include "ns3/fd-net-device-module.h"
#include "ns3/point-to-point-module.h"
#include <sys/socket.h>
#include <arpa/inet.h>
#include "ns3/flow-monitor-helper.h"
#include "ns3/csma-helper.h"
 #include "ns3/mobility-module.h"
 #include "ns3/queue.h"
 #include "ns3/drop-tail-queue.h"
#include "ns3/malicious-tag.h"
#include "ns3/tcp-echo-server.h"
#include "ns3/packet-metadata.h"
#include "ns3/attack-app.h"
#include "ns3/ipv4-raw-socket-impl.h"

#define INGRESS_NODE 1
#define EGRESS_NODE 2
#define FORWARDING_NODE 4
#define MAN_IN_MIDDLE_NODE 3
#define AGGREGATOR_NODE 5
#define ON_TIME (std::string)"0.25"
#define BURST_PERIOD 1
#define OFF_TIME std::to_string(BURST_PERIOD - stof(ON_TIME))


using namespace ns3;
using namespace std;




class MyApp : public Application
{

public:

  MyApp ();

  virtual ~MyApp();


  void Setup (Ptr<Node> node,Ipv4Address raddress ,Ipv4Address address, uint16_t port,uint16_t peer_port,int type );
  void PrintTraffic (Ptr<Socket> socket);
  void PrintTraffic1 (Ptr<Socket> socket);
  void PrintTrafficManInMiddle (Ptr<Socket> socket);
  int sendMessage(  Ptr<Packet> packetNew, Ptr<Socket> txSocketn0);
  char ** giveParsingString(int msgType);
  char ** giveDestIPForPkt(Ptr<Packet> packetNew);
  void  pktProcessingIngressNode (Ptr<Socket> socket);
  void pktProcessingEgressNode (Ptr<Socket> socket);
  void pktProcessingAggregatorNode (Ptr<Socket> socket);
  void HandleAccept (Ptr<Socket> s, const Address& from);
  void HandlePeerClose (Ptr<Socket> socket);
  void HandlePeerError (Ptr<Socket> socket);
  void TearDownLink (Ptr<Node> nodeA, Ptr<Node> nodeB, uint32_t interfaceA, uint32_t interfaceB);

private:
  virtual void StartApplication (void);
  virtual void StopApplication (void);


//  void ScheduleTx (void);
//  void SendPacket (void);
//  void ReceivePacket (Ptr<Socket>);


  Ptr<Ipv4RawSocketImpl>     m_socket;
  Ptr<Socket>     m_rsocket;
  Ipv4Address     m_peer;
  uint16_t        m_port;
  uint16_t        m_peer_port;
  EventId         m_Event;
  uint32_t        m_packetsReceived;
  uint32_t        m_packetsSent;
  Ipv4Address     m_raddress;
  std::list<Ptr<Socket> > m_socketList; //the accepted sockets
  Ptr<Node>       node;
  int m_type_of_node;
  float previous = 0.0;
  float average = 0.0;
  int numSamples=0;

};

NS_LOG_COMPONENT_DEFINE ("MyApp");
NS_OBJECT_ENSURE_REGISTERED (MyApp);

MyApp::MyApp ()
  : m_socket (0),
	m_rsocket(0),
    m_peer (),
    m_port (0),
	m_peer_port(0),
    m_Event (),
    m_packetsReceived(0),
	m_packetsSent (0),
	m_raddress ()
{
	NS_LOG_FUNCTION_NOARGS ();
}

MyApp::~MyApp()
{
  NS_LOG_FUNCTION_NOARGS ();
  m_socket = 0;

}

void
MyApp::Setup (Ptr<Node> node,Ipv4Address raddress ,Ipv4Address address, uint16_t port,uint16_t peer_port,int type )
{


	NS_LOG_FUNCTION_NOARGS ();
    this->node=node;
    m_raddress = raddress;
    m_peer = address;
    m_port = port;
    m_peer_port = peer_port;
    m_type_of_node=type;


}

void MyApp::HandleAccept (Ptr<Socket> s, const Address& from)
		  {
	NS_LOG_FUNCTION (this << s << from);
	if(m_type_of_node ==3)
			m_rsocket->SetRecvCallback (MakeCallback (&MyApp::PrintTrafficManInMiddle,this));

		else if (m_type_of_node ==4)
			m_rsocket->SetRecvCallback (MakeCallback (&MyApp::PrintTraffic,this));
		else if(m_type_of_node ==1)
			m_rsocket->SetRecvCallback (MakeCallback (&MyApp::pktProcessingIngressNode,this));
		else if (m_type_of_node == 2)
			m_rsocket->SetRecvCallback (MakeCallback (&MyApp::pktProcessingEgressNode,this));
		else if (m_type_of_node == 5)
				m_rsocket->SetRecvCallback (MakeCallback (&MyApp::pktProcessingAggregatorNode,this));
		else if (m_type_of_node ==6)
				m_rsocket->SetRecvCallback (MakeCallback (&MyApp::PrintTraffic1,this));
	m_socketList.push_back (s);
		  }

void MyApp::HandlePeerClose (Ptr<Socket> socket)
{
	NS_LOG_FUNCTION (this << socket);
}

void MyApp::HandlePeerError (Ptr<Socket> socket)
{
	NS_LOG_FUNCTION (this << socket);
}

void MyApp::StartApplication (void)
{
	NS_LOG_FUNCTION_NOARGS ();
 // m_type_of_node = 1 ingress 2 egress 3 man-in-the-middle 4 just_forward

	TypeId tid = TypeId::LookupByName ("ns3::TcpSocketFactory");
	       		m_rsocket  = Socket::CreateSocket (this->node, tid);





	//m_rsocket->SetAttribute ("IpHeaderInclude", BooleanValue (true));
	std::printf("Number of Dev %d Node Num: %d \n",this->node->GetNDevices(),this->node->GetId());
	Ptr<Ipv4> ipV4Info = this->node->GetObject<Ipv4>();
	//std::cout<<"IP:"<<m_raddress;
//	int interfaceIndex = ipV4Info->GetInterfaceForAddress(m_raddress);
	//std::cout<<"NetDev:"<<interfaceIndex;
	//m_rsocket->BindToNetDevice(this->node->GetDevice(interfaceIndex));

//
//	if (m_type_of_node == 2)
//	{
//		m_socket->Bind (InetSocketAddress (Ipv4Address("172.24.2.144"), m_port));
//		int interfaceIndex = ipV4Info->GetInterfaceForAddress(Ipv4Address("172.24.2.144"));
//		std::cout<<"NetDev:"<<interfaceIndex;
//		m_socket->BindToNetDevice(this->node->GetDevice(interfaceIndex));
//		m_socket->Initialize();
//		m_socket->Listen();
//		m_socket->SetAcceptCallback (MakeNullCallback<bool, Ptr<Socket>, const Address &> (),MakeCallback (&MyApp::HandleAccept, this));
//		m_socket->SetCloseCallbacks (MakeCallback (&MyApp::HandlePeerClose, this), MakeCallback (&MyApp::HandlePeerError, this));
//	}
//	else if (m_type_of_node == 3 || m_type_of_node == 4)
//	{
//		m_rsocket->Bind (InetSocketAddress (m_raddress, m_port));
//				int interfaceIndex = ipV4Info->GetInterfaceForAddress(m_raddress);
//				std::cout<<"Aggregator NetDev:"<<interfaceIndex;
//				m_rsocket->BindToNetDevice(this->node->GetDevice(interfaceIndex));
//	}
	//else
		m_rsocket->Bind (InetSocketAddress (m_raddress, m_port));

		//int interfaceIndex = ipV4Info->GetInterfaceForAddress(m_raddress);
				//std::cout<<"NetDev:"<<interfaceIndex;
				//m_rsocket->BindToNetDevice(this->node->GetDevice(interfaceIndex));
	//m_rsocket->Initialize();
	m_rsocket->Listen();
	m_rsocket->SetAcceptCallback (MakeNullCallback<bool, Ptr<Socket>, const Address &> (),MakeCallback (&MyApp::HandleAccept, this));
	m_rsocket->SetCloseCallbacks (MakeCallback (&MyApp::HandlePeerClose, this), MakeCallback (&MyApp::HandlePeerError, this));

	if(m_type_of_node ==3)
		m_rsocket->SetRecvCallback (MakeCallback (&MyApp::PrintTrafficManInMiddle,this));

	else if (m_type_of_node ==4)
		m_rsocket->SetRecvCallback (MakeCallback (&MyApp::PrintTraffic,this));
	else if(m_type_of_node ==1)
		m_rsocket->SetRecvCallback (MakeCallback (&MyApp::pktProcessingIngressNode,this));
	else if (m_type_of_node == 2)
		m_rsocket->SetRecvCallback (MakeCallback (&MyApp::pktProcessingEgressNode,this));
	else if (m_type_of_node == 5)
			m_rsocket->SetRecvCallback (MakeCallback (&MyApp::pktProcessingAggregatorNode,this));
	else if (m_type_of_node ==6)
			m_rsocket->SetRecvCallback (MakeCallback (&MyApp::PrintTraffic1,this));


//	Ptr<Ipv4RawSocketFactory> txSocketFactory = this->node->GetObject<Ipv4RawSocketFactory> ();
//		m_socket =  DynamicCast<Ipv4RawSocketImpl> (txSocketFactory->CreateSocket ());
//		m_socket->SetRecvPktInfo (true);
//		m_socket->SetProtocol(UdpL4Protocol::PROT_NUMBER);
//
//		//m_socket->BindToNetDevice(this->node->GetDevice(interfaceIndex));
//		m_socket->Bind (InetSocketAddress (Ipv4Address::GetAny (), m_port+1));
//		m_socket->Listen();
//		m_socket->SetAcceptCallback (MakeNullCallback<bool, Ptr<Socket>, const Address &> (),MakeCallback (&MyApp::HandleAccept, this));
//		m_socket->SetCloseCallbacks (MakeCallback (&MyApp::HandlePeerClose, this), MakeCallback (&MyApp::HandlePeerError, this));
//
//		if(m_type_of_node ==3)
//			m_socket->SetRecvCallback (MakeCallback (&MyApp::PrintTrafficManInMiddle,this));
//
//		else if (m_type_of_node ==4)
//			m_socket->SetRecvCallback (MakeCallback (&MyApp::PrintTraffic,this));
//		else if(m_type_of_node ==1)
//			m_socket->SetRecvCallback (MakeCallback (&MyApp::pktProcessingIngressNode,this));
//		else if (m_type_of_node == 2)
//			m_socket->SetRecvCallback (MakeCallback (&MyApp::pktProcessingEgressNode,this));
//		else if (m_type_of_node == 5)
//				m_socket->SetRecvCallback (MakeCallback (&MyApp::pktProcessingAggregatorNode,this));
//		else if (m_type_of_node ==6)
//				m_socket->SetRecvCallback (MakeCallback (&MyApp::PrintTraffic1,this));

  m_packetsSent = 0;
  m_packetsReceived=0;

}

void
MyApp::StopApplication (void)
{
	NS_LOG_FUNCTION_NOARGS ();

  if (m_Event.IsRunning ())
    {
      Simulator::Cancel (m_Event);
    }

  if (m_rsocket)
    {
      m_rsocket->Close ();
    }
  if (m_socket)
      {
        m_socket->Close ();
      }
}

void
MyApp::PrintTraffic (Ptr<Socket> socket)
 {
	 Packet::EnablePrinting();
	   Ptr<Packet> packet;
	   Address from;
	   //char ** destIP;

	   while ((packet = socket->RecvFrom (from)))
	     {
		   //packet->PrintPacketTags(std::cerr);
		   m_packetsReceived++;
		   Ipv4Header ipV4Hdr;
		   packet->RemoveHeader (ipV4Hdr);
//		   UdpHeader udpHdr;
//		   packet->RemoveHeader (udpHdr);

		   ipV4Hdr.SetSource(m_raddress);
//		   udpHdr.SetDestinationPort(7001);
//		   udpHdr.SetSourcePort(7001);
//		   UdpHeader udpHdr;
//		   packet->RemoveHeader (udpHdr);
	      // std::cout << "at=" << Simulator::Now ().GetSeconds () << "s, rx bytes=" << packet->GetSize () << std::endl;
	      // destIP = giveDestIPForPkt( packet);
	       unsigned char buffer[packet->GetSize ()+1] ;
	       unsigned int bufferFloat[packet->GetSize ()+1];
	       packet->CopyData (buffer, packet->GetSize ());
	       //int integerData;
	       float floatingPointData;
	       memcpy(&bufferFloat, &buffer[0], 4);

	       bufferFloat[0] = ntohl(bufferFloat[0]);
	       bufferFloat[1] = ntohl(bufferFloat[1]);
	       memcpy(&floatingPointData, &bufferFloat[1], 4);
	       //printf("point0 = %d\n", bufferFloat[0]);
	      // printf("point1 = %f\n", floatingPointData);
	       //Ptr<Packet> copy = packet->Copy ();
	       //Ipv4Header iph;
	       //copy->RemoveHeader (iph);
	       //Ipv4Address destAddr = iph.GetDestination();

	       //int numbTx = txSocketn0->Send(packet);

	       //std::printf("Float as int:  %x\n",bufferFloat[1]);
	       //std::printf("Float as float: %f\n",floatingPointData);



	       	       Ptr<Packet> packetNew = Create<Packet>(buffer,packet->GetSize ());
	       	       //packetNew->AddHeader(udpHdr);
	       	       //packetNew->AddHeader(ipV4Hdr);

	       	       socket->SendTo(packetNew,0,InetSocketAddress (m_peer, m_peer_port));
	       m_packetsSent++;
	       //m_Event= Simulator::Schedule (Simulator::Now (), &MyApp::sendMessage, packetNew,m_socket);
	       //txSocketn0->SetSendCallback (MakeBoundCallback (&SendMsg,packet));

	     }



 }

void
MyApp::PrintTraffic1 (Ptr<Socket> socket)
 {
	 Packet::EnablePrinting();
	   Ptr<Packet> packet;

	   //char ** destIP;
	   Address from;
	   while ((packet = socket->RecvFrom (from)))
	     {

		   m_packetsReceived++;
		   Ipv4Header ipHdr;
		   packet->RemoveHeader (ipHdr);
		   UdpHeader udpHdr;
		   packet->RemoveHeader (udpHdr);
//
//		   printf("\n IP HDR \n");
//		   ipHdr.Print(std::cout);
//		   printf("UDP HDR \n");
//		   udpHdr.Print(std::cout);
//		   printf("\n");
	      // std::cout << "at=" << Simulator::Now ().GetSeconds () << "s, rx bytes=" << packet->GetSize () << std::endl;
	      // destIP = giveDestIPForPkt( packet);
		  // packet->PrintPacketTags(std::cerr);
	       unsigned char buffer[packet->GetSize ()+1] ;
	       //unsigned char adressBuf[1024] ;
	       unsigned int bufferFloat[packet->GetSize ()+1];
	       packet->CopyData (buffer, packet->GetSize ());
	       //int integerData;
	       float floatingPointData;
	       memcpy(&bufferFloat, &buffer[0], 8);

	       bufferFloat[0] = ntohl(bufferFloat[0]);
	       bufferFloat[1] = ntohl(bufferFloat[1]);
	       memcpy(&floatingPointData, &bufferFloat[1], 4);
	       printf("Time = %f\n", floatingPointData);
	       //from.CopyTo(adressBuf);
	       //printf("From = %s\n",adressBuf );


	       average = (average*numSamples+(floatingPointData-previous))/(numSamples+1);
	       numSamples++;
	       printf("Average = %f\n",average);
	       printf("Samples = %d\n",numSamples);
	       previous=floatingPointData;




	       //Ptr<Packet> copy = packet->Copy ();
	       //Ipv4Header iph;
	       //copy->RemoveHeader (iph);socket->m_spoof
	       //Ipv4Address destAddr = iph.GetDestination();

	       //int numbTx = txSocketn0->Send(packet);

	       //std::printf("Float as int:  %x\n",bufferFloat[1]);
	       //std::printf("Float as float: %f\n",floatingPointData);

	       //m_socket->SendTo(packet,0,InetSocketAddress (m_peer, m_peer_port));
	       m_packetsSent++;
	       //m_Event= Simulator::Schedule (Simulator::Now (), &MyApp::sendMessage, packetNew,m_socket);
	       //txSocketn0->SetSendCallback (MakeBoundCallback (&SendMsg,packet));

	     }



 }



void
MyApp::PrintTrafficManInMiddle (Ptr<Socket> socket)
 {
	 Packet::EnablePrinting();
	   Ptr<Packet> packet;


	  Address from;
	   while ((packet = socket->RecvFrom (from)))
	     {
		   std::printf("In Print traffic MITM method \n");
		   m_packetsReceived++;
	       //std::cout << "at=" << Simulator::Now ().GetSeconds () << "s, rx bytes=" << packet->GetSize () << std::endl;
		   Ipv4Header ipV4Hdr1;
		   packet->RemoveHeader (ipV4Hdr1);
//		   UdpHeader udpHdr1;
//		   packet->RemoveHeader (udpHdr1);


	       unsigned char buffer[packet->GetSize ()] ;
	       unsigned int bufferFloat[packet->GetSize ()];
	       packet->CopyData (buffer, packet->GetSize ());
	       int integerData;
	       float floatingPointData;
	       memcpy(&bufferFloat, &buffer[0], packet->GetSize ());
	       Ipv4Header ipV4Hdr;
	       UdpHeader udpHdr;
	       ipV4Hdr.SetSource(m_raddress);
	       ipV4Hdr.SetDestination(m_peer);
	       ipV4Hdr.SetSource(Ipv4Address("172.24.2.144"));
	       ipV4Hdr.SetProtocol(17); // 17 stands for udp
	       ipV4Hdr.SetTtl(255);
	       udpHdr.SetDestinationPort(7001);
	       udpHdr.SetSourcePort(7001);
	       bufferFloat[0] = ntohl(bufferFloat[0]);

	       //printf("msgType = %d\n", bufferFloat[0]);

	       //Ptr<Packet> copy = packet->Copy ();
	       //Ipv4Header iph;
	       //copy->RemoveHeader (iph);
	       //Ipv4Address destAddr = iph.GetDestination();

	       //int numbTx = txSocketn0->Send(packet);

	       //std::printf("Float as int:  %x\n",bufferFloat[1]);
	       //std::printf("Float as float: %f\n",floatingPointData);
	       integerData =  bufferFloat[0];
	       char ** string = giveParsingString(integerData);

	       int i=0;
	       if(Simulator::Now ().GetSeconds ()<0.0)
	       {
	       while(strcmp(string[i],"end")!=0 )
	       {
	    	   //printf("dataType = %s\n", string[i]);
	    	   if(strcmp(string[i],"float")==0)
	    	   {
	    		  //printf("dataType = %s\n", string[i]);
	    		   bufferFloat[i] = ntohl(bufferFloat[i]);
	    		   memcpy(&floatingPointData, &bufferFloat[i], 4);
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
	    		   bufferFloat[i] = htonl(bufferFloat[i]);
	    	   }
	    	   i++;
	       }
	       }
	       bufferFloat[0] = htonl(bufferFloat[0]);
	       memcpy(&buffer, &bufferFloat, packet->GetSize ());
	       ipV4Hdr.SetIdentification(m_packetsSent);
	       	    	   //udpHdr.ForcePayloadSize(packet->GetSize ());
	       	    	   udpHdr.InitializeChecksum(m_raddress,m_peer,17);

	       Ptr<Packet> packetNew = Create<Packet>(buffer,packet->GetSize ());
	       udpHdr.EnableChecksums();
	       	    	   //packetNew->AddHeader(udpHdr);
	       	    	   ipV4Hdr.SetPayloadSize(packetNew->GetSize());
	       	    	   ipV4Hdr.EnableChecksum();
	       	    	   //socket->SetAttribute ("IpHeaderInclude", BooleanValue (true));
	       	    	   //packetNew->AddHeader(ipV4Hdr);

	       socket->SendTo(packetNew,0,InetSocketAddress (m_peer, m_peer_port));
	       m_packetsSent++;




	       //m_Event= Simulator::Schedule (Simulator::Now (), &MyApp::sendMessage, packetNew,m_socket);
	       //txSocketn0->SetSendCallback (MakeBoundCallback (&SendMsg,packet));

	     }



 }

void
MyApp::pktProcessingIngressNode (Ptr<Socket> socket)
 {
	 Packet::EnablePrinting();
	   Ptr<Packet> packet;

	   //Ptr<Ipv4L3Protocol> ipv4L3Protocol = m_node->GetObject<Ipv4L3Protocol > ();
	   // NS_ASSERT(ipv4L3Protocol);
	    socket = DynamicCast<Ipv4RawSocketImpl>(socket);
	   //u_int32_t interfaceIndex = ipv4L3Protocol->GetInterfaceForDevice(socket->GetBoundNetDevice());

	    Address from;
	   while (socket->GetRxAvailable () > 0)
	     {
		   uint32_t toRead =socket->GetRxAvailable ();
		   packet = socket->Recv (toRead, 0);

//		   std::printf("In Print Pkt Ingress\n");
//		   packet->Print(std::cout);
		   m_packetsReceived++;

		   Ipv4Header ipV4Hdr1;
		   packet->RemoveHeader (ipV4Hdr1);
		   printf("\n IP HDR in Ingress \n");
		   ipV4Hdr1.Print(std::cout);

		   TcpHeader udpHdr1;
		   packet->PeekHeader (udpHdr1);
		   printf("UDP HDR Ingress \n");
		   udpHdr1.Print(std::cout);
		   printf("\n");
		   if(udpHdr1.GetFlags()==udpHdr1.SYN){
			   std::cout << udpHdr1.FlagsToString(udpHdr1.GetFlags(), ",")<<endl;
			   //m_rsocket->ForwardUp(packet, ipV4Hdr1, ipv4L3Protocol->GetInterface(interfaceIndex));
			   continue;

		   }
		   if(udpHdr1.GetDestinationPort()!=7001)
		   		   {
		   			   continue;
		   		   }
		   		   		//packet->Print(std::cout);

	       //std::cout << "Ingress at=" << Simulator::Now ().GetSeconds () << "s, rx bytes=" << packet->GetSize () << std::endl;


		   Ipv4Header ipV4Hdr;
		   TcpHeader udpHdr;
		   udpHdr.SetDestinationPort(7001);
		   udpHdr.SetSourcePort(7001);



	       unsigned char buffer[packet->GetSize ()+1] ;
	       unsigned int bufferFloat[packet->GetSize ()];

	       packet->CopyData (buffer, packet->GetSize ());
	       int type;
	      int indexOfNode;
	       memcpy(&bufferFloat, &buffer[0], 8);

	       bufferFloat[0] = ntohl(bufferFloat[0]);
	       bufferFloat[1] = ntohl(bufferFloat[1]);
	       type = bufferFloat[0];
	       indexOfNode = bufferFloat[1];
	       std::cout <<"Type:"<<type<<std::endl;
	       std::cout <<"Index of Node:"<<indexOfNode<<std::endl;
	       std::string to;
	       if(type==5 || type==8)
	       {
	    	   switch(indexOfNode)
	    	   {
	    	   case(1):

	    		   //m_socket->Connect (InetSocketAddress (Ipv4Address("10.1.6.2"), 7001));
	    	       to = "10.1.6.2";
	    	   	   ipV4Hdr.SetSource(Ipv4Address("10.1.6.1"));
	    	   	   ipV4Hdr.SetDestination(Ipv4Address("10.1.6.2"));
	    	   	   //std::cout <<"Sent to:10.1.6.2"<<std::endl;
	    	   	   break;

	    	   case(2):

	    		  // m_socket->Connect (InetSocketAddress (Ipv4Address("10.1.6.6"), 7001));
					ipV4Hdr.SetSource(Ipv4Address("10.1.6.5"));
				   ipV4Hdr.SetDestination(Ipv4Address("10.1.6.6"));
	    	       to = "10.1.6.6";
	    	   	   break;

	    	   case(3):

	    		  // m_socket->Connect (InetSocketAddress (Ipv4Address("10.1.6.10"), 7001));
				   ipV4Hdr.SetSource(Ipv4Address("10.1.6.9"));
				   ipV4Hdr.SetDestination(Ipv4Address("10.1.6.10"));
	    	       to = "10.1.6.10";
	    	   	   break;

	    	   case(4):

	    		   //m_socket->Connect (InetSocketAddress (Ipv4Address("10.1.6.14"), 7001));
				   ipV4Hdr.SetSource(Ipv4Address("10.1.6.13"));
				   ipV4Hdr.SetDestination(Ipv4Address("10.1.6.14"));
	    	   	   to = "10.1.6.14";
	    	   	   break;

	    	   default:
	    		   std::printf("Invalid node index");
	    		   break;


	    	   }
	       }

	       else if(type==4 || type==7)
	       {
	    	   switch(indexOfNode)
	    	   {
	    	   case(1):

	       	    								   //m_socket->Connect (InetSocketAddress (Ipv4Address("10.1.6.18"), 7001));
	       	    	    						   //std::cout <<"Sent to:10.1.6.18"<<std::endl;
												   ipV4Hdr.SetDestination(Ipv4Address("10.1.6.18"));
	    	   	   	   	   	   	   	   	   	   	   to = "10.1.6.18";
	    	   break;

	    	   case(2):

	       	    						  // m_socket->Connect (InetSocketAddress (Ipv4Address("10.1.6.18"), 7001));
										ipV4Hdr.SetDestination(Ipv4Address("10.1.6.18"));
	    	   	   	   	   	   	   	   to = "10.1.6.18";
	    	   break;

	    	   case(3):

	       	    						  // m_socket->Connect (InetSocketAddress (Ipv4Address("10.1.6.18"), 7001));
						ipV4Hdr.SetDestination(Ipv4Address("10.1.6.18"));
	    	   	   	   to = "10.1.6.18";
	    	   break;

	    	   case(4):

	       	    						  // m_socket->Connect (InetSocketAddress (Ipv4Address("10.1.6.18"), 7001));
						ipV4Hdr.SetDestination(Ipv4Address("10.1.6.18"));
	    	   	   	   	   to = "10.1.6.18";
	    	   break;

	    	   default:
	    		   std::printf("Invalid node index");
	    		   break;


	    	   }
	       }

	       else if(type== 1 )
	      	       	       {

	      	       	    		  // m_socket->Connect (InetSocketAddress (Ipv4Address("172.24.9.249"), 7001));
	      	       	    		to = "172.24.9.249";
	      	       	    	ipV4Hdr.SetDestination(Ipv4Address("172.24.9.249"));



	      	       	       }
	       else if(type== 3 )
	      	      	       	       {

	      	      	       	    		 //  m_socket->Connect (InetSocketAddress (Ipv4Address("172.24.9.250"), 7001));
	      	      	       	    	to = "172.24.9.250";
	      	      	       	 ipV4Hdr.SetDestination(Ipv4Address("172.24.9.250"));



	      	      	       	       }

	       //socket->SetAttribute ("IpHeaderInclude", BooleanValue (true));
	       Ptr<Packet> packetNew = Create<Packet>(buffer,packet->GetSize ());
	       	       	    	//packetNew->AddHeader(udpHdr);
	       	       	    	//packetNew->AddHeader(ipV4Hdr);
	       	       	    	if(!to.empty()){
	       	       	    		       socket->SendTo(packetNew,0,InetSocketAddress (Ipv4Address (to.c_str ()), 7001));
	       	       	    		       m_packetsSent++;
	       	       	    	}
	       //m_Event= Simulator::Schedule (Simulator::Now (), &MyApp::sendMessage, packetNew,m_socket);
	       //txSocketn0->SetSendCallback (MakeBoundCallback (&SendMsg,packet));

	     }



 }

void
MyApp::pktProcessingEgressNode (Ptr<Socket> socket)
 {
	 Packet::EnablePrinting();
	   Ptr<Packet> packet;
	   Ptr<Ipv4> ipV4Info = this->node->GetObject<Ipv4>();
	   //	std::cout<<"IP routing prot:"<<ipV4Info->GetRoutingProtocol()<<endl;
//	   	int interfaceIndex = ipV4Info->GetInterfaceForAddress(Ipv4Address("172.24.2.144"));
//	   	std::cout<<"NetDev:"<<interfaceIndex;
//	   	socket->BindToNetDevice(this->node->GetDevice(interfaceIndex));

	   Address from;
	   	   while ((packet = socket->RecvFrom (from)))
	     {

		   m_packetsReceived++;
//		   std::printf("In Print Pkt Egress\n");
//		   		   packet->Print(std::cout);

		   		Ipv4Header ipV4Hdr1;
		   				   packet->RemoveHeader (ipV4Hdr1);

		   				if(ipV4Hdr1.GetProtocol()!=17)
		   						   		   {
		   						   			   continue;
		   						   		   }
		   				   //printf("\n IP HDR in Egress \n");
//		   				   ipV4Hdr1.Print(std::cout);
		   				   ipV4Hdr1.SetSource(m_raddress);
//		   				   UdpHeader udpHdr;
//		   				   packet->RemoveHeader (udpHdr);
//		   				   printf("UDP HDR Egress \n");
//		   				   udpHdr.Print(std::cout);
//		   				   printf("\n");

//		   		 PacketMetadata::ItemIterator metaData = packet->BeginItem();
//		   				   		   		   PacketMetadata::Item metaDataItem;
//		   				   		   		   int removableBytes=0;
//
//		   				   		   			while(metaData.HasNext())
//		   				   		   			{
//		   				   		   				metaDataItem = metaData.Next();
//		   				   		   			 if( metaDataItem.type == PacketMetadata::Item::HEADER)
//		   				   		   					   		   {
//		   				   		   				 	 	 	 	 std::cout<<"Header Type"<<metaDataItem.tid.GetName();
//		   				   		   					   			removableBytes+=metaDataItem.currentSize;
//		   				   		   					   		   }
//		   				   		   			 else if(metaDataItem.type == PacketMetadata::Item::PAYLOAD){
//		   				   								 std::printf("Removable byte: %d\n",removableBytes);
//
//		   				   								packet->RemoveAtStart(removableBytes);
//		   				   								break;
//		   				   		   			}
//		   				   		   			}
		   				   		   	TcpHeader udpHdr;
		   				   		   				  		   		Ipv4Header ipV4Hdr;
		   				   		   				  		   		ipV4Hdr.SetSource(Ipv4Address("172.24.2.55"));
		   				   		   				  		   		ipV4Hdr.SetProtocol(17); // 17 stands for udp
		   				   		   				  		   		ipV4Hdr.SetTtl(255);
		   				   		   				  		   		udpHdr.SetDestinationPort(7001);
		   				   		   				  		   		udpHdr.SetSourcePort(7001);


	       unsigned char buffer[packet->GetSize ()+1] ;
	       unsigned int bufferFloat[packet->GetSize ()];
	       packet->CopyData (buffer, packet->GetSize ());
	       int type;
	       int indexOfNode;
	       int secondNodeIndex;
	       memcpy(&bufferFloat, &buffer[0], 12);

	       bufferFloat[0] = ntohl(bufferFloat[0]);
	       bufferFloat[1] = ntohl(bufferFloat[1]);
	       type = bufferFloat[0];
	       indexOfNode = bufferFloat[1];
	       std::string to;
	       if(type==7)
	       		       {
	       		    	   bufferFloat[2] = ntohl(bufferFloat[2]);
	       		    	   secondNodeIndex = bufferFloat[2];
	       		       }
//	       std::cout <<"Type:"<<type<<endl;
//	       std::cout <<"Index of Node:"<<indexOfNode<<endl;
//	       std::cout <<"Index of 2 Node:"<<secondNodeIndex<<endl;
	       if(type==5 || type==8)
	       {
	    	   switch(indexOfNode)
	    	   {
	    	   case(1):

	    		   //m_socket->Connect (InetSocketAddress (Ipv4Address("172.24.9.244"), 7001));
	    	   	   to = "172.24.9.244";
	    	   	   ipV4Hdr.SetDestination(Ipv4Address("172.24.9.244"));
	    	   	   std::cout <<"Sent to:172.24.9.244"<<std::endl;
	    	   	   break;

	    	   case(2):

	    		   //m_socket->Connect (InetSocketAddress (Ipv4Address("172.24.9.245"), 7001));
	    	   	   to = "172.24.9.245";
	    	   	   ipV4Hdr.SetDestination(Ipv4Address("172.24.9.245"));
	    	   //std::cout <<"Sent to:172.24.9.245"<<std::endl;
	    	   	   break;

	    	   case(3):

	    		   //m_socket->Connect (InetSocketAddress (Ipv4Address("172.24.9.246"), 7001));
	    	       to = "172.24.9.246";
	    	   ipV4Hdr.SetDestination(Ipv4Address("172.24.9.246"));
	    	   //std::cout <<"Sent to:172.24.9.246"<<std::endl;
	    	   	   break;

	    	   case(4):

	    		  // m_socket->Connect (InetSocketAddress (Ipv4Address("172.24.9.247"), 7001));
	    	       to = "172.24.9.247";
	    	   ipV4Hdr.SetDestination(Ipv4Address("172.24.9.247"));
	    	   //std::cout <<"Sent to:172.24.9.247"<<std::endl;
	    	   	   break;

	    	   default:
	    		   std::printf("Invalid node index");
	    		   break;


	    	   }
	    	   Ptr<Packet> packetNew = Create<Packet>(buffer,packet->GetSize ());
	    	   ipV4Hdr.SetIdentification(m_packetsSent);
	    	   //udpHdr.ForcePayloadSize(packet->GetSize ());
	    	   udpHdr.InitializeChecksum(Ipv4Address("172.24.2.55"),Ipv4Address(to.c_str ()),17);

	    	   udpHdr.EnableChecksums();
	    	   packetNew->AddHeader(udpHdr);
	    	   ipV4Hdr.SetPayloadSize(packetNew->GetSize());
	    	   ipV4Hdr.EnableChecksum();
	    	   m_socket->SetAttribute ("IpHeaderInclude", BooleanValue (true));
	    	   packetNew->AddHeader(ipV4Hdr);
	    	   if(!to.empty()){
	    	   	       int status = m_socket->SendTo(packetNew,0,InetSocketAddress (Ipv4Address (to.c_str ()), 7001));
	    	   	    std::cout <<"Sent to:"<< to.c_str () << "NumBytes:"<<status <<std::endl;
	    	   	       m_packetsSent++;
	    	   }
	       }

	       else if(type==4 || type==7)
	       	       {
	       	    	   switch(secondNodeIndex)
	       	    	   {
	       	    	   case(1):

	       	    		   //m_socket->Connect (InetSocketAddress (Ipv4Address("172.24.9.240"), 7001));
	       	    	   	   to = "172.24.9.240";
	       	    	   	   ipV4Hdr.SetDestination(Ipv4Address("172.24.9.240"));
	       	    	   	   break;

	       	    	   case(2):

	       	    		   //m_socket->Connect (InetSocketAddress (Ipv4Address("172.24.9.241"), 7001));
	       	    	   	   to = "172.24.9.241";
	       	    	   	   ipV4Hdr.SetDestination(Ipv4Address("172.24.9.241"));
	       	    	   	   break;

	       	    	   case(3):

	       	    		  // m_socket->Connect (InetSocketAddress (Ipv4Address("172.24.9.242"), 7001));
	       	    	   	   to = "172.24.9.242";
	       	    	   	   ipV4Hdr.SetDestination(Ipv4Address("172.24.9.242"));
	       	    	   	   break;

	       	    	   case(4):

	       	    		   //m_socket->Connect (InetSocketAddress (Ipv4Address("172.24.9.243"), 7001));
								ipV4Hdr.SetDestination(Ipv4Address("172.24.9.243"));
	       	    	   	   to = "172.24.9.243";
	       	    	   	   break;

	       	    	   default:
	       	    		   std::printf("Invalid node index");
	       	    		   break;


	       	    	   }
	       	    	Ptr<Packet> packetNew = Create<Packet>(buffer,packet->GetSize ());
	       	    	ipV4Hdr.SetIdentification(m_packetsSent);
	       	    	//ipV4Hdr.EnableChecksum();
	       	    	//udpHdr.EnableChecksums();

	       	    	packetNew->AddHeader(udpHdr);
	       	    	packetNew->AddHeader(ipV4Hdr);


	       	    	if(!to.empty()){
	       	    		       socket->SendTo(packetNew,0,InetSocketAddress (Ipv4Address (to.c_str ()), 7001));
	       	    		       m_packetsSent++;
	       	    	}
	       	       }

	       else if(type== 1 )
	      	       	       {

	      	       	    		 //  m_socket->Connect (InetSocketAddress (Ipv4Address("172.24.9.250"), 7001));




	      	       	       }
	       else if(type== 3 )
	      	      	       	       {

	      	      	       	    		//   m_socket->Connect (InetSocketAddress (Ipv4Address("172.24.9.248"), 7001));




	      	      	       	       }

	       //m_Event= Simulator::Schedule (Simulator::Now (), &MyApp::sendMessage, packetNew,m_socket);
	       //txSocketn0->SetSendCallback (MakeBoundCallback (&SendMsg,packet));

	     }



 }

void MyApp::TearDownLink (Ptr<Node> nodeA, Ptr<Node> nodeB, uint32_t interfaceA, uint32_t interfaceB)
{
  nodeA->GetObject<Ipv4> ()->SetDown (interfaceA);
  nodeB->GetObject<Ipv4> ()->SetDown (interfaceB);
}

void MyApp::pktProcessingAggregatorNode (Ptr<Socket> socket)
{
	Packet::EnablePrinting();
		   Ptr<Packet> packet;


		   Address from;

		   //m_socket->Connect (InetSocketAddress (m_peer, m_peer_port)); //depends on the data
		   while ((packet = socket->RecvFrom (from)))
		     {
			  // std::printf("In Aggregator \n");
			   std::printf("In Print Pkt Aggregator\n");
			   		   packet->Print(std::cout);
			   m_packetsReceived++;

			   Ipv4Header ipV4Hdr;
			   		   				   packet->RemoveHeader (ipV4Hdr);
			   		   				   printf("\n IP HDR in Aggregator \n");
			   		   				   ipV4Hdr.Print(std::cout);
			   		   				   ipV4Hdr.SetSource(m_raddress);
			   		   				   UdpHeader udpHdr;
			   		   				   packet->RemoveHeader (udpHdr);
			   		   				   printf("UDP HDR Aggregator \n");
			   		   				   udpHdr.Print(std::cout);
			   		   				   printf("\n");
		       //std::cout << "Ingress at=" << Simulator::Now ().GetSeconds () << "s, rx bytes=" << packet->GetSize () << std::endl;
//			   PacketMetadata::ItemIterator metaData = packet->BeginItem();
//			  		   				   		   		   PacketMetadata::Item metaDataItem;
//			  		   				   		   		   int removableBytes=0;
//
//			  		   				   		   			while(metaData.HasNext())
//			  		   				   		   			{
//			  		   				   		   				metaDataItem = metaData.Next();
//			  		   				   		   			 if( metaDataItem.type == PacketMetadata::Item::HEADER)
//			  		   				   		   					   		   {
//			  		   				   		   				 	 	 	 	 std::cout<<"Header Type"<<metaDataItem.tid.GetName();
//			  		   				   		   					   			removableBytes+=metaDataItem.currentSize;
//			  		   				   		   					   		   }
//			  		   				   		   			 else if(metaDataItem.type == PacketMetadata::Item::PAYLOAD){
//			  		   				   								 std::printf("Removable byte: %d\n",removableBytes);
//
//			  		   				   								packet->RemoveAtStart(removableBytes);
//			  		   				   								break;
//			  		   				   		   			}
//			  		   				   		   			}

//			  		   		UdpHeader udpHdr;
//			  		   		Ipv4Header ipV4Hdr;
//			  		   		ipV4Hdr.SetSource(m_raddress);
			  		   		udpHdr.SetDestinationPort(7001);
			  		   		udpHdr.SetSourcePort(7001);


//			   		   			while(metaData.HasNext())
//			   		   			{
//			   		   				metaDataItem = metaData.Next();
//			   							if(metaDataItem.type == metaDataItem.HEADER){
//			   								packet->RemoveHeader (udpHdr);
//
//			   		   						   printf("UDP HDR \n");
//			   		   						   		   udpHdr.Print(std::cout);
//			   		   						   		   printf("\n");
//			   		   			}
//			   							if(metaDataItem.type == metaDataItem.PAYLOAD){
//			   								break;
//			   							}
//			   							}


		       unsigned char buffer[packet->GetSize ()+1] ;
		       unsigned int bufferFloat[packet->GetSize ()];
		       packet->CopyData (buffer, packet->GetSize ());
		       int type;
		       int indexOfNode;
		       int secondNodeIndex = 0 ;
		       memcpy(&bufferFloat, &buffer[0], 12);

		       bufferFloat[0] = ntohl(bufferFloat[0]);
		       bufferFloat[1] = ntohl(bufferFloat[1]);
		       std::string to;
		       type = bufferFloat[0];
		       indexOfNode = bufferFloat[1];
		       if(type==7)
		       {
		    	   bufferFloat[2] = ntohl(bufferFloat[2]);
		    	   secondNodeIndex = bufferFloat[2];
		       }

		       std::cout <<"Type:"<<type<<endl;
		       std::cout <<"Index of Node:"<<indexOfNode<<endl;
		       std::cout <<"Index of 2 Node:"<<secondNodeIndex<<endl;

		       if(type==4 || type==7)
		       	       {
		       	    	   switch(secondNodeIndex)
		       	    	   {
		       	    	   case(1):

		       	    		   //m_socket->Connect (InetSocketAddress (Ipv4Address("10.1.7.2"), 7001));
		       	    	   	   to = "10.1.7.2";
		       	    	   	   ipV4Hdr.SetDestination(Ipv4Address("10.1.7.2"));
		       	    	 //std::cout <<"Sent to:10.1.7.2"<<std::endl;
		       	    	   	   break;

		       	    	   case(2):

		       	    		   //m_socket->Connect (InetSocketAddress (Ipv4Address("10.1.7.6"), 7001));
		       	    	   	   to = "10.1.7.6";
		       	    	 ipV4Hdr.SetDestination(Ipv4Address("10.1.7.6"));
		       	    	   	   break;

		       	    	   case(3):

		       	    		   //m_socket->Connect (InetSocketAddress (Ipv4Address("10.1.7.10"), 7001));
		       	    	   	   to = "10.1.7.10";
		       	    	   	   ipV4Hdr.SetDestination(Ipv4Address("10.1.7.10"));
		       	    	   	   break;

		       	    	   case(4):

		       	    		  //m_socket->Connect (InetSocketAddress (Ipv4Address("10.1.7.14"), 7001));
							ipV4Hdr.SetDestination(Ipv4Address("10.1.7.14"));
		       	    	   	   to = "10.1.7.14";
		       	    	   	   break;

		       	    	   default:
		       	    		   std::printf("Invalid node index");
		       	    		   break;


		       	    	   }
		       	    	Ptr<Packet> packetNew = Create<Packet>(buffer,packet->GetSize ());
		       	    	packetNew->AddHeader(udpHdr);
		       	    	packetNew->AddHeader(ipV4Hdr);
		       	    			       socket->SetAttribute ("IpHeaderInclude", BooleanValue (true));
		       	    			    if(!to.empty()){
		       	    			       socket->SendTo(packetNew,0,InetSocketAddress (Ipv4Address (to.c_str ()), 7001));
		       	    			       m_packetsSent++;
		       	    			    }
		       	       }



		       //m_Event= Simulator::Schedule (Simulator::Now (), &MyApp::sendMessage, packetNew,m_socket);
		       //txSocketn0->SetSendCallback (MakeBoundCallback (&SendMsg,packet));

		     }



}


char ** MyApp::giveParsingString(int msgType)
{


	if(msgType <=3)
	{
		const char *parseStr[] = {"int","int","float","float","end"};
		char **string =(char **)malloc(sizeof(*string)*5);
		for(int i=0;i<5;i++)
		{
			string[i] = (char *)malloc(sizeof(*string[i])*6);
			strcpy(string[i],parseStr[i]);
		}



		//std::printf("%s",*string);
		return string;

	}
	else
	{


		const char *parseStr[] = {"int","int","int","float","float","float","float","end"};
				char **string =(char **)malloc(sizeof(*string)*8);
				for(int i=0;i<8;i++)
				{
					string[i] = (char *)malloc(sizeof(*string[i])*6);
					strcpy(string[i],parseStr[i]);
					//std::printf("%s\n",string[i]);
				}


				//std::printf("%s",*string);
				return string;
	}




}








int
main (int argc, char *argv[])

{
	Time::SetResolution (Time::NS);

	PacketMetadata::Enable();
	Packet::EnablePrinting();
	//Packet::EnableChecking();


//	FlowMonitorHelper flowmon;
//	  Ptr<FlowMonitor> monitor;
//	  monitor = flowmon.InstallAll();

	  bool dosEnabled = false;
	  bool manInTheMiddle = false;
	  bool ArpSpoofEnabled =false;
	  double stopTime = 10;
	  uint32_t nNodes = 2;
	  MobilityHelper mobility;
	  mobility.SetMobilityModel("ns3::ConstantPositionMobilityModel");
	  //
	  // Allow the user to override any of the defaults at run-time, via command-line
	  // arguments
	  //
	  CommandLine cmd;
	  std::string deviceName ("eno1");
	  std::string encapMode ("Dix");

	  cmd.AddValue ("deviceName", "device name", deviceName);
	  cmd.AddValue ("stopTime", "stop time (seconds)", stopTime);
	  cmd.AddValue ("encapsulationMode", "encapsulation mode of emu device (\"Dix\" [default] or \"Llc\")", encapMode);
	  cmd.AddValue ("DoSEnabled", "DoS enabled", dosEnabled);
	  cmd.AddValue ("MiTmEnabled", "Man-in-the-middle enabled", manInTheMiddle);
	  cmd.AddValue ("ArpSpoofEnabled", "Arp Spoofing enabled", ArpSpoofEnabled);
	  //cmd.AddValue ("nNodes", "number of nodes to create (>= 2)", nNodes);

	  cmd.Parse (argc, argv);

	  GlobalValue::Bind ("SimulatorImplementationType",
	                     StringValue ("ns3::RealtimeSimulatorImpl"));

	  GlobalValue::Bind ("ChecksumEnabled", BooleanValue (true));
	  //GlobalValue::Bind ("RcvBufSize",  UintegerValue (1310));
	  NodeContainer Attackers;
	  Attackers.Create(4);
	  nNodes = 4;

	  //
	  // Explicitly create the nodes required by the topology (shown above).
	  //
	  NS_LOG_INFO ("Create nodes.");
	  NodeContainer n;
	  n.Create (nNodes);



//create the DERs, ingress, egress, and the aggregator nodes
	  NodeContainer DERs;
	  DERs.Create(4);
	  Ptr<Node> Aggregator = CreateObject<Node> ();
	  Ptr<Node> ingressNode = CreateObject<Node> ();
	  Ptr<Node> egressNode = CreateObject<Node> ();
	  //Ptr<Node> RTU = CreateObject<Node> ();
	  //Ptr<Node> DSO = CreateObject<Node> ();


	  mobility.Install(n);
	  mobility.Install(Aggregator);
	  mobility.Install(DERs);
	  mobility.Install(ingressNode);
	  mobility.Install(egressNode);
	  mobility.Install(Attackers);










      InternetStackHelper stack;
      stack.Install (n);
      stack.Install (DERs);
      stack.Install (Aggregator);
      stack.Install (ingressNode);
      stack.Install (egressNode);
      stack.Install (Attackers);

  //  stack.EnablePcapIpv4All("Tx");
  //  stack.EnablePcapIpv4All("Rx");
  //  stack.EnablePcapIpv4All("Dropped");
  //
  // Explicitly create the channels required by the topology (shown above).
    //




    NetDeviceContainer d0;
    NetDeviceContainer d1;
    Ipv4AddressHelper ipv4;
    Ipv4InterfaceContainer i0;
    Ipv4InterfaceContainer i1;
    Ipv4AddressHelper address;
    ApplicationContainer apps;
    NodeContainer IngressDER1 = NodeContainer (ingressNode, DERs.Get(0));
    NodeContainer IngressDER2 = NodeContainer (ingressNode, DERs.Get(1));
    NodeContainer IngressDER3 = NodeContainer (ingressNode, DERs.Get(2));
    NodeContainer IngressDER4 = NodeContainer (ingressNode, DERs.Get(3));
    NodeContainer IngressAggregator = NodeContainer (ingressNode, Aggregator);
    NodeContainer DERsn0Attacker = NodeContainer (Attackers.Get(0),n.Get (0), DERs);
    NodeContainer DER1n0 = NodeContainer (n.Get (0), DERs.Get(0));
    NodeContainer DER2n0 = NodeContainer (n.Get (0), DERs.Get(1));
    NodeContainer DER3n0 = NodeContainer (n.Get (0), DERs.Get(2));
    NodeContainer DER4n0 = NodeContainer (n.Get (0), DERs.Get(3));
    NodeContainer n0n1 = NodeContainer (n.Get (0), n.Get (1));
    NodeContainer n0n2 = NodeContainer (n.Get (0), n.Get (2));
    NodeContainer n1n3 = NodeContainer (n.Get (1), n.Get (3));
    NodeContainer n2n3 = NodeContainer (n.Get (2), n.Get (3));
    NodeContainer n3Aggregator = NodeContainer (n.Get (3), Aggregator);
    NodeContainer AggregatorEgress = NodeContainer (Aggregator,egressNode);
    NodeContainer DER1Egress = NodeContainer (DERs.Get(0),egressNode);
    NodeContainer DER2Egress = NodeContainer (DERs.Get(1),egressNode);
    NodeContainer DER3Egress = NodeContainer (DERs.Get(2),egressNode);
    NodeContainer DER4Egress = NodeContainer (DERs.Get(3),egressNode);
    NodeContainer n2Attacker1 = NodeContainer (n.Get (2), Attackers.Get(0));
    NodeContainer n2Attacker2 = NodeContainer (n.Get (2), Attackers.Get(1));
    NodeContainer n2Attacker3 = NodeContainer (n.Get (2), Attackers.Get(2));
    NodeContainer n2Attacker4 = NodeContainer (n.Get (2), Attackers.Get(3));

    //connection between the Router1 and the attackers



    //********************Setup connections between nodes **********************************************

    NS_LOG_INFO ("Create links.");

    // We create the channels first without any IP addressing information
      NS_LOG_INFO ("Create channels.");
      PointToPointHelper p2p;
      p2p.SetDeviceAttribute ("DataRate", StringValue ("1000Mbps"));
      p2p.SetChannelAttribute ("Delay",  TimeValue (NanoSeconds (656)));
      PointerValue ptr;

      NetDeviceContainer d0d1 = p2p.Install (n0n1);
      d0d1.Get(0)->GetAttribute ("TxQueue", ptr);
      Ptr<Queue<Packet> > txQueuen0 = ptr.Get<Queue<Packet> > ();
      txQueuen0->SetMaxSize( QueueSize (QueueSizeUnit::PACKETS, 10));
      d0d1.Get(1)->GetAttribute ("TxQueue", ptr);
            Ptr<Queue<Packet> > txQueuen1 = ptr.Get<Queue<Packet> > ();
            txQueuen1->SetMaxSize( QueueSize (QueueSizeUnit::PACKETS, 10));
      TrafficControlHelper tch;
                tch.SetRootQueueDisc ("ns3::FifoQueueDisc",
                                      "MaxSize",  QueueSizeValue (QueueSize ("10p")));

//      tch.SetRootQueueDisc ("ns3::TbfQueueDisc",
//                                       "Burst", UintegerValue (10000),
//                                       "Mtu", UintegerValue (1500),
//                                       "Rate", DataRateValue (DataRate (DataRate ("100Mbps"))),
//                                       "PeakRate", DataRateValue (DataRate (DataRate ("1000Mbps"))));
               QueueDiscContainer qdiscs = tch.Install (d0d1);



      NetDeviceContainer d0d2 = p2p.Install (n0n2);

      //p2p.SetDeviceAttribute ("DataRate", StringValue ("10Mbps"));
      //p2p.SetChannelAttribute ("Delay", StringValue ("10ms"));
      NetDeviceContainer d1d3 = p2p.Install (n1n3);
      d1d3.Get(0)->GetAttribute ("TxQueue", ptr);
                  Ptr<Queue<Packet> > txQueuen12 = ptr.Get<Queue<Packet> > ();
                  txQueuen12->SetMaxSize( QueueSize (QueueSizeUnit::PACKETS, 10));
                  d1d3.Get(1)->GetAttribute ("TxQueue", ptr);
                                    Ptr<Queue<Packet> > txQueuen3 = ptr.Get<Queue<Packet> > ();
                                    txQueuen3->SetMaxSize( QueueSize (QueueSizeUnit::PACKETS, 10));
       tch.Install (d1d3);


      //p2p.SetChannelAttribute ("DataRate", StringValue ("50Mbps"));
      //p2p.SetChannelAttribute ("Delay", StringValue ("2ms"));
      NetDeviceContainer d2d3 = p2p.Install (n2n3);
      d2d3.Get(0)->GetAttribute ("TxQueue", ptr);
                        Ptr<Queue<Packet> > txQueuend2d31 = ptr.Get<Queue<Packet> > ();
                        txQueuend2d31 ->SetMaxSize( QueueSize (QueueSizeUnit::PACKETS, 10));
                        d2d3.Get(1)->GetAttribute ("TxQueue", ptr);
                                          Ptr<Queue<Packet> > txQueuend2d32 = ptr.Get<Queue<Packet> > ();
                                          txQueuend2d32->SetMaxSize( QueueSize (QueueSizeUnit::PACKETS, 10));
      tch.Install (d2d3);

      //p2p connections for attacker nodes
//      NetDeviceContainer NetDevn2Attacker1 = p2p.Install (n2Attacker1);
//      tch.Install (NetDevn2Attacker1);
//      NetDeviceContainer NetDevn2Attacker2 = p2p.Install (n2Attacker2);
//      NetDeviceContainer NetDevn2Attacker3 = p2p.Install (n2Attacker3);
//      NetDeviceContainer NetDevn2Attacker4 = p2p.Install (n2Attacker4);


      // Later, we add IP addresses.
       NS_LOG_INFO ("Assign IP Addresses.");

       ipv4.SetBase ("10.1.1.0", "255.255.255.252");
       ipv4.Assign (d0d1);

       ipv4.SetBase ("10.1.2.0", "255.255.255.252");
       ipv4.Assign (d1d3);

       ipv4.SetBase ("10.1.3.0", "255.255.255.252");
       ipv4.Assign (d2d3);

       ipv4.SetBase ("10.1.5.0", "255.255.255.252");
       ipv4.Assign (d0d2);


       //IP addresses for Attacker nodes
//       ipv4.SetBase ("10.1.5.4", "255.255.255.252");
//       ipv4.Assign (NetDevn2Attacker1);
//       ipv4.SetBase ("10.1.5.8", "255.255.255.252");
//       ipv4.Assign (NetDevn2Attacker2);
//       ipv4.SetBase ("10.1.5.12", "255.255.255.252");
//       ipv4.Assign (NetDevn2Attacker3);
//       ipv4.SetBase ("10.1.5.16", "255.255.255.252");
//       ipv4.Assign (NetDevn2Attacker4);

       // Create router nodes, initialize routing database and set up the routing
       // tables in the nodes.


   //setting up ingress node to communicate with the GTNET
       EmuFdNetDeviceHelper emu;
           emu.SetDeviceName (deviceName);
           emu.SetAttribute ("EncapsulationMode", StringValue (encapMode));


       address.SetBase ("172.24.0.0", "255.255.0.0", "0.0.2.55");
       d0 = emu.Install (ingressNode);
       Ptr<FdNetDevice> dev = d0.Get (0)->GetObject<FdNetDevice> ();
       dev->SetAddress (Mac48Address ("64:00:6a:5c:af:58"));
       NS_LOG_INFO ("Assign IP Address of EMU interface.");
       i0 = address.Assign (d0); //IP address for node n0 with emulation
       dev->Initialize();

       //tch.Install (dev);

       //connect DERs and Aggregator to the Ingress node using p2p links

       PointToPointHelper p2pDERIngress;
       p2pDERIngress.SetDeviceAttribute ("DataRate", StringValue ("1000Mbps"));
       p2pDERIngress.SetChannelAttribute ("Delay", TimeValue (NanoSeconds (600)));
       NetDeviceContainer NetDevIngressDER1 = p2pDERIngress.Install (IngressDER1);
       address.SetBase ("10.1.6.0", "255.255.255.252"); //ingress-Int2->DER1_Int1  10.1.6.1->10.1.6.2
       address.Assign (NetDevIngressDER1);
       //tch.Install (NetDevIngressDER1);
       // tch.Install (NetDevIngressDER1.Get(1));

       NetDeviceContainer NetDevIngressDER2 = p2pDERIngress.Install (IngressDER2);
       ipv4.SetBase ("10.1.6.4", "255.255.255.252"); //ingress-Int3->DER2_Int1  10.1.6.5->10.1.6.6
       ipv4.Assign (NetDevIngressDER2);
//        tch.Install (NetDevIngressDER2.Get(1));

       NetDeviceContainer NetDevIngressDER3 = p2pDERIngress.Install (IngressDER3);
       ipv4.SetBase ("10.1.6.8", "255.255.255.252"); //ingress-Int4->DER3_Int1  10.1.6.9->10.1.6.10
       ipv4.Assign (NetDevIngressDER3);
       // tch.Install (NetDevIngressDER3.Get(1));

       NetDeviceContainer NetDevIngressDER4 = p2pDERIngress.Install (IngressDER4);
       ipv4.SetBase ("10.1.6.12", "255.255.255.252"); //ingress-Int5->DER4_Int1  10.1.6.13->10.1.6.14
       ipv4.Assign (NetDevIngressDER4);
       // tch.Install (NetDevIngressDER4.Get(1));

//       NetDeviceContainer NetDevIngressAggregator = p2pDERIngress.Install (IngressAggregator);
//       ipv4.SetBase ("10.1.6.16", "255.255.255.252"); //ingress-Int6->Aggregator_Int1  10.1.6.17->10.1.6.18
//       ipv4.Assign (NetDevIngressAggregator);

//       //connect DERs to n0 (CSMA switch) node using CSMA
       CsmaHelper csma;
       csma.SetChannelAttribute ("DataRate", StringValue ("1000Mbps"));
       csma.SetChannelAttribute ("Delay", TimeValue (NanoSeconds (6560)));

       csma.SetDeviceAttribute ("EncapsulationMode", StringValue ("Dix"));

       NetDeviceContainer csmaDERsn0 = csma.Install (DERsn0Attacker); //installing the CSMA netdevice on n0 and DERs
       ipv4.SetBase ("10.1.7.0", "255.255.255.248"); //n0-Int3->DERs-int2 10.1.7.1->{10.1.7.2-10.1.7.5)+10.1.7.6(Attacker)

       Ipv4InterfaceContainer csmaInterfaces;
         csmaInterfaces = ipv4.Assign (csmaDERsn0);
         std::stringstream macAddr;
         uint32_t attackerId = 0;
         uint32_t victimDer = 2;
         uint32_t csmaSwitch = 1;
         Address victimAddr;
         for( uint32_t i = 0; i <  DERsn0Attacker.GetN(); i++ )
           {
             macAddr << "00:00:00:00:00:0" << i;
             Ptr<NetDevice> nd = csmaDERsn0.Get (i);
             Ptr<CsmaNetDevice> cd = nd->GetObject<CsmaNetDevice> ();
             cd->SetAddress(ns3::Mac48Address(macAddr.str().c_str()));
             // take a copy of victim addr
             if(i == victimDer)
               victimAddr = cd->GetAddress();
             std::cout << macAddr.str()<<std::endl;
             macAddr.str(std::string());
           }

       //Connect DERs to n2 using p2p

//       NetDeviceContainer NetDevDER1n0 = p2pDERIngress.Install (DER1n0);
//       ipv4.SetBase ("10.1.7.0", "255.255.255.252"); //n0-Int3->DER1_Int2  10.1.7.1->10.1.7.2
//       ipv4.Assign (NetDevDER1n0);
//
//       NetDeviceContainer NetDevDER2n0 = p2pDERIngress.Install (DER2n0);
//       ipv4.SetBase ("10.1.7.4", "255.255.255.252"); //n0-Int4->DER2_Int2  10.1.7.5->10.1.7.6
//       ipv4.Assign (NetDevDER2n0);
//
//       NetDeviceContainer NetDevDER3n0 = p2pDERIngress.Install (DER3n0);
//       ipv4.SetBase ("10.1.7.8", "255.255.255.252"); //n0-Int5->DER3_Int2  10.1.7.9->10.1.7.10
//       ipv4.Assign (NetDevDER3n0);
//
//       NetDeviceContainer NetDevDER4n0 = p2pDERIngress.Install (DER4n0);
//       ipv4.SetBase ("10.1.7.12", "255.255.255.252"); //n0-Int6->DER4_Int2  10.1.7.13->10.1.7.14
//       ipv4.Assign (NetDevDER4n0);







       //connect n3 to aggregator
       NetDeviceContainer NetDevn3Aggregator = p2pDERIngress.Install (n3Aggregator);
       ipv4.SetBase ("10.1.8.0", "255.255.255.252"); //n3-Int2->Aggregator_Int2  10.1.8.1->10.1.8.2
       ipv4.Assign (NetDevn3Aggregator);
       NetDevn3Aggregator.Get(0)->GetAttribute ("TxQueue", ptr);
                        Ptr<Queue<Packet> >NetDevn3Aggregatorn3 = ptr.Get<Queue<Packet> > ();
                        NetDevn3Aggregatorn3->SetMaxSize( QueueSize (QueueSizeUnit::PACKETS, 10));
                        NetDevn3Aggregator.Get(1)->GetAttribute ("TxQueue", ptr);
                                          Ptr<Queue<Packet> > NetDevn3AggregatorAgg = ptr.Get<Queue<Packet> > ();
                                          NetDevn3AggregatorAgg ->SetMaxSize( QueueSize (QueueSizeUnit::PACKETS, 10));

       //connect aggregator and DERs to egress interface
        NetDeviceContainer NetDevAggregatorEgress = p2pDERIngress.Install (AggregatorEgress);
        ipv4.SetBase ("10.1.8.4", "255.255.255.252"); //Aggregator-Int3->Egress_Int1  10.1.8.5->10.1.8.6
        ipv4.Assign (NetDevAggregatorEgress);
        //tch.Install (NetDevAggregatorEgress.Get(1));

//        NetDeviceContainer NetDevDER1Egress = p2pDERIngress.Install (DER1Egress);
//        ipv4.SetBase ("10.1.8.8", "255.255.255.252"); //DER1-Int3->Egress_Int2  10.1.8.9->10.1.8.10
//        ipv4.Assign (NetDevDER1Egress);
//
//        NetDeviceContainer NetDevDER2Egress = p2pDERIngress.Install (DER2Egress);
//        ipv4.SetBase ("10.1.8.12", "255.255.255.252"); //DER2-Int3->Egress_Int3  10.1.8.13->10.1.8.14
//        ipv4.Assign (NetDevDER2Egress);
//
//        NetDeviceContainer NetDevDER3Egress = p2pDERIngress.Install (DER3Egress);
//        ipv4.SetBase ("10.1.8.16", "255.255.255.252"); //DER2-Int3->Egress_Int4  10.1.8.17->10.1.8.18
//        ipv4.Assign (NetDevDER3Egress);
//
//        NetDeviceContainer NetDevDER4Egress = p2pDERIngress.Install (DER4Egress);
//        ipv4.SetBase ("10.1.8.20", "255.255.255.252"); //DER4-Int3->Egress_Int5  10.1.8.21->10.1.8.22
//        ipv4.Assign (NetDevDER4Egress);

        //Second Emulated interface Egress node
             std::string device2Name ("enp0s20u6"); //edit the name corresponding to the device name
             std::string encapMode2 ("Dix");
             EmuFdNetDeviceHelper emu2;
             emu2.SetDeviceName (device2Name);
             emu2.SetAttribute ("EncapsulationMode", StringValue (encapMode2));

             ipv4.SetBase ("172.24.0.0", "255.255.0.0", "0.0.2.144");
             d1 = emu2.Install (egressNode);


             Ptr<FdNetDevice> dev1 = d1.Get (0)->GetObject<FdNetDevice> ();
             //tch.Install (dev1);
             dev1->SetAddress (Mac48Address ("9c:eb:e8:b2:8e:c8"));
             NS_LOG_INFO ("Assign IP Address of EMU interface2.");
             i1 = ipv4.Assign (d1); //IP address for node n3 with emulation
             dev1->Initialize();




  //********************Setup routing**********************************************
             NS_LOG_INFO ("Setup routing");
       Ipv4StaticRoutingHelper ipv4RoutingHelper;
//       Ptr<SocketFactory> rxSocketFactory = n.Get (0)->GetObject<UdpSocketFactory> ();
//       Ptr<Socket> rxSocketn0 = rxSocketFactory->CreateSocket ();
//       rxSocketn0->Bind (InetSocketAddress (Ipv4Address ("172.24.2.55"), 4888));


       //rxSocketn0->SetRecvCallback (MakeBoundCallback (&PrintTraffic ,&n));

       //set routing
       Ptr<Ipv4> ipv4ingressNode = ingressNode->GetObject<Ipv4>();
       Ptr<Ipv4StaticRouting> staticRoutingIngressNode = ipv4RoutingHelper.GetStaticRouting (ipv4ingressNode);
       // The ifIndex for this outbound route is 1; the first p2p link added

       staticRoutingIngressNode->SetDefaultRoute(Ipv4Address("172.24.0.1"),1,0); //only for testing interface is one because emulation was the first device installed


       //intermediate node that relays traffic from node 0 to node 3
       Ptr<Ipv4> ipv4n0 = n.Get(0)->GetObject<Ipv4>();
       Ptr<Ipv4StaticRouting> staticRouting_n0= ipv4RoutingHelper.GetStaticRouting (ipv4n0);
       // The ifIndex for this outbound route is 1; the first p2p link added

       staticRouting_n0->SetDefaultRoute(Ipv4Address("10.1.1.2"),1,0);

       Ptr<Ipv4> ipv4n1 = n.Get(1)->GetObject<Ipv4>();
             Ptr<Ipv4StaticRouting> staticRouting_n1= ipv4RoutingHelper.GetStaticRouting (ipv4n1);
             // The ifIndex for this outbound route is 1; the first p2p link added

             staticRouting_n1->SetDefaultRoute(Ipv4Address("10.1.2.2"),2,0);

             Ptr<Ipv4> ipv4n3 = n.Get(3)->GetObject<Ipv4>();
                         Ptr<Ipv4StaticRouting> staticRouting_n3= ipv4RoutingHelper.GetStaticRouting (ipv4n3);
                         // The ifIndex for this outbound route is 1; the first p2p link added
                         staticRouting_n3->SetDefaultRoute(Ipv4Address("10.1.8.2"),3,0);
                         //staticRouting_n3->SetDefaultRoute(Ipv4Address("10.1.8.2"),2,0);



       //DER route for 10.1.8.5
       Ptr<Ipv4> ipv4DER1 = DERs.Get(0)->GetObject<Ipv4>();
       Ptr<Ipv4StaticRouting> staticRouting_DER1= ipv4RoutingHelper.GetStaticRouting (ipv4DER1);
       staticRouting_DER1->AddHostRouteTo (Ipv4Address ("10.1.8.5"), Ipv4Address ("10.1.7.2"), 2);



       Ptr<Ipv4> ipv4DER2 = DERs.Get(1)->GetObject<Ipv4>();
       Ptr<Ipv4StaticRouting> staticRouting_DER2= ipv4RoutingHelper.GetStaticRouting (ipv4DER2);
       staticRouting_DER2->AddHostRouteTo (Ipv4Address ("10.1.8.5"), Ipv4Address ("10.1.7.2"), 2);

       Ptr<Ipv4> ipv4DER3 = DERs.Get(2)->GetObject<Ipv4>();
       Ptr<Ipv4StaticRouting> staticRouting_DER3= ipv4RoutingHelper.GetStaticRouting (ipv4DER3);
       staticRouting_DER3->AddHostRouteTo (Ipv4Address ("10.1.8.5"), Ipv4Address ("10.1.7.2"), 2);

       Ptr<Ipv4> ipv4DER4 = DERs.Get(3)->GetObject<Ipv4>();
       Ptr<Ipv4StaticRouting> staticRouting_DER4= ipv4RoutingHelper.GetStaticRouting (ipv4DER4);
       staticRouting_DER4->AddHostRouteTo (Ipv4Address ("10.1.8.5"), Ipv4Address ("10.1.7.2"), 2);

       //DER route for 10.1.8.6

//              staticRouting_DER1->AddHostRouteTo (Ipv4Address ("10.1.8.6"), Ipv4Address ("10.1.8.10"), 3);
//
//
//
//              staticRouting_DER2->AddHostRouteTo (Ipv4Address ("10.1.8.6"), Ipv4Address ("10.1.8.14"), 3);
//
//
//              staticRouting_DER3->AddHostRouteTo (Ipv4Address ("10.1.8.6"), Ipv4Address ("10.1.8.18"), 3);
//
//
//              staticRouting_DER4->AddHostRouteTo (Ipv4Address ("10.1.8.6"), Ipv4Address ("10.1.8.22"), 3);
//


       Ptr<Ipv4> ipv4Aggregator = Aggregator->GetObject<Ipv4>();
              Ptr<Ipv4StaticRouting> staticRouting_Aggregator= ipv4RoutingHelper.GetStaticRouting (ipv4Aggregator);
              staticRouting_Aggregator->AddHostRouteTo (Ipv4Address ("10.1.7.2"), Ipv4Address ("10.1.8.1"), 2);
              staticRouting_Aggregator->AddHostRouteTo (Ipv4Address ("10.1.7.6"), Ipv4Address ("10.1.8.1"), 2);
              staticRouting_Aggregator->AddHostRouteTo (Ipv4Address ("10.1.7.10"), Ipv4Address ("10.1.8.1"), 2);
              staticRouting_Aggregator->AddHostRouteTo (Ipv4Address ("10.1.7.14"), Ipv4Address ("10.1.8.1"), 2);
              staticRouting_Aggregator->AddHostRouteTo (Ipv4Address ("172.24.2.144"), Ipv4Address ("10.1.8.6"), 2);


       Ptr<Ipv4> ipv4_egressNode = egressNode->GetObject<Ipv4>();

         Ptr<Ipv4StaticRouting> staticRouting_egressNode = ipv4RoutingHelper.GetStaticRouting (ipv4_egressNode);
          // The ifIndex for this outbound route is 1; the first p2p link added

         staticRouting_egressNode->SetDefaultRoute(Ipv4Address ("172.24.0.1"),2,0);
         //staticRouting_egressNode->SetDefaultRoute(Ipv4Address ("172.24.0.1"),1,0);

         Ptr<Ipv4> ipv4_ingressNode = ingressNode->GetObject<Ipv4>();
         std::cout<<"Routing protocol"<<endl;
         Ptr<OutputStreamWrapper> routingStream = Create<OutputStreamWrapper> (&std::cout);

//         Ptr<Ipv4StaticRouting> staticRouting_ingressNode = ipv4RoutingHelper.GetStaticRouting (ipv4_ingressNode);
//         staticRouting_ingressNode->AddHostRouteTo (Ipv4Address ("10.1.6.2"), Ipv4Address ("10.1.6.1"), 2);
//         staticRouting_ingressNode->AddHostRouteTo (Ipv4Address ("10.1.6.6"), Ipv4Address ("10.1.6.5"), 3);
//         staticRouting_ingressNode->AddHostRouteTo (Ipv4Address ("10.1.6.10"), Ipv4Address ("10.1.6.9"), 4);
//         staticRouting_ingressNode->AddHostRouteTo (Ipv4Address ("10.1.6.14"), Ipv4Address ("10.1.6.13"), 5);
         ipv4_ingressNode->GetRoutingProtocol()->PrintRoutingTable(routingStream);


            Ipv4GlobalRoutingHelper::PopulateRoutingTables ();
          //Print Routin Table

//          Ptr<OutputStreamWrapper> routingStream = Create<OutputStreamWrapper> (&std::cout);
          //ipv4RoutingHelper.PrintRoutingTableAt(Seconds(10), DERs.Get (0), routingStream);
          ipv4RoutingHelper.PrintRoutingTableAt(Seconds(100), DERs.Get(0), routingStream);
       // rxSocket2->SetRecvCallback (MakeCallback (&SocketPrinter) );
       //PrintTraffic ( &n, rxSocketn0);


//**********************Application Layer**************************************************
          NS_LOG_INFO ("Setup applications.");
          //print the transformer overload time using tcp

//                  Ptr<MyApp> appTcp= CreateObject<MyApp> ();
//                  appTcp->Setup (ingressNode,Ipv4Address ("172.24.2.55"),Ipv4Address ("10.1.8.5"), 10000,10000,6);
//                  ingressNode->AddApplication (appTcp);
//                  appTcp->SetStartTime (Seconds (1.));
//                  appTcp->SetStopTime (Seconds (stopTime));

          // get IPV4 interface for the attacker
          std::pair<Ptr<Ipv4>, uint32_t> returnValue = csmaInterfaces.Get (attackerId);
          Ptr<Ipv4> ipv4Val = returnValue.first;
          uint32_t index = returnValue.second;
          Ptr<Ipv4Interface> iface =  ipv4Val->GetObject<Ipv4L3Protocol> ()->GetInterface (index);

          std::pair<Ptr<Ipv4>, uint32_t> returnValue2 = csmaInterfaces.Get (victimDer);
           Ptr<Ipv4> ipv4Val2 = returnValue.first;
           uint32_t index2 = returnValue.second;
           Ptr<Ipv4Interface> iface2 =  ipv4Val2->GetObject<Ipv4L3Protocol> ()->GetInterface (index2);


          if(ArpSpoofEnabled){
          //contruct attacker app
          Ptr<AttackApp> attacker = CreateObject<AttackApp> ();
          attacker->Setup(DERsn0Attacker.Get(attackerId), csmaDERsn0.Get(attackerId), iface, csmaInterfaces.GetAddress(csmaSwitch), csmaInterfaces.GetAddress(victimDer), victimAddr);
          DERsn0Attacker.Get (attackerId)->AddApplication (attacker);
          attacker->SetStartTime (Seconds (1.0));
          attacker->SetStopTime (Seconds (200.0));
          }


       //ingress interface

       Ptr<MyApp> app = CreateObject<MyApp> ();
       app->Setup (ingressNode,Ipv4Address ("172.24.2.55"),Ipv4Address ("10.1.8.6"), 7001,7001,INGRESS_NODE);
       ingressNode->AddApplication (app);
       app->SetStartTime (Seconds (1.));
       app->SetStopTime (Seconds (stopTime));




       //DERs application layer for the interface connecting to the ingress interface

       Ptr<MyApp> appDER1Extern = CreateObject<MyApp> ();
       appDER1Extern->Setup (DERs.Get(0),Ipv4Address ("10.1.6.2"),Ipv4Address ("172.24.2.144"), 7001,7001,FORWARDING_NODE);
       DERs.Get(0)->AddApplication (appDER1Extern);
       appDER1Extern->SetStartTime (Seconds (1.));
       appDER1Extern->SetStopTime (Seconds (stopTime));

       Ptr<MyApp> appDER2Extern = CreateObject<MyApp> ();
       appDER2Extern->Setup (DERs.Get(1),Ipv4Address ("10.1.6.6"),Ipv4Address ("172.24.2.144"), 7001,7001,FORWARDING_NODE);
       DERs.Get(1)->AddApplication (appDER2Extern);
       appDER2Extern->SetStartTime (Seconds (1.));
       appDER2Extern->SetStopTime (Seconds (stopTime));

       Ptr<MyApp> appDER3Extern = CreateObject<MyApp> ();
       appDER3Extern->Setup (DERs.Get(2),Ipv4Address ("10.1.6.10"),Ipv4Address ("172.24.2.144"), 7001,7001,FORWARDING_NODE);
       DERs.Get(2)->AddApplication (appDER3Extern);
       appDER3Extern->SetStartTime (Seconds (1.));
       appDER3Extern->SetStopTime (Seconds (stopTime));

       Ptr<MyApp> appDER4Extern = CreateObject<MyApp> ();
       appDER4Extern->Setup (DERs.Get(3),Ipv4Address ("10.1.6.14"),Ipv4Address ("172.24.2.144"), 7001,7001,FORWARDING_NODE);
       DERs.Get(3)->AddApplication (appDER4Extern);
       appDER4Extern->SetStartTime (Seconds (1.));
       appDER4Extern->SetStopTime (Seconds (stopTime));

//       Ptr<MyApp> appAggregatorExtern = CreateObject<MyApp> ();
//       appAggregatorExtern->Setup (Aggregator,Ipv4Address ("10.1.6.18"),Ipv4Address ("10.1.8.5"), 7001,7001,AGGREGATOR_NODE);
//       Aggregator->AddApplication (appAggregatorExtern);
//       appAggregatorExtern->SetStartTime (Seconds (1.));
//       appAggregatorExtern->SetStopTime (Seconds (stopTime));


       UdpServerHelper server (7001);
                  ApplicationContainer appsAgg = server.Install (Aggregator);
                  appsAgg.Start (Seconds (1.0));
                  appsAgg.Stop (Seconds (10.0));


//       Ptr<MyApp> appAggregatorIntern = CreateObject<MyApp> ();
//       appAggregatorIntern->Setup (Aggregator,Ipv4Address ("10.1.8.5"),Ipv4Address ("10.1.8.6"), 7001,7001,MAN_IN_MIDDLE_NODE);
//              Aggregator->AddApplication (appAggregatorIntern);
//              appAggregatorIntern->SetStartTime (Seconds (1.));
//              appAggregatorIntern->SetStopTime (Seconds (stopTime));

//       Ptr<MyApp> appDER1Intern = CreateObject<MyApp> ();
//       appDER1Intern->Setup (DERs.Get(0),Ipv4Address ("10.1.7.2"),Ipv4Address ("10.1.8.6"), 7001,7001,MAN_IN_MIDDLE_NODE);
//       DERs.Get(0)->AddApplication (appDER1Intern);
//       appDER1Intern->SetStartTime (Seconds (1.));
//       appDER1Intern->SetStopTime (Seconds (stopTime));
//
//       Ptr<MyApp> appDER2Intern = CreateObject<MyApp> ();
//       appDER2Intern->Setup (DERs.Get(1),Ipv4Address ("10.1.7.6"),Ipv4Address ("10.1.8.6"), 7001,7001,MAN_IN_MIDDLE_NODE);
//       DERs.Get(1)->AddApplication (appDER2Intern);
//       appDER2Intern->SetStartTime (Seconds (1.));
//       appDER2Intern->SetStopTime (Seconds (stopTime));
//
//       Ptr<MyApp> appDER3Intern = CreateObject<MyApp> ();
//       appDER3Intern->Setup (DERs.Get(2),Ipv4Address ("10.1.7.10"),Ipv4Address ("10.1.8.6"), 7001,7001,MAN_IN_MIDDLE_NODE);
//       DERs.Get(2)->AddApplication (appDER3Intern);
//       appDER3Intern->SetStartTime (Seconds (1.));
//       appDER3Intern->SetStopTime (Seconds (stopTime));
//
//       Ptr<MyApp> appDER4Intern = CreateObject<MyApp> ();
//       appDER4Intern->Setup (DERs.Get(3),Ipv4Address ("10.1.7.14"),Ipv4Address ("10.1.8.6"), 7001,7001,MAN_IN_MIDDLE_NODE);
//       DERs.Get(3)->AddApplication (appDER4Intern);
//       appDER4Intern->SetStartTime (Seconds (1.));
//       appDER4Intern->SetStopTime (Seconds (stopTime));




       //Attacker Node to generate DoS traffic towards node0
if (dosEnabled){
	NS_LOG_INFO ("Enable DoS");
    uint16_t port = 7001;   // Discard port (RFC 863)
      OnOffHelper onoff ("ns3::UdpSocketFactory",
      Address (InetSocketAddress (Ipv4Address ("172.24.2.144"), port)));
      onoff.SetConstantRate (DataRate ("50Mbps"));
       //onoff.SetAttribute("OnTime", StringValue("ns3::ConstantRandomVariable[Constant=" + ON_TIME + "]"));
         //onoff.SetAttribute("OffTime", StringValue("ns3::ConstantRandomVariable[Constant=" + OFF_TIME + "]"));
       ApplicationContainer onOffapps = onoff.Install (n.Get(2));
      onOffapps.Start (Seconds (20.0));
       onOffapps.Stop (Seconds (50.0));

}





//Setting up the egress node

       Ptr<MyApp> app2 = CreateObject<MyApp> ();
               app2->Setup (egressNode,Ipv4Address ("172.24.2.144"),Ipv4Address ("172.24.9.240"), 7001,7001,EGRESS_NODE);
               egressNode->AddApplication (app2);
               app2->SetStartTime (Seconds (1.));
               app2->SetStopTime (Seconds (stopTime));



              // Create static routes from A to C


//              ipv4RoutingHelper.PrintRoutingTableAt(Seconds(10), n.Get (1), routingStream);
//              ipv4RoutingHelper.PrintRoutingTableAt(Seconds(10), n.Get (3), routingStream);

  //device 0 is sta and device 1 is ap

  /*PacketSinkHelper packetSinkHelper ("ns3::UdpSocketFactory", InetSocketAddress (Ipv4Address::GetAny (), 8080));
  ApplicationContainer sinkApps = packetSinkHelper.Install (n.Get (0));
  sinkApps.Start (Seconds (0.));
  sinkApps.Stop (Seconds (20.));

  PacketSinkHelper packetSinkHelper2 ("ns3::UdpSocketFactory", InetSocketAddress (Ipv4Address::GetAny (), 8085));
  ApplicationContainer sinkApps2 = packetSinkHelper2.Install (nodes.Get (1));
  sinkApps2.Start (Seconds (0.));
  sinkApps2.Stop (Seconds (20.));

  Ptr<MyApp> app = CreateObject<MyApp> ();
  app->Setup (n.Get(1),InetSocketAddress (i1.GetAddress (1), 8085),InetSocketAddress (interfaces.GetAddress (0), 49153), 1040, 5, DataRate ("1Mbps"));
  n.Get (1)->AddApplication (app);
  app->SetStartTime (Seconds (1.));
  app->SetStopTime (Seconds (20.));

  Ptr<MyApp> app2 = CreateObject<MyApp> ();
  app2->Setup (nodes.Get(0),InetSocketAddress (interfaces.GetAddress (0),8080), InetSocketAddress (interfaces.GetAddress (1), 49153), 1040, 5, DataRate ("1Mbps"));
  nodes.Get (0)->AddApplication (app2);
  app2->SetStartTime (Seconds (1.));
  app2->SetStopTime (Seconds (20.));*/
//
  AnimationInterface anim("rtds-dos-sim2.xml");
  anim.EnablePacketMetadata (true);
  anim.SetConstantPosition (n.Get (0), 10 , 10);

  	  anim.UpdateNodeDescription(n.Get (0),"CSMA");
  	anim.UpdateNodeDescription(n.Get (1),"Router1");
  	anim.UpdateNodeDescription(n.Get (2),"Router2");
  	anim.UpdateNodeDescription(n.Get (3),"Router3");
  	anim.UpdateNodeImage (3, anim.AddResource ("/home/rtds-cybersec/repos/ns-3-allinone/netanim/attacker.png") );
  	  	anim.UpdateNodeSize (3, 2.0,2.0 );
  	anim.UpdateNodeImage (4, anim.AddResource ("/home/rtds-cybersec/repos/ns-3-allinone/netanim/switch.png") );
  	anim.UpdateNodeSize (4, 2.0,2.0 );
  	anim.SetConstantPosition (n.Get (1), 15 , 10);
  	anim.UpdateNodeImage (5, anim.AddResource ("/home/rtds-cybersec/repos/ns-3-allinone/netanim/router.png") );
  	anim.UpdateNodeSize (5, 2.0,2.0 );
  	anim.SetConstantPosition (n.Get (2), 10 , 15);
  	anim.UpdateNodeImage (6, anim.AddResource ("/home/rtds-cybersec/repos/ns-3-allinone/netanim/router.png") );
  	anim.UpdateNodeSize (6, 2.0,2.0 );
  	anim.SetConstantPosition (n.Get (3), 15 , 20);
  	anim.UpdateNodeImage (7, anim.AddResource ("/home/rtds-cybersec/repos/ns-3-allinone/netanim/router.png") );
  	anim.UpdateNodeSize (7, 2.0,2.0 );

  	anim.SetConstantPosition (DERs.Get (0), 5 , 0);
  	anim.UpdateNodeDescription(DERs.Get (0),"DER1");
  	anim.SetConstantPosition (DERs.Get (1), 5 , 5);
  	  	anim.UpdateNodeDescription(DERs.Get (1),"DER2");
  	  anim.SetConstantPosition (DERs.Get (2), 5 , 10);
  	  	anim.UpdateNodeDescription(DERs.Get (2),"DER3");
  	  anim.SetConstantPosition (DERs.Get (3), 5 , 15);
  	  	anim.UpdateNodeDescription(DERs.Get (3),"DER4");



  	  anim.SetConstantPosition (ingressNode, 0 , 25);
  	  anim.UpdateNodeDescription(ingressNode,"ingressNode");
  	anim.SetConstantPosition (egressNode, 25 , 25);
  	  		  anim.UpdateNodeDescription(egressNode,"egressNode");
  	  		anim.SetConstantPosition (Aggregator, 20 , 25);
  	  		  anim.UpdateNodeDescription(Aggregator,"Aggregator");
  anim.SetStartTime (Seconds(1.0));
  anim.SetStopTime (Seconds(stopTime));


emu.EnablePcapAll ("rtds-dos-sim-1", true);
p2pDERIngress.EnablePcapAll("rtds-dos-sim-Aggre", false);
//  emu.EnableAsciiAll ("rtds-dos-sim-1.tr");
 emu2.EnablePcapAll ("rtds-dos-sim-2", true);
//    emu2.EnableAsciiAll ("frtds-dos-sim-2.tr");

  Simulator::Stop (Seconds (stopTime+2));
  Simulator::Run ();
  Simulator::Destroy ();

  return 0;
}

