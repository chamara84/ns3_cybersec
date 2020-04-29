/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * Copyright (c) 2012 University of Washington, 2012 INRIA 
 * Copyright (c) 2019 RTDS Technologies Inc.
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

// Network topology
//
// Packets sent to the device "tap0" on the Linux host will be sent to the
// tap bridge on node zero and then emitted onto the ns-3 simulated CSMA
// network.  ARP will be used on the CSMA network to resolve MAC addresses.
// Packets destined for the CSMA device on node zero will be sent to the
// device "tap0" on the linux Host.
//
//  +----------+
//  | external |
//  |  Linux   |
//  |   Host   |
//  |          |
//  | "tap0" |
//  +----------+
//       |           n0            n1            n2            n3
//       |       +--------+    +--------+    +--------+    +--------+
//       +-------|  tap   |    | Tcp    |    |        |    |        |
//               | bridge |    | Server |    |        |    |        |
//               +--------+    +--------+    +--------+    +--------+
//               |  CSMA  |    |  CSMA  |    |  CSMA  |    |  CSMA  |
//               +--------+    +--------+    +--------+    +--------+
//                   |             |             |             |
//                   |             |             |             |
//                   |             |             |             |
//                   ===========================================
//                                 CSMA LAN 10.1.1
//
// The CSMA device on node zero is:  10.1.1.1
// The CSMA device on node one is:   10.1.1.2
// The CSMA device on node two is:   10.1.1.3
// The CSMA device on node three is: 10.1.1.4
//
// Some simple things to do:
//
// 1) Ping one of the simulated nodes
//
//    ./waf --run tap-csma&
//    ping 10.1.1.2
//    telnet 10.1.1.2  12345
//
//Make sure to allow port 12345 on your iptables
//Put a routing table entry at the client machine to the network 10.1.1.0/24 having the GW as the IP of the actual local
//IP of the PC running NS-3
//Allow the port 12345 at the iptables for the FORWARD table
/*#enable forwarding
sudo iptables -I FORWARD -p all -d 10.1.1.0/24  -j ACCEPT
sudo iptables -I FORWARD -p all -s 10.1.1.0/24  -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT

If not put a NAT entry so that all packets coming to the local IP (172.24.2.155) of the PC on port 12345 will be natted to 10.1.1.2
#enable natting

sudo iptables -t nat -A PREROUTING -i em1 -p tcp --dport 12345 -j DNAT --to-destination 10.1.1.2
sudo iptables -t nat -A POSTROUTING -o tap0 -p tcp --dport 12345 -d 10.1.1.2 -j SNAT --to-source 172.24.2.155


// If the --server mode is specified, only one ns-3 node is created 
// on the specified device name, assuming that a client node is
// on another virtual machine.  The server node will use 10.1.1.1
*/
#include <fstream>
#include "ns3/core-module.h"
#include "ns3/internet-module.h"
#include "ns3/applications-module.h"
#include "ns3/fd-net-device-module.h"
#include "ns3/callback.h"
#include "ns3/socket-factory.h"
#include "ns3/udp-socket-factory.h"
#include "ns3/tcp-socket-factory.h"
#include "ns3/simulator.h"
#include "ns3/simple-channel.h"
#include "ns3/simple-net-device.h"
#include "ns3/simple-net-device-helper.h"
#include "ns3/socket.h"
#include "ns3/traffic-control-helper.h"
#include "ns3/tcp-option-rfc793.h"
#include "ns3/tap-bridge-module.h"
#include "ns3/header.h"
#include "ns3/packet.h"
#include "ns3/ipv4-header.h"
#include <sys/socket.h>
#include <arpa/inet.h>
#include <math.h>
#include <string.h>

using namespace ns3;

NS_LOG_COMPONENT_DEFINE ("TapTcpEchoExample");
int changeVariables = 0;
std::list<Ptr<Socket> > m_socketList; //the accepted sockets
/*static void
 SendMsg (Ptr<Packet> packet,Ptr<Socket> socket)
 {

	   unsigned char buffer[1024] ;
	   unsigned int bufferFloat[1024];


	   if(changeVariables){
		   packet->CopyData (buffer, packet->GetSize ());
		          int integerData;
		          float floatingPointData;
		          memcpy(&bufferFloat, &buffer[0], 8);

		          bufferFloat[0] = ntohl(bufferFloat[0]);
		          bufferFloat[1] = ntohl(bufferFloat[1]);
		          integerData =  bufferFloat[0];
		          memcpy(&floatingPointData, &bufferFloat[1], 4);
		          integerData = integerData + (int)ceil(integerData*0.1);
		          floatingPointData = floatingPointData*1.1;
		          memcpy(&bufferFloat[0], &integerData, 4);
		          memcpy(&bufferFloat[1], &floatingPointData, 4);
		          bufferFloat[0] = htonl(bufferFloat[0]);
		          bufferFloat[1] = htonl(bufferFloat[1]);
		          memcpy(&buffer, & bufferFloat, 8);
		          Ptr<Packet> packetNew = Create<Packet>(&buffer,8);
		          int numbTx = socket->Send(packetNew);
	   }
 }*/

bool HandleAcceptRequest (Ptr<Socket> s, const Address& from)
{
	NS_LOG_INFO(" HANDLE ACCEPT REQUEST FROM " <<  InetSocketAddress::ConvertFrom(from));

	return true;
}

 void
 SocketPrinter (Ptr<Socket> socket)
 {


   Ptr<Packet> packet;


//   Ptr<SocketFactory> rxSocketFactory = n->Get (0)->GetObject<TcpSocketFactory> ();
//   Ptr<Socket> txSocketn0 = rxSocketFactory->CreateSocket ();
//   txSocketn0->Bind();
//   txSocketn0->Connect (InetSocketAddress (Ipv4Address ("172.24.9.244"), 7001));
   while ((socket->GetRxAvailable())>0)
     {


       uint32_t toRead =socket->GetRxAvailable ();
       packet = socket->Recv (toRead, 0);
       std::cout << "at=" << Simulator::Now ().GetSeconds () << "s, rx bytes=" << packet->GetSize () << std::endl;
       unsigned char buffer[1024] ;
       unsigned int bufferFloat[1024];
       packet->CopyData (buffer, packet->GetSize ());
       float floatingPointData;
       memcpy(&bufferFloat, &buffer[0], 8);

       bufferFloat[0] = ntohl(bufferFloat[0]);
       bufferFloat[1] = ntohl(bufferFloat[1]);
       memcpy(&floatingPointData, &bufferFloat[1], 4);
       printf("point0 = %d\n", bufferFloat[0]);
       printf("point1 = %f\n", floatingPointData);
       //Ptr<Packet> copy = packet->Copy ();
       //Ipv4Header iph;
       //copy->RemoveHeader (iph);
       //Ipv4Address destAddr = iph.GetDestination();

       //int numbTx = txSocketn0->Send(packet);

       //std::printf("Float as int:  %x\n",bufferFloat[1]);
       //std::printf("Float as float: %f\n",floatingPointData);

       //modifying the data
//       integerData =  bufferFloat[0];
//       memcpy(&floatingPointData, &bufferFloat[1], 4);
//       integerData = integerData + (int)ceil(integerData*0.1);
//       floatingPointData = floatingPointData*1.1;
//       memcpy(&bufferFloat[0], &integerData, 4);
//       memcpy(&bufferFloat[1], &floatingPointData, 4);
       bufferFloat[0] = htonl(bufferFloat[0]);
       bufferFloat[1] = htonl(bufferFloat[1]);
       memcpy(&buffer, &bufferFloat, 8);
       Ptr<Packet> packetNew = Create<Packet>(buffer,8);
       socket->Send(packetNew);
       //txSocketn0->SetSendCallback (MakeBoundCallback (&SendMsg,packet));

     }
 }

void HandleAccept (Ptr<Socket> s, const Address& from)
		  {
	NS_LOG_FUNCTION (s << from);
	s->SetRecvCallback (MakeCallback (&SocketPrinter));
	m_socketList.push_back (s);
		  }
// static void
// PrintTraffic (NodeContainer *n,Ptr<Socket> socket)
// {
//
//   socket->SetRecvCallback (MakeBoundCallback (&SocketPrinter,n));
//   std::printf("after Print traffic method \n");
// }


void HandleClose(Ptr<Socket> s1)
{
	NS_LOG_INFO(" PEER CLOSE ");
	NS_LOG_INFO("**********************************************************");

	//Ptr<Socket> s2 = m_pair[s1];

	/*
	m_conn.erase(s1);
	m_conn.erase(s2);
	m_pair.erase(s1);
	m_pair.erase(s2);
	PrintPairs();
	NS_LOG_INFO("Closing socket S1 " << s1);
	s1->Close();
	NS_LOG_INFO("Closing socket S2 " << s2);
	s2->Close();
	NS_LOG_INFO("Done closing sockets " << s1 << " " << s2);
	*/
	if (s1) {
		s1->Close();
		s1 = NULL;
	}
}
int
main (int argc, char *argv[])
{
  ns3::PacketMetadata::Enable ();
  std::string deviceName ("eno1");
  std::string encapMode ("Dix");
  bool clientMode = false;
  bool serverMode = false;
  double stopTime = 10;
  uint32_t nNodes = 4;
  std::string mode = "ConfigureLocal";
   std::string tapName = "tap0";
  //Config::SetDefault ("ns3::TcpL4Protocol::SocketType", StringValue ("ns3::TcpTahoe"));


  //
  // Allow the user to override any of the defaults at run-time, via command-line
  // arguments
  //
  CommandLine cmd;
  cmd.AddValue ("client", "client mode", clientMode);
  cmd.AddValue ("server", "server mode", serverMode);
  cmd.AddValue ("deviceName", "device name", deviceName);
  cmd.AddValue ("stopTime", "stop time (seconds)", stopTime);
  cmd.AddValue ("encapsulationMode", "encapsulation mode of emu device (\"Dix\" [default] or \"Llc\")", encapMode);
  cmd.AddValue ("nNodes", "number of nodes to create (>= 2)", nNodes);

  cmd.Parse (argc, argv);

  GlobalValue::Bind ("SimulatorImplementationType",
                     StringValue ("ns3::RealtimeSimulatorImpl"));

  GlobalValue::Bind ("ChecksumEnabled", BooleanValue (true));

  if (clientMode && serverMode)
    {
      NS_FATAL_ERROR("Error, both client and server options cannot be enabled.");
    }
  //
  // need at least two nodes
  //
  nNodes = nNodes < 2 ? 2 : nNodes;

  //
  // Explicitly create the nodes required by the topology (shown above).
  //
  NS_LOG_INFO ("Create nodes.");
  NodeContainer n;
  n.Create (nNodes);
  Config::SetDefault("ns3::TcpSocket::SegmentSize", UintegerValue (1460));



  //
  // Explicitly create the channels required by the topology (shown above).
  //
  NS_LOG_INFO ("Create channels.");
//  EmuFdNetDeviceHelper emu;
//  emu.SetDeviceName (deviceName);
//  emu.SetAttribute ("EncapsulationMode", StringValue (encapMode));

  CsmaHelper csma;
    csma.SetChannelAttribute ("DataRate", DataRateValue (5000000));
    csma.SetChannelAttribute ("Delay", TimeValue (MilliSeconds (2)));

    NetDeviceContainer devices = csma.Install (n);

    InternetStackHelper internet; //installing the networking capability

      internet.Install (n);

      Ipv4AddressHelper ipv4;
        Ipv4InterfaceContainer i;
        ApplicationContainer apps;

        ipv4.SetBase ("10.1.1.0", "255.255.255.0", "0.0.0.1");

      if (serverMode)
          {

           Ipv4StaticRoutingHelper ipv4RoutingHelper;
//             // Create static routes from A to C
//
            Ptr<Ipv4> ipv4A = n.Get(1)->GetObject<Ipv4>();

            Ptr<Ipv4StaticRouting> staticRoutingA = ipv4RoutingHelper.GetStaticRouting (ipv4A);
             // The ifIndex for this outbound route is 1; the first p2p link added

            staticRoutingA->SetDefaultRoute(Ipv4Address("10.1.1.1"),1,0);

            Ptr<Ipv4> ipv4B = n.Get(2)->GetObject<Ipv4>();

                        Ptr<Ipv4StaticRouting> staticRoutingB = ipv4RoutingHelper.GetStaticRouting (ipv4B);
                         // The ifIndex for this outbound route is 1; the first p2p link added

                        staticRoutingB->SetDefaultRoute(Ipv4Address("10.1.1.1"),1,0);
      //
      //      d = emu.Install (n.Get (0));
      //      Ptr<FdNetDevice> dev = d.Get (0)->GetObject<FdNetDevice> ();
      //      dev->SetAddress (Mac48Address ("64:00:6a:5c:af:58"));
            NS_LOG_INFO ("Assign IP Addresses.");
            i = ipv4.Assign (devices);
          }

  TapBridgeHelper tapBridge;
    tapBridge.SetAttribute ("Mode", StringValue (mode));
    tapBridge.SetAttribute ("DeviceName", StringValue (tapName));
    tapBridge.Install (n.Get (0), devices.Get (0));





    
  if (serverMode)
    {

      //
      // Create a UdpEchoServer application 
      //
      NS_LOG_INFO ("Create Applications.");
      //uint16_t sinkPort = 12345;
      // Create the TCP sockets
      Ptr<SocketFactory> rxSocketFactory = n.Get (1)->GetObject<TcpSocketFactory> ();
            Ptr<Socket> rxSocketn0 = rxSocketFactory->CreateSocket ();

      Ptr<Ipv4> ipV4Info = n.Get (1)->GetObject<Ipv4>();
      int interfaceIndex = ipV4Info->GetInterfaceForAddress(Ipv4Address("10.1.1.2"));
      						std::cout<<"NetDev:"<<interfaceIndex;


      //rxSocketn0->SetAttribute("SegmentSize", UintegerValue (1460));
     // rxSocketn0->SetAttribute("MaxWindowSize", UintegerValue (60000));
     //rxSocketn0->SetAttribute("WindowScaling", BooleanValue (true));
     //rxSocketn0->SetAttribute("RcvBufSize", ns3::UintegerValue(60000));
      rxSocketn0->Bind (InetSocketAddress (Ipv4Address("10.1.1.2"), 12345));
      rxSocketn0->Listen();
      rxSocketn0->SetRecvCallback (MakeCallback (&SocketPrinter));
      rxSocketn0->SetAcceptCallback (MakeCallback(&HandleAcceptRequest),MakeCallback (&HandleAccept));
      rxSocketn0->SetCloseCallbacks(MakeCallback(&HandleClose), MakeCallback(&HandleClose));
      rxSocketn0->Initialize();

        //rxSocketn0->Connect (InetSocketAddress (Ipv4Address ("172.24.9.244"), 7001));

//      Address sinkLocalAddress (InetSocketAddress (Ipv4Address ("172.24.2.55"), sinkPort));
//           PacketSinkHelper sinkHelper ("ns3::TcpSocketFactory", sinkLocalAddress);
//             ApplicationContainer sinkApp = sinkHelper.Install (n.Get(0));
//            sinkApp.Start (Seconds (1.0));
//             sinkApp.Stop (Seconds (60.0));

//        Ptr<TcpEchoServer> app = CreateObject<TcpEchoServer> ();
//             //app->Setup (ingressNode,Ipv4Address ("172.24.2.55"),Ipv4Address ("10.1.8.6"), 7001,7001,INGRESS_NODE);
//             app->SetAttribute("Local",Ipv4AddressValue("172.24.2.55"));
//             app->SetAttribute("Port", UintegerValue (12345));
//
//
//             n.Get(0)->AddApplication (app);
//             app->SetStartTime (Seconds (1.));
//             app->SetStopTime (Seconds (stopTime));

        //rxSocketn0->SetRecvCallback (MakeCallback (&SocketPrinter));
       // rxSocket2->SetRecvCallback (MakeCallback (&SocketPrinter) );
        //PrintTraffic ( &n, rxSocketn0);

    /*  UdpEchoServerHelper server (4888);
      apps = server.Install (n.Get (0));
      apps.Start (Seconds (1.0));
      apps.Stop (Seconds (stopTime));*/
    }

 csma.EnablePcapAll ("fd-tap-tcp-echo", true);
 csma.EnableAsciiAll ("fd-tap-tcp-echo.tr");

 Ipv4GlobalRoutingHelper::PopulateRoutingTables ();
  //
  // Now, do the actual simulation.
  //
  NS_LOG_INFO ("Run Simulation.");
  Simulator::Stop (Seconds (stopTime + 2));
  Simulator::Run ();
  Simulator::Destroy ();
  NS_LOG_INFO ("Done.");
}
