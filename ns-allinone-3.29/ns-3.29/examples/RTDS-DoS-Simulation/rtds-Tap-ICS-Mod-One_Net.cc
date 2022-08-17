/*
 * rtds-Tap-ICS-Mod.cc
 *
 *  Created on: May 8, 2020
 *      Author: chamara
 *      Based on an example from the Univesity of Strathclyde
 */

/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
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
 * along with this program; if not, write to the FreeEthernet (enp6s0f1) Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */





/*
 * Use two hostonly interfaces in the virtual box
 * Run the setupInterface script
 * Add routes to the NS3 networks in windows
 * route ADD 192.168.10.0 MASK 255.255.255.0  192.168.19.4 METRIC 3 IF 3
 */

// Includes
#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <iostream>
#include <fstream>
#include "ns3/ipv4-address-generator.h"
#include <string>
#include <cassert>
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
#include "ns3/tap-bridge-module.h"
#include "ns3/tap-bridge-helper.h"


using namespace ns3;
using namespace std;

NS_LOG_COMPONENT_DEFINE ("RTDS-Tap-Log");


int main (int argc, char *argv[])
{

// For configurability at the start of the simulation
/*
  int nrNetNodes = 0;
  int linkDelay = 0;
//  std::string indataRate = "100MBps"
  CommandLine cmd;
  cmd.AddValue ("nrNetNodes","number of nodes in between the interface",nrNetNodes);
  cmd.AddValue ("linkDelay","the distance between nodes i.e. propagation delay", linkDelay);
//  cmd.AddValue ("indataRate","the capacity of P2P lings", indataRate);
  cmd.Parse (argc, argv);
*/

	//Time::SetResolution (Time::NS);
		//PacketMetadata::Enable();
	//	Packet::EnablePrinting();
	//	MobilityHelper mobility;
	//		  mobility.SetMobilityModel("ns3::ConstantPositionMobilityModel");

  //
  // We are interacting with the outside, real, world.  This means we have to
  // interact in real-time and therefore means we have to use the real-time
  // simulator and take the time to calculate checksums.
  //
  GlobalValue::Bind ("SimulatorImplementationType", StringValue ("ns3::RealtimeSimulatorImpl"));
  GlobalValue::Bind ("ChecksumEnabled", BooleanValue (true));

  //
  // Create interface nodes inside ns3

  // create Bridges (Interface nodes) that will connect to the outside world
//  Ptr<Node> inN0 = CreateObject<Node> ();
//  Ptr<Node> inN1 = CreateObject<Node> ();
//  Ptr<Node> inN2 = CreateObject<Node> ();
//  Ptr<Node> inN3 = CreateObject<Node> ();
//  Ptr<Node> inN4 = CreateObject<Node> ();

  // Create ns3 nodes for simulating the communications network
  Ptr<Node> n0 = CreateObject<Node> ();
  Ptr<Node> n1 = CreateObject<Node> ();
  Ptr<Node> n2 = CreateObject<Node> ();
  Ptr<Node> n3 = CreateObject<Node> ();
  Ptr<Node> n4 = CreateObject<Node> ();


  //Containers for grouping nodes, used to group nodes which will have a common connection
//  NodeContainer inNx = NodeContainer(inN0,inN1,inN2,inN3,inN4);
  //NodeContainer inN3n3 = NodeContainer(inN3,n3);
  //NodeContainer n2inN2 = NodeContainer(n2,inN2);
  //NodeContainer n3inN3 = NodeContainer(n3,inN3);
  //NodeContainer n4inN4 = NodeContainer(n4,inN4);

  // container for topology connections
  //for topology check https://photos.app.goo.gl/sUDM8VBMIXqnpuf72  *The non-lte picture example

  NodeContainer n0n1n2n3 = NodeContainer(n0,n1,n2,n3,n4);
 // NodeContainer n1n2 = NodeContainer(n1,n2);
//  NodeContainer n1n3 = NodeContainer(n1,n3);
//  NodeContainer n4inN4 = NodeContainer(n4,inN4);


  // Use a CsmaHelper to get a CSMA channel created, and the needed net
  // devices installed on both of the nodes.  The data rate and delay for the
  // channel can be set through the command-line parser.

  //CsmaHelper assits in adding csma links(interfaces) to the grouped nodes inside the containers.


//  CsmaHelper csmaIngress;
//  csmaIngress.SetChannelAttribute ("DataRate", StringValue ("100Mbps"));
//  csmaIngress.SetChannelAttribute ("Delay", TimeValue (NanoSeconds (6560))); // be very carefull about the delay that is applied to CSMA link, excessive delays will stack due to half duplex behaviour of the link


  CsmaHelper csmaNetwork;

    csmaNetwork.SetChannelAttribute ("DataRate", StringValue ("100Mbps"));
      csmaNetwork.SetChannelAttribute ("Delay", TimeValue (NanoSeconds (6560))); // be very carefull about the delay that is applied to CSMA link, excessive delays will stack due to half duplex behaviour of the link


//  PointToPointHelper p2p;
//  p2p.SetDeviceAttribute ("DataRate", StringValue ("100Mbps"));
//  p2p.SetChannelAttribute ("Delay", TimeValue (MicroSeconds (5)));  // delay of the point to point link can be manipulated to apply excessive delays
 //  p2p.SetChannelAttribute ("Delay", StringValue ("100ms"));


  // connecting linux interfaces to nodes, Connecting a cable to all the devices within a container in these cases between 2 nodes

     NetDeviceContainer dn0n1n2n3 = csmaNetwork.Install (n0n1n2n3); //Network access to the outside
     //NetDeviceContainer dinNx = csmaIngress.Install(inNx); //network access to the inside

   //  NetDeviceContainer dn3dinN3 = csma.Install (n3inN3);
   //  NetDeviceContainer dn4dinN4 = csma.Install (n4inN4);
  // connecting nodes for the simulation
  //	NetDeviceContainer dn4inN4 = p2p.Install (n4inN4); //link connecting the outside network to the inside
 //   NetDeviceContainer dn1dn2 = p2p.Install (n1n2);
 //   NetDeviceContainer dn1dn3 = p2p.Install (n1n3);
 //   NetDeviceContainer dn3dn4 = p2p.Install (n3n4);


// end of building the network

// installing IP stacks into the nodes
InternetStackHelper stack;
stack.Install (n0);
stack.Install (n1);
stack.Install (n2);
stack.Install (n3);
stack.Install (n4);
//stack.Install (inN0);
//stack.Install (inN1);
//stack.Install (inN2);
//stack.Install (inN3);
//stack.Install (inN4);


// For interfaces between real linux interface and interface between simulation node

// *** NOTE: because initialised first CSMA i.e. the interface to real dices is INDEX = 1

Ipv4AddressHelper ipv4;




ipv4.SetBase ("172.24.0.0", "255.255.0.0","0.0.9.241"); //this is the outer network
Ipv4InterfaceContainer ipn0n1n2n3 = ipv4.Assign (dn0n1n2n3);

//ipv4.SetBase ("192.168.100.0", "255.255.255.0"); //this is the network in the inner side
//Ipv4InterfaceContainer ipinNx = ipv4.Assign (dinNx);
////
//ipv4.SetBase ("192.168.12.0", "255.255.255.252");  //this is the p2p link
//Ipv4InterfaceContainer ipn4inN4 = ipv4.Assign (dn4inN4);
////
//ipv4.SetBase ("192.168.13.0", "255.255.255.0");
//Ipv4InterfaceContainer in3in4 = ipv4.Assign (dn3dn4);




// Get access to the IPv4 stack of the nodes to push routing tables
 Ptr<Ipv4> ipv4n0 = n0->GetObject<Ipv4> ();
 Ptr<Ipv4> ipv4n1 = n1->GetObject<Ipv4> ();
 Ptr<Ipv4> ipv4n2 = n2->GetObject<Ipv4> ();
 Ptr<Ipv4> ipv4n3 = n3->GetObject<Ipv4> ();
 Ptr<Ipv4> ipv4n4 = n4->GetObject<Ipv4> ();
// Ptr<Ipv4> ipv4inN0 = inN0->GetObject<Ipv4> ();
// Ptr<Ipv4> ipv4inN1 = inN1->GetObject<Ipv4> ();
// Ptr<Ipv4> ipv4inN2 = inN2->GetObject<Ipv4> ();
// Ptr<Ipv4> ipv4inN3 = inN3->GetObject<Ipv4> ();
// Ptr<Ipv4> ipv4inN4 = inN4->GetObject<Ipv4> ();
// Setup routing

//Automatic routing setup  does not work, cant see end device IP addresses

Ipv4GlobalRoutingHelper::PopulateRoutingTables ();

//can use manual routing too (complete-untested)

 //Ipv4StaticRoutingHelper ipv4RoutingHelper;
// routes outbound frsudo brctl addif br-right tap-rightom A and D are setup in the lxc containers


/*
// routing in node 0
// Create static routes
Ptr<Ipv4StaticRouting> staticRoutingA = ipv4RoutingHelper.GetStaticRouting (ipv4A);
//from B to C
// The ifIndex for this outbound route is 2; 0 - loopback (always), 1 - CSMA, 2- Tap device? (based on order of device instantiations in the node)
staticRoutingA->AddHostRouteTo (Ipv4Address ("192.168.11.5"), Ipv4Address ("192.168.10.1"), 1);
// and route B to A
staticRoutingA->AddHostRouteTo (Ipv4Address ("192.168.10.5"), Ipv4Address ("192.168.10.2"), 2);
//route to lixun server phisical port
staticRoutingA->AddHostRouteTo (Ipv4Address ("192.168.10.2"), Ipv4Address ("192.168.10.2"), 2);
// route from 192.168.10.2 to 192.168.10.1
staticRoutingA->AddHostRouteTo (Ipv4Address ("192.168.10.1"), Ipv4Address ("192.168.10.1"), 1);
*/


// Ptr<Ipv4StaticRouting> staticRoutingn0 = ipv4RoutingHelper.GetStaticRouting (ipv4n0);
//
// // routing from n0 to n1,n2,n3,n4
// // The ifIndex for this outbound route is 2; 0 - loopback (always), 1 - CSMA, 2- P2P (based on order of device instantiations in the node)
//
//staticRoutingn0->SetDefaultRoute(Ipv4Address ("172.24.0.1"), 2,0);
////staticRoutingn0->AddNetworkRouteTo(Ipv4Address ("192.168.100.0"),Ipv4Mask ("255.255.255.0"),Ipv4Address ("172.24.9.245"),1,3); //may be not needed since Ns3 knows the existence and routing for the network
//
//
//
////Ptr<Ipv4StaticRouting> staticRoutinginN0 = ipv4RoutingHelper.GetStaticRouting (ipv4inN0);
//
// // routing from n1 to n0,n2,n3,n4
// // Create static routes
// Ptr<Ipv4StaticRouting> staticRoutingn1 = ipv4RoutingHelper.GetStaticRouting (ipv4n1);
//
// // The ifIndex for this outbound route is 2; 0 - loopback (always), 1 - CSMA, 2- P2P (based on order of device instantiations in the node)
//
// staticRoutingn1->AddNetworkRouteTo (Ipv4Address ("172.24.0.0"), Ipv4Mask ("255.255.0.0"), 1,0);
//
// // routing from n2 to n0,n1,n3,n4
// // Create static routes
// Ptr<Ipv4StaticRouting> staticRoutingn2 = ipv4RoutingHelper.GetStaticRouting (ipv4n2);
// //from B to C
// // The ifIndex for this outbound route is 2; 0 - loopback (always), 1 - CSMA, 2- P2P (based on order of device instantiations in the node)
//
//  staticRoutingn2->AddNetworkRouteTo(Ipv4Address ("172.24.0.0"), Ipv4Mask ("255.255.0.0"), 1,0);
//
// // routing from n3 to n0,n1,n2,n4
// // Create static routes
// Ptr<Ipv4StaticRouting> staticRoutingn3 = ipv4RoutingHelper.GetStaticRouting (ipv4n3);
//
//
// // The ifIndex for this outbound route is 2; 0 - loopback (always), 1 - CSMA, 2- P2P (based on order of device instantiations in the node)
//  staticRoutingn3->SetDefaultRoute(Ipv4Address ("172.24.0.1"), 2,0); // or next hop ip is: 192.168.12.1
//
//

//  Ptr<Ipv4StaticRouting> staticRoutingn4 = ipv4RoutingHelper.GetStaticRouting (ipv4n4);
//
//
//   // The ifIndex for this outbound route is 2; 0 - loopback (always), 1 - CSMA, 2- P2P (based on order of device instantiations in the node)
//    staticRoutingn4->SetDefaultRoute(Ipv4Address ("172.24.0.1"), 2,0); // or next hop ip is: 192.168.12.1


// end of routing setup



// Use the TapBridgeHelper to connect to the pre-configured tap devices for
// the left side.  We go with "UseBridge" mode since the CSMA devices support
// promiscuous mode and can therefore make it appear that the bridge is
// extended into ns-3.  The install method essentially bridges the specified
// tap to the specified CSMA device.
//
// Connect the left side tap to the left side CSMA device in ghost node n0

  TapBridgeHelper tapBridge;
tapBridge.SetAttribute ("Mode", StringValue ("UseBridge"));
tapBridge.SetAttribute ("DeviceName", StringValue ("tap00"));
tapBridge.Install (n0, dn0n1n2n3.Get (0));

//
// Connect the right side tap to the right side CSMA device in ghost node n3
//
// Contrainer left is used only because right container is replaced with a windows mashine running PMU connection tester
//

tapBridge.SetAttribute ("DeviceName", StringValue ("tap01"));
tapBridge.Install (n4, dn0n1n2n3.Get (4));

//Ipv4GlobalRoutingHelper::PopulateRoutingTables ();
//          //Print Routin Table
//
//          Ptr<OutputStreamWrapper> routingStream = Create<OutputStreamWrapper> (&std::cout);
////          std::cout<<"Routing Table inN4"<<endl;
////          ipv4RoutingHelper.PrintRoutingTableAt(Seconds(1), inN4, routingStream);
//          std::cout<<"Routing Table n4"<<endl;
//          ipv4RoutingHelper.PrintRoutingTableAt(Seconds(1), n4, routingStream);
////          std::cout<<"Routing Table n0"<<endl;
////          ipv4RoutingHelper.PrintRoutingTableAt(Seconds(1), n0, routingStream);




          //setup application

       //   std::stringstream macAddr;
                                uint32_t attackerId = 3;
                                uint32_t attackerId2 = 2;

                               // uint32_t csmaSwitch = 4;
                                Address victimAddr;


                                //attack on the company side network
//                                for( uint32_t i = 0; i <  n0n1n2n3.GetN(); i++ )
//                                  {
//                                	//macAddr << "00:00:00:00:00:0" << i;
//                                	Ptr<NetDevice> nd = dn0n1n2n3.Get (i);
//                                	Ptr<CsmaNetDevice> cd = nd->GetObject<CsmaNetDevice> ();
//								   //cd->SetAddress(ns3::Mac48Address(macAddr.str().c_str()));
//
//
//                                   // cd->SetAddress(ns3::Mac48Address(macAddr.str().c_str()));
//                                    // take a copy of victim addr
//                                    if(i == victimDer)
//                                      victimAddr = cd->GetAddress();
//
//                                  }
                                std::pair<Ptr<Ipv4>, uint32_t> returnValue = ipn0n1n2n3.Get (attackerId);

                                Ptr<Ipv4> ipv4Val = returnValue.first;
                                uint32_t index = returnValue.second;

                                Ptr<Ipv4Interface> iface =  ipv4Val->GetObject<Ipv4L3Protocol> ()->GetInterface (index);


                                Ptr<AttackApp> attacker = CreateObject<AttackApp> ();
                                std::vector<Ipv4Address> spoofedIPs{Ipv4Address ("172.24.9.251")};
                                                                std::vector<Ipv4Address>victimIPs{Ipv4Address ("172.24.4.113")};
                                                                std::vector<Address>victimMACs{ns3::Mac48Address("60:15:92:10:13:22")};
                                //attacker->Setup(n0n1n2n3.Get(attackerId), dn0n1n2n3.Get(attackerId), iface, Ipv4Address ("172.24.9.250"), Ipv4Address ("172.24.2.90"), ns3::Mac48Address("00:30:a7:1d:75:bd"));
                               attacker->Setup(n0n1n2n3.Get(attackerId), dn0n1n2n3.Get(attackerId), iface, spoofedIPs, victimIPs, victimMACs);
                                n0n1n2n3.Get (attackerId)->AddApplication (attacker);
                                attacker->SetStartTime (Seconds (1.0));
                                attacker->SetStopTime (Seconds (3600.0));



                                std::pair<Ptr<Ipv4>, uint32_t> returnValue2 = ipn0n1n2n3.Get (attackerId);

                                                                Ptr<Ipv4> ipv4Val2 = returnValue2.first;
                                                                uint32_t index2= returnValue2.second;

                                                                Ptr<Ipv4Interface> iface2 =  ipv4Val2->GetObject<Ipv4L3Protocol> ()->GetInterface (index2);


                                                                Ptr<AttackApp> attacker2 = CreateObject<AttackApp> ();
                                                                std::vector<Ipv4Address> spoofedIPs1{Ipv4Address ("172.24.4.113")};
                                                                std::vector<Ipv4Address>victimIPs1{Ipv4Address ("172.24.9.251")};
                                                                std::vector<Address>victimMACs1{ns3::Mac48Address("10:65:30:05:d8:ff")};
                                                             //   attacker2->Setup(n0n1n2n3.Get(attackerId2), dn0n1n2n3.Get(attackerId2), iface2, Ipv4Address ("172.24.9.90"), Ipv4Address ("172.24.9.250"), ns3::Mac48Address("00:50:c2:4f:9b:73"));
                                                               attacker2->Setup(n0n1n2n3.Get(attackerId), dn0n1n2n3.Get(attackerId), iface,  spoofedIPs1, victimIPs1,victimMACs1);
                                                                n0n1n2n3.Get (attackerId)->AddApplication (attacker2);
                                                                attacker2->SetStartTime (Seconds (1.0));
                                                                attacker2->SetStopTime (Seconds (3600.0));



                                //attack on the my side network
//                                                               for( uint32_t i = 0; i <  inNx.GetN(); i++ )
//                                                                 {
//                                                            	  // macAddr << "00:00:00:00:00:1" << i;
//                                                            	   Ptr<NetDevice> nd1 = dinNx.Get (i);
//                                                            	   Ptr<CsmaNetDevice> cd1 = nd1->GetObject<CsmaNetDevice> ();
//                                                            	   //cd1->SetAddress(ns3::Mac48Address(macAddr.str().c_str()));
//
//                                                                  // cd->SetAddress(ns3::Mac48Address(macAddr.str().c_str()));
//                                                                   // take a copy of victim addr
//                                                                   if(i == victimDer)
//                                                                     victimAddr = cd1->GetAddress();
//
//                                                                 }
//                                                               std::pair<Ptr<Ipv4>, uint32_t> returnValue1 = ipinNx.Get (attackerId);
//
//                                                               Ptr<Ipv4> ipv4Val1 = returnValue1.first;
//                                                               uint32_t index1 = returnValue1.second;
//
//                                                               Ptr<Ipv4Interface> iface1 =  ipv4Val1->GetObject<Ipv4L3Protocol> ()->GetInterface (index1);
//
//
//                                                               Ptr<AttackApp> attacker1 = CreateObject<AttackApp> (); //Ipv4Address ("192.168.100.10"), ns3::Mac48Address("00:50:c2:4f:9b:73")
//                                                               attacker1->Setup(inNx.Get(attackerId), dinNx.Get(attackerId), iface1, ipinNx.GetAddress(csmaSwitch), Ipv4Address ("192.168.100.10"), ns3::Mac48Address("00:50:c2:4f:9b:73"));
//                                                               inNx.Get (attackerId)->AddApplication (attacker1);
//                                                               attacker1->SetStartTime (Seconds (1.0));
//                                                               attacker1->SetStopTime (Seconds (3600.0));

//csmaNetwork.EnablePcapAll ("pmuconnectiontestNet", true);


//csmaIngress.EnablePcapAll ("pmuconnectiontestIng", false);
csmaNetwork.EnablePcapAll ("pmuconnectiontestNet", false);
//p2p.EnablePcapAll("pmuconnectiontestP2P", false);


  // Run the simulation for ten minutes to give the user time to play around
  //
  Simulator::Stop (Seconds (3600.));
  Simulator::Run ();
  Simulator::Destroy ();
}




