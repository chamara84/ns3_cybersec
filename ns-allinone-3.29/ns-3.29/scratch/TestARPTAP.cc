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


Time::SetResolution (Time::NS);
PacketMetadata::Enable();
Packet::EnablePrinting();

GlobalValue::Bind ("SimulatorImplementationType",
                     StringValue ("ns3::RealtimeSimulatorImpl"));

GlobalValue::Bind ("ChecksumEnabled", BooleanValue (true));

//Creating the nodes 
Ptr<Node> n0 = CreateObject<Node> ();
Ptr<Node> n1 = CreateObject<Node> ();
Ptr<Node> n2 = CreateObject<Node> ();
Ptr<Node> n3 = CreateObject<Node> ();



NodeContainer LAN1nodes = NodeContainer(n0,n1,n2,n3);; //Container for LAN1 nodes which consists of n0 and n1

//we install csmanet devices on nodes of LAN1 
 
 CsmaHelper csma;
 csma.SetChannelAttribute ("DataRate", StringValue ("100Mbps"));
 csma.SetChannelAttribute ("Delay", TimeValue (NanoSeconds (6560)));
 
 
 
 
 NetDeviceContainer LAN1devices;
 LAN1devices = csma.Install(LAN1nodes);

 
 
 
 // WE install the protocol stacks on the nodes
 InternetStackHelper stack; 
 stack.Install(LAN1nodes);

 
Ipv4AddressHelper address; // we use the Ipv4AddressHelper to assign IP addresses to our device interfaces.
address.SetBase ("172.24.0.0", "255.255.0.0","0.0.9.241");
Ipv4InterfaceContainer LAN1Interfaces;
LAN1Interfaces = address.Assign (LAN1devices);





// Access to IPv4 stack of the nodes

Ptr<Ipv4> ipv4n0 = n0->GetObject<Ipv4> ();
Ptr<Ipv4> ipv4n1 = n1->GetObject<Ipv4> ();
Ptr<Ipv4> ipv4n2 = n2->GetObject<Ipv4> ();
Ptr<Ipv4> ipv4n3 = n3->GetObject<Ipv4> ();


Ipv4GlobalRoutingHelper::PopulateRoutingTables ();  // populates the routing tables
 Ipv4StaticRoutingHelper ipv4RoutingHelper;

  
 // the next hop of n1 is n0
 
 //Ptr<Ipv4StaticRouting> staticRoutingn0 = ipv4RoutingHelper.GetStaticRouting (ipv4n0);
  

  //staticRoutingn0->SetDefaultRoute (Ipv4Address ("172.16.29.1"),1,0);
  
//staticRoutingn0->AddNetworkRouteTo (Ipv4Address ("172.24.29.0"), Ipv4Mask ("255.255.255.0"), 1,0);






//Ptr<Ipv4StaticRouting> staticRoutingn1 = ipv4RoutingHelper.GetStaticRouting (ipv4n1);
  




// Connect the left side tap to the left side CSMA device in ghost node n0

TapBridgeHelper tapBridge;
tapBridge.SetAttribute ("Mode", StringValue ("UseBridge"));
tapBridge.SetAttribute ("DeviceName", StringValue ("tap00"));
tapBridge.Install (n3, LAN1devices.Get (3));


tapBridge.SetAttribute ("DeviceName", StringValue ("tap01"));
tapBridge.Install (n0, LAN1devices.Get (0));












 uint32_t attackerId = 2;
 uint32_t attackerId2 = 2;



  std::pair<Ptr<Ipv4>, uint32_t> returnValue =  LAN1Interfaces.Get (attackerId);
  Ptr<Ipv4> ipv4 = returnValue.first;
  uint32_t index = returnValue.second;
  Ptr<Ipv4Interface> iface =  ipv4->GetObject<Ipv4L3Protocol> ()->GetInterface (index);
  
  std::pair<Ptr<Ipv4>, uint32_t> returnValue2 =  LAN1Interfaces.Get (attackerId2);
  Ptr<Ipv4> ippv4 = returnValue2.first;
  uint32_t index2 = returnValue2.second;
  Ptr<Ipv4Interface> iface2 =  ippv4->GetObject<Ipv4L3Protocol> ()->GetInterface (index2);
  

  
  //contruct attacker app
  Ptr<AttackApp> attacker = CreateObject<AttackApp> ();

  std::vector<Ipv4Address> spoofedIPs{Ipv4Address ("172.24.9.251")};
                                std::vector<Ipv4Address>victimIPs{Ipv4Address ("172.24.9.167")};
                                std::vector<Address>victimMACs{ns3::Mac48Address("00:50:c2:4f:99:0c")};
                                //attacker->Setup(n0n1n2n3.Get(attackerId), dn0n1n2n3.Get(attackerId), iface, Ipv4Address ("172.24.9.250"), Ipv4Address ("172.24.2.90"), ns3::Mac48Address("00:30:a7:1d:75:bd"));
                               attacker->Setup(LAN1nodes.Get(attackerId), LAN1devices.Get(attackerId), iface, spoofedIPs, victimIPs, victimMACs);
                                LAN1nodes.Get (attackerId)->AddApplication (attacker);
                                attacker->SetStartTime (Seconds (1.0));
                                attacker->SetStopTime (Seconds (3600.0));
  
  //Here the attack in the other direction
  


   Ptr<AttackApp> attacker2 = CreateObject<AttackApp> ();
                                                                std::vector<Ipv4Address> spoofedIPs1{Ipv4Address ("172.24.9.167")};
                                                                                                std::vector<Ipv4Address>victimIPs1{Ipv4Address ("172.24.9.251")};
                                                                                                std::vector<Address>victimMACs1{ns3::Mac48Address("80:6d:97:30:1c:74")};
                                                             //   attacker2->Setup(n0n1n2n3.Get(attackerId2), dn0n1n2n3.Get(attackerId2), iface2, Ipv4Address ("172.24.9.90"), Ipv4Address ("172.24.9.250"), ns3::Mac48Address("00:50:c2:4f:9b:73"));
                                                               attacker2->Setup(LAN1nodes.Get(attackerId), LAN1devices.Get(attackerId), iface2,  spoofedIPs1, victimIPs1,victimMACs1);
                                                                LAN1nodes.Get (attackerId2)->AddApplication (attacker2);
                                                                attacker2->SetStartTime (Seconds (1.0));
                                                                attacker2->SetStopTime (Seconds (3600.0));
  
  
  
  
  
  
  
  
 
  Ipv4GlobalRoutingHelper::PopulateRoutingTables ();
  
  
  //socket1->Send(pkt);


 
  csma.EnablePcapAll("arpspooftap"); 
   Simulator::Stop (Seconds (3600));
  Simulator::Run ();
  
  //Address tk= csmaDevices.Get(attackerId)->GetAddress();
  
  //std::cout << csmaInterfaces.GetAddress(victimId) << std::endl;
  //std::cout << csmaInterfaces.GetAddress(serverId) << std::endl;
  std::cout << LAN1Interfaces.GetAddress(2) << std::endl;
    //std::cout << LAN1Interfaces.GetAddress(0) << std::endl;
  //std::cout << tk << std::endl;
  std::cout << LAN1devices.Get(2)->GetAddress() << std::endl;
  //std::cout << LAN1devices.Get(0)->GetAddress() << std::endl;
  Simulator::Destroy ();
  
  
  return 0;
}

