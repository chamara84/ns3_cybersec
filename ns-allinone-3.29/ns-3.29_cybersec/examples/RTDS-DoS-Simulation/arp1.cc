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
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include "ns3/core-module.h"
#include "ns3/network-module.h"
#include "ns3/csma-module.h"
#include "ns3/internet-module.h"
#include "ns3/point-to-point-module.h"
#include "ns3/applications-module.h"
#include "ns3/ipv4-global-routing-helper.h"
#include "ns3/traffic-control-module.h"
 #include "ns3/mobility-module.h"
#include "ns3/netanim-module.h"
#include "ns3/attack-app.h"
#include <sstream>   
#include <iostream> 
#include "ns3/ethernet-trailer.h"

using namespace ns3;

NS_LOG_COMPONENT_DEFINE ("arp1");

//class AttackApp : public Application
//{
//public:
//
//  AttackApp ();
//  virtual ~AttackApp();
//
//  void Setup (Ptr<Node> aNode, Ptr<NetDevice> aDev, Ptr<Ipv4Interface> iface,  Ipv4Address addr, Ipv4Address vAddr, Address vMac);
//
//private:
//  virtual void StartApplication (void);
//  virtual void StopApplication (void);
//  void ScheduleTx (void);
//  void SendPacket (void);
//
//  Ptr<Node> m_node;
//  Ptr<NetDevice> m_device;
//  Ptr<Ipv4Interface> m_iface;
//  Ipv4Address m_fakeAddr;
//
//  // victim info
//  Ipv4Address m_vAddr;
//  Address m_vMac;
//
//  EventId         m_sendEvent;
//  bool            m_running;
//
//  ArpL3Protocol m_attacker;
//  Ptr<ArpCache> m_arpCache;
//};
//
//
//AttackApp::AttackApp ()
//  :m_node(),
//  m_device(),
//  m_iface(),
//  m_fakeAddr(),
//  m_vAddr(),
//  m_vMac(),
//  m_sendEvent (),
//  m_running (false)
//{
//}
//
//AttackApp::~AttackApp()
//{
//}
//
//void
//AttackApp::Setup (Ptr<Node> aNode, Ptr<NetDevice> aDev, Ptr<Ipv4Interface> iface, Ipv4Address addr, Ipv4Address vAddr, Address vMac)
//{
//  m_node = aNode;
//  m_device = aDev;
//  m_iface = iface;
//  m_fakeAddr = addr;
//  m_vAddr = vAddr;
//  m_vMac = vMac;
//}
//
//void
//AttackApp::StartApplication (void)
//{
//  // initialize the attacker
//  m_attacker.SetNode(m_node);
//  m_attacker.SetTrafficControl(m_node->GetObject<TrafficControlLayer> ());
//  m_arpCache = m_attacker.CreateCache(m_device, m_iface);
//  m_running = true;
//  SendPacket();
//}
//
//void
//AttackApp::StopApplication (void)
//{
//  m_running = false;
//
//  if (m_sendEvent.IsRunning ())
//    {
//      Simulator::Cancel (m_sendEvent);
//    }
//}
//
//void
//AttackApp::SendPacket (void)
//{
//  m_attacker.SendArpReply(m_arpCache, m_fakeAddr, m_vAddr, m_vMac);
//  std::cout << "stucked here" << std::endl;
//  ScheduleTx ();
//}
//
//void
//AttackApp::ScheduleTx (void)
//{
//  if (m_running)
//    {
//      Time tNext (MilliSeconds(1000));
//      m_sendEvent = Simulator::Schedule (tNext, &AttackApp::SendPacket, this);
//    }
//}

int
main ()
{
  GlobalValue::Bind ("ChecksumEnabled", BooleanValue (true));
  LogComponentEnable ("UdpClient", LOG_LEVEL_INFO);
  LogComponentEnable ("UdpServer", LOG_LEVEL_INFO);
  LogComponentEnable ("ArpL3Protocol", LOG_LEVEL_INFO);
  LogComponentEnable ("ArpHeader", LOG_LEVEL_INFO);
  LogComponentEnable("arp1", LOG_LEVEL_INFO);
  MobilityHelper mobility;
  mobility.SetMobilityModel("ns3::ConstantPositionMobilityModel");
  uint32_t nPackets = 10;
  uint32_t packetInt = 1000;
  uint32_t propDelay = 200;
  uint32_t delayT = 0;
  uint32_t serverStart = 5;          // Server start time in ms
  uint32_t clientStart = 50;          // Client start time in ms
  uint32_t stopTime = (clientStart) + (nPackets*packetInt) + (10*propDelay) + delayT; // Stop the simulation once all packets have been received

  Ptr<OutputStreamWrapper> stdOutput(new OutputStreamWrapper(&std::cout));
  
  uint32_t nCsma = 3;
  uint32_t attackerId = 1;
  uint32_t serverId = 2;
  uint32_t victimId = 0;

  uint16_t port = 4000;
  uint32_t MaxPacketSize = 32;
  
  Address victimAddr;

  NodeContainer csmaNodes;

  csmaNodes.Create (nCsma);

  mobility.Install(csmaNodes);
  CsmaHelper csma;
  csma.SetChannelAttribute ("DataRate", StringValue ("100Mbps"));
  csma.SetChannelAttribute ("Delay", TimeValue (NanoSeconds (6560)));
  csma.SetDeviceAttribute ("EncapsulationMode", StringValue ("Dix"));


  NetDeviceContainer csmaDevices = csma.Install (csmaNodes);

  // define the mac address
  std::stringstream macAddr;
  InternetStackHelper stack;
                 stack.Install (csmaNodes);

    TrafficControlHelper tch;
           tch.SetRootQueueDisc ("ns3::TbfQueueDisc",
                                 "Burst", UintegerValue (10000),
                                 "Mtu", UintegerValue (1500),
                                 "Rate", DataRateValue (DataRate (DataRate ("100Mbps"))),
                                 "PeakRate", DataRateValue (DataRate (DataRate ("1000Mbps"))));
          QueueDiscContainer qdiscs = tch.Install (csmaDevices);


  for( uint32_t i = 0; i < nCsma; i++ )  
  {
    macAddr << "00:00:00:00:00:0" << i;
    Ptr<NetDevice> nd = csmaDevices.Get (i);
    Ptr<CsmaNetDevice> cd = nd->GetObject<CsmaNetDevice> ();
    cd->SetAddress(ns3::Mac48Address(macAddr.str().c_str()));


    // take a copy of victim addr
    if(i == victimId)
      victimAddr = cd->GetAddress();
    std::cout << macAddr.str()<<std::endl;
    macAddr.str(std::string());








//     csmaNodes.Get (i)->RegisterProtocolHandler (MakeCallback (&TrafficControlLayer::Receive, tc1),
//                                        Ipv4L3Protocol::PROT_NUMBER, nd);
//     csmaNodes.Get (i)->RegisterProtocolHandler (MakeCallback (&TrafficControlLayer::Receive, tc1),
//                                        ArpL3Protocol::PROT_NUMBER, nd);
//
//     //tc1 ->RegisterProtocolHandler (MakeCallback (&Ipv4L3Protocol::Receive, tc1),
//     //                               Ipv4L3Protocol::PROT_NUMBER, nd);
//     tc1 ->RegisterProtocolHandler (MakeCallback (&ArpL3Protocol::Receive, PeekPointer (csmaNodes.Get (i)->GetObject<ArpL3Protocol> ())),
//                                    ArpL3Protocol::PROT_NUMBER, nd);
//     tc1->SetNode(csmaNodes.Get (i));
     //csmaNodes.Get (i)->GetObject<ArpL3Protocol> ()->SetTrafficControl(csmaNodes.Get (i)->GetObject<TrafficControlLayer> ());
  }



  Ipv4AddressHelper address;
  address.SetBase ("10.1.1.0", "255.255.255.0");
  Ipv4InterfaceContainer csmaInterfaces;
  csmaInterfaces = address.Assign (csmaDevices);
  
  // get IPV4 interface for the attacker
  std::pair<Ptr<Ipv4>, uint32_t> returnValue = csmaInterfaces.Get (attackerId);
  Ptr<Ipv4> ipv4 = returnValue.first;
  uint32_t index = returnValue.second;
  Ptr<Ipv4Interface> iface =  ipv4->GetObject<Ipv4L3Protocol> ()->GetInterface (index);

  std::pair<Ptr<Ipv4>, uint32_t> returnValue2 = csmaInterfaces.Get (victimId);
   Ptr<Ipv4> ipv42 = returnValue2.first;
   uint32_t index2 = returnValue2.second;
   Ptr<Ipv4Interface> iface2 =  ipv42->GetObject<Ipv4L3Protocol> ()->GetInterface (index2);


  //construct attacker app
  Ptr<AttackApp> attacker = CreateObject<AttackApp> ();
  attacker->Setup(csmaNodes.Get(attackerId), csmaDevices.Get(attackerId), iface, csmaInterfaces.GetAddress(serverId), csmaInterfaces.GetAddress(victimId), victimAddr);
  csmaNodes.Get (attackerId)->AddApplication (attacker);
  attacker->SetStartTime (MilliSeconds (serverStart + delayT ));
  attacker->SetStopTime (MilliSeconds (stopTime));
  
  UdpServerHelper serverAttacker (port);
    ApplicationContainer appsAttack = serverAttacker.Install (csmaNodes.Get (attackerId));
   // Ipv4Address sourceAddr = csmaInterfaces.GetAddress(serverId);
    appsAttack.Start (MilliSeconds (serverStart + delayT));
    appsAttack.Stop (MilliSeconds (stopTime));

  UdpServerHelper server (port);
  ApplicationContainer apps = server.Install (csmaNodes.Get (serverId));
  Ipv4Address sourceAddr = csmaInterfaces.GetAddress(serverId);
  apps.Start (MilliSeconds (serverStart + delayT));
  apps.Stop (MilliSeconds (stopTime));

  uint32_t maxPacketCount = nPackets;
  UdpClientHelper client (sourceAddr, port);
  client.SetAttribute ("MaxPackets", UintegerValue (maxPacketCount));
  client.SetAttribute ("Interval", TimeValue (MilliSeconds (packetInt)));
  client.SetAttribute ("PacketSize", UintegerValue (MaxPacketSize));
  apps = client.Install (csmaNodes.Get (victimId));
  apps.Start (MilliSeconds (clientStart + delayT));
  apps.Stop (MilliSeconds (stopTime));
  Ptr<OutputStreamWrapper> routingStream = Create<OutputStreamWrapper> (&std::cout);
  Ipv4GlobalRoutingHelper::PopulateRoutingTables ();
  Ptr< ArpCache > cache0 = iface2->GetArpCache();
  Simulator::Schedule (MilliSeconds ((clientStart) + (8*packetInt) + (10*propDelay)), &ArpCache::PrintArpCache,cache0,routingStream);
  csma.EnablePcapAll("arp1"); 
  AnimationInterface anim("arp1");
    anim.EnablePacketMetadata (true);
    anim.SetConstantPosition (csmaNodes.Get (0), 10 , 10);
	anim.UpdateNodeDescription(csmaNodes.Get (0),"Client");
	anim.SetConstantPosition (csmaNodes.Get (serverId), 5 , 10);
  	anim.UpdateNodeDescription(csmaNodes.Get (serverId),"Server");
  	anim.SetConstantPosition (csmaNodes.Get (attackerId), 10 , 5);
  	anim.UpdateNodeDescription(csmaNodes.Get (attackerId),"Attacker");
  	anim.SetStartTime (MilliSeconds (0.0));
  	  anim.SetStopTime (MilliSeconds (stopTime));
  Simulator::Run ();
  Simulator::Destroy ();
return 0;
}
