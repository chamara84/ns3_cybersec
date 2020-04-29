/* -*-  Mode: C++; c-file-style: "gnu"; indent-tabs-mode:nil; -*- */
/*
 * Copyright (c) 2009 Strasbourg University
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
 *
 * Author: David Gross <gdavid.devel@gmail.com>
 */

// Network topology
//
//             STA2
//              |
//              |
//   R1         R2
//   |          |
//   |          |
//   ------------
//           |
//           |
//          STA 1
//
// - Initial configuration :
//         - STA1 default route : R1
//         - R1 static route to STA2 : R2
//         - STA2 default route : R2
// - STA1 send Echo Request to STA2 using its default route to R1
// - R1 receive Echo Request from STA1, and forward it to R2
// - R1 send an ICMPv6 Redirection to STA1 with Target STA2 and Destination R2
// - Next Echo Request from STA1 to STA2 are directly sent to R2

#include <fstream>
#include "ns3/core-module.h"
#include "ns3/internet-module.h"
#include "ns3/csma-module.h"
#include "ns3/internet-apps-module.h"
#include "ns3/on-off-helper.h"
#include "ns3/applications-module.h"



using namespace ns3;

NS_LOG_COMPONENT_DEFINE ("Icmpv4RedirectExample");

int main (int argc, char **argv)
{
  bool verbose = false;

  CommandLine cmd;
  cmd.AddValue ("verbose", "turn on log components", verbose);
  cmd.Parse (argc, argv);

  if (verbose)
    {
      LogComponentEnable ("Icmpv4RedirectExample", LOG_LEVEL_INFO);
      LogComponentEnable ("Icmpv4L4Protocol", LOG_LEVEL_INFO);
      LogComponentEnable ("Ipv4L3Protocol", LOG_LEVEL_ALL);
      LogComponentEnable ("Ipv4StaticRouting", LOG_LEVEL_ALL);
      LogComponentEnable ("Ipv4Interface", LOG_LEVEL_ALL);
      LogComponentEnable ("Icmpv4L4Protocol", LOG_LEVEL_ALL);
      LogComponentEnable ("NdiscCache", LOG_LEVEL_ALL);
    }

  NS_LOG_INFO ("Create nodes.");
  Ptr<Node> sta1 = CreateObject<Node> ();
  Ptr<Node> r1 = CreateObject<Node> ();
  Ptr<Node> r2 = CreateObject<Node> ();
  Ptr<Node> sta2 = CreateObject<Node> ();
  NodeContainer net1 (sta1, r1, r2);
  NodeContainer net2 (r2, sta2);
  NodeContainer all (sta1, r1, r2, sta2);

  InternetStackHelper internetv4;
  internetv4.SetIpv6StackInstall(false);
  internetv4.Install (all);

  NS_LOG_INFO ("Create channels.");
  CsmaHelper csma;
  csma.SetChannelAttribute ("DataRate", DataRateValue (5000000));
  csma.SetChannelAttribute ("Delay", TimeValue (MilliSeconds (2)));
  NetDeviceContainer ndc1 = csma.Install (net1); 
  NetDeviceContainer ndc2 = csma.Install (net2);

  NS_LOG_INFO ("Assign IPv4 Addresses.");
  Ipv4AddressHelper ipv4;

  ipv4.SetBase ("10.1.1.0", "255.255.255.0");
  Ipv4InterfaceContainer iic1 = ipv4.Assign (ndc1);


  ipv4.SetBase ("10.1.2.0", "255.255.255.0");
  Ipv4InterfaceContainer iic2 = ipv4.Assign (ndc2);

  Ipv4GlobalRoutingHelper::PopulateRoutingTables ();

  Ipv4StaticRoutingHelper routingHelper;
//
//  // manually inject a static route to the second router.
  Ptr<Ipv4StaticRouting> routing = routingHelper.GetStaticRouting (r1->GetObject<Ipv4> ());
  //routing->AddHostRouteTo (Ipv4Address ("10.1.2.2"), Ipv4Address ("10.1.1.3"), 1);
//
 Ptr<Ipv4StaticRouting> routingSTA1 = routingHelper.GetStaticRouting (sta1->GetObject<Ipv4> ());
 routingSTA1->SetDefaultRoute(Ipv4Address("10.1.1.2"),1,0);
//
//    Ptr<Ipv4StaticRouting> routingSTA2 = routingHelper.GetStaticRouting (sta2->GetObject<Ipv4> ());
//        routingSTA2->SetDefaultRoute(Ipv4Address("10.1.2.1"),1,0);
//

  Ptr<OutputStreamWrapper> routingStream = Create<OutputStreamWrapper> (&std::cout);
  routingHelper.PrintRoutingTableAt (Seconds (3.0), r1, routingStream);
  routingHelper.PrintRoutingTableAt (Seconds (3.0), sta1, routingStream);
  routingHelper.PrintRoutingTableAt (Seconds (3.0), r2, routingStream);
    routingHelper.PrintRoutingTableAt (Seconds (3.0), sta1, routingStream);

  NS_LOG_INFO ("Create Applications.");
 // uint32_t packetSize = 1024;
  //uint32_t maxPacketCount = 5;
  Time interPacketInterval = Seconds (1.);
  uint16_t port = 7001;   // Discard port (RFC 863)
  OnOffHelper onoff ("ns3::UdpSocketFactory",
        Address (InetSocketAddress (Ipv4Address ("10.1.2.2"), port)));
        onoff.SetConstantRate (DataRate ("0.005Mbps"));

         //onoff.SetAttribute("OnTime", StringValue("ns3::ConstantRandomVariable[Constant=" + ON_TIME + "]"));
           //onoff.SetAttribute("OffTime", StringValue("ns3::ConstantRandomVariable[Constant=" + OFF_TIME + "]"));
         ApplicationContainer onOffapps = onoff.Install (sta1);
        onOffapps.Start (Seconds (2.0));
         onOffapps.Stop (Seconds (10.0));


           UdpServerHelper server (port);
           ApplicationContainer apps = server.Install (sta2);
           apps.Start (Seconds (1.0));
           apps.Stop (Seconds (10.0));


  AsciiTraceHelper ascii;
  csma.EnableAsciiAll (ascii.CreateFileStream ("icmpv4-redirect.tr"));
  csma.EnablePcapAll ("icmpv4-redirect", true);

  /* Now, do the actual simulation. */
  NS_LOG_INFO ("Run Simulation.");
  Simulator::Run ();
  Simulator::Destroy ();
  NS_LOG_INFO ("Done.");
}

