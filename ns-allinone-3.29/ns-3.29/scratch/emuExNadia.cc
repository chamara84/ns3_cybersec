

#include <fstream>
#include "ns3/core-module.h"
#include "ns3/internet-module.h"
#include "ns3/applications-module.h"
#include "ns3/fd-net-device-module.h"
#include "ns3/string.h"

#include <cstring>


#define DDOS_RATE "1Mb/s"

using namespace ns3;


NS_LOG_COMPONENT_DEFINE ("EmulatedUdpEchoExample");


    Ptr<Socket> socketSend ;


void sendhandler (Ptr<Socket> socket,Ptr<Packet> pkt )
{
  std::cout << "Sending" << std::endl;
  socket->Send(pkt);
  Simulator::Schedule(Seconds(1), &sendhandler,socket,pkt);
}


static void
SocketPrinter2 (Ptr<Socket> socket) //print traffic from GTNET-Master and send to n1 (192.16.29.90)
{
  Ptr<Packet> packet;
  while ((packet = socket->Recv ()))
    {

    std::cout << "at=" << Simulator::Now ().GetSeconds () << "s, rx bytes=" << packet->GetSize () << std::endl;
     uint8_t buffer[packet->GetSize ()] ;
    //uint8_t *buffer = new uint8_t[packet->GetSize ()];
    packet->CopyData(buffer, packet->GetSize ());
    //packet= packet->Copy();
    for ( uint8_t  i=0; i< packet->GetSize (); i++)
    {

    std::cout << *(buffer+i);

    }

    socket->Connect (InetSocketAddress (Ipv4Address("172.16.29.221"), 7775));
      Ptr<Packet> packetNew = Create<Packet>(buffer,packet->GetSize ());
      	       socket->Send(packetNew);

      //sendhandler(socket,packet);

     printf("\n");

    }



}

static void
SocketPrinter1 (Ptr<Socket> socket)// print traffic from n2 and send to relay2 at GTNET-Slave (IP: 172.16.29.8)
{
  Ptr<Packet> packet;


  while ((packet = socket->Recv ()))
    {
    //NS_LOG_INFO(" Received a Packet of size:" << packet->GetSize() << " at time " << Now().GetSeconds());
    //NS_LOG_INFO(packet->ToString());
    std::cout << "at=" << Simulator::Now ().GetSeconds () << "s, rx bytes=" << packet->GetSize () << std::endl;
     uint8_t buffer[packet->GetSize ()] ;
    //uint8_t *buffer = new uint8_t[packet->GetSize ()];
    packet->CopyData(buffer, packet->GetSize ());
    //packet= packet->Copy();
    for ( uint8_t  i=0; i< packet->GetSize (); i++)
    {

    std::cout << *(buffer+i);

    }

     printf("\n");


     socket->Connect (InetSocketAddress (Ipv4Address("172.16.29.8"), 7775));
           Ptr<Packet> packetNew = Create<Packet>(buffer,packet->GetSize ());
           socket->Send(packetNew);

    }


   //sendhandler(socket,packet);

}








int main (int argc, char *argv[])
{

  PacketMetadata::Enable ();

  std::string deviceName1 ("enx806d971a885f");
  std::string deviceName ("enp0s31f6");
  std::string encapMode ("Dix");

  uint32_t nNodes = 1;
  //std::string localGateway ("172.16.29.1");
  std::string localAddress ("172.16.29.99");
  std::string localAddress1 ("172.16.29.221");
  Ipv4Address localIp1 (localAddress.c_str ());
  Ipv4Address localIp2 (localAddress1.c_str ());
  Ipv4Mask localMask ("255.255.255.0");
  std::string intMAC[2];
  	  	  intMAC[0]="80:e8:2c:28:9e:8f";
  	  	  intMAC[1] ="80:6d:97:1a:88:5f" ;

  //cmd.Parse (argc, argv);

  GlobalValue::Bind ("SimulatorImplementationType",
                     StringValue ("ns3::RealtimeSimulatorImpl"));

  GlobalValue::Bind ("ChecksumEnabled", BooleanValue (true));


 // Creating the ns3 node

  NodeContainer n1;  // The first emulated node
  n1.Create (nNodes);

  NodeContainer n2; //the second emulated node
  n2.Create (nNodes);


  NodeContainer LANnodes;
  //= NodeContainer(n1,n2);

  LANnodes.Add(n1.Get(0));
  LANnodes.Add(n2.Get(0));

   //Ptr<Node> n = CreateObject<Node> ();
   //Ptr<Node> n1 = CreateObject<Node> ();

  // Adding internet stacks

  InternetStackHelper internet;
  internet.Install (n1);
  internet.Install (n2);


  //EmuHelper emu;
        EmuFdNetDeviceHelper emu1;
        //emu.SetAttribute ("deviceName", StringValue (deviceName));
          emu1.SetDeviceName (deviceName);
          emu1.SetAttribute ("EncapsulationMode", StringValue (encapMode));

    // installing Fdemunetdevice on the node

          NetDeviceContainer d1 = emu1.Install (n1.Get(0));
          Ptr<FdNetDevice> dev1 = d1.Get (0)->GetObject<FdNetDevice> ();
                              dev1->SetAddress (Mac48Address (intMAC[0].c_str()));
                              NS_LOG_INFO ("Assign IP Address of EMU interface1.");
                              Ipv4AddressHelper addr1;
                                    addr1.SetBase ("172.16.29.0", "255.255.255.0", "0.0.0.99");
                              Ipv4InterfaceContainer     i1 = addr1.Assign (d1); //IP address for node n3 with emulation

                              dev1->Initialize();
          //d.Get(0)->SetFileDescriptor (fd);

  //EmuHelper emu1;
        EmuFdNetDeviceHelper emu2;
        //emu.SetAttribute ("deviceName", StringValue (deviceName));
          emu2.SetDeviceName (deviceName1);
          emu2.SetAttribute ("EncapsulationMode", StringValue (encapMode));

    // installing Fdemunetdevice on the node

          NetDeviceContainer d2 = emu2.Install (n2.Get(0));
       //   d2.Get(0)->SetAttribute ("Address", Mac48AddressValue (Mac48Address::Allocate ()));
          //d.Get(0)->SetFileDescriptor (fd);

          Ptr<FdNetDevice> dev2 = d2.Get (0)->GetObject<FdNetDevice> ();
                     dev2->SetAddress (Mac48Address (intMAC[1].c_str()));
                     NS_LOG_INFO ("Assign IP Address of EMU interface2.");
                     Ipv4AddressHelper addr2;
                           addr2.SetBase ("172.16.29.0", "255.255.255.0", "0.0.0.221");
                     Ipv4InterfaceContainer     i2 = addr2.Assign (d2); //IP address for node n3 with emulation

                     dev2->Initialize();

  //Assign IP  to the ns3 node n1
//  NS_LOG_INFO ("Create IPv4 Interface");
//  Ptr<Ipv4> ipv4 = n1.Get(0)->GetObject<Ipv4> ();
//  uint32_t interface1 = ipv4->AddInterface (d1.Get(0));
//  Ipv4InterfaceAddress address = Ipv4InterfaceAddress (localIp1 , localMask);
//  ipv4->AddAddress (interface1, address);
//  ipv4->SetMetric (interface1, 1);
//  ipv4->SetUp (interface1);
//
//
//  //Assign IP  to the ns3 node n2
//  NS_LOG_INFO ("Create IPv4 Interface");
//  Ptr<Ipv4> ipvv4 = n2.Get(0)->GetObject<Ipv4> ();
//  uint32_t interface2 = ipvv4->AddInterface (d2.Get(0));
//  Ipv4InterfaceAddress address1 = Ipv4InterfaceAddress (localIp2 , localMask);
//  ipvv4->AddAddress (interface2, address1);
//  ipvv4->SetMetric (interface2, 1);
//  ipvv4->SetUp (interface2);



  //Create a p2p link between n1 and n2

      PointToPointHelper p2p;
      p2p.SetDeviceAttribute ("DataRate", StringValue ("100Mbps"));
      p2p.SetChannelAttribute ("Delay",  TimeValue (NanoSeconds (656)));


      NetDeviceContainer LANdevices = p2p.Install (LANnodes);


      Ipv4AddressHelper addr;
      addr.SetBase ("172.16.30.0", "255.255.255.252");
      //addr.Assign (LANdevices);

      Ipv4InterfaceContainer LANInterfaces;
      LANInterfaces = addr.Assign (LANdevices);




  Ipv4StaticRoutingHelper ipv4RoutingHelper;

//  Ptr<Ipv4> ipv4n2 =n2.Get(0)->GetObject<Ipv4>();
//  Ptr<Ipv4StaticRouting> staticn2 = ipv4RoutingHelper.GetStaticRouting (ipv4n2);
//
//  staticn2->AddNetworkRouteTo (Ipv4Address ("172.24.0.0"), Ipv4Mask ("255.255.0.0"),2,10);
//   // staticn2->SetDefaultRoute(Ipv4Address ("172.16.29.40"),2,0);
//
//
  Ptr<Ipv4> ipv4n1 =n1.Get(0)->GetObject<Ipv4>();
  Ptr<Ipv4StaticRouting> staticn1 = ipv4RoutingHelper.GetStaticRouting (ipv4n1);
  //staticn1->AddHostRouteTo (Ipv4Address ("172.24.9.167"),Ipv4Address ("172.24.2.205"),2,10);
 staticn1->AddNetworkRouteTo (Ipv4Address ("172.16.29.0"), Ipv4Mask ("255.255.255.0"),3,10);
  //staticn1->SetDefaultRoute(Ipv4Address ("172.16.29.19"),1,0);

  Ipv4GlobalRoutingHelper::PopulateRoutingTables ();
            //Print Routin Table

//            Ptr<OutputStreamWrapper> routingStream = Create<OutputStreamWrapper> (&std::cout);
//            std::cout<<"Routing Table n1"<<std::endl;
//            ipv4RoutingHelper.PrintRoutingTableAt(Seconds(1), n1.Get (0), routingStream);
//            std::cout<<"Routing Table n2"<<std::endl;
//            ipv4RoutingHelper.PrintRoutingTableAt(Seconds(1), n2.Get (0), routingStream);


  // Associate socket2 to the node n2 to listen to the traffic coming from GTNET-Master

  Ptr<SocketFactory> socketFactory = n1.Get(0)->GetObject<UdpSocketFactory> ();
  Ptr<Socket> socket1  = socketFactory->CreateSocket ();
  socket1->Bind (InetSocketAddress (localIp1, 7001));  //53330
  socket1->SetRecvCallback (MakeCallback (&SocketPrinter2));



    // Associate socket1 to node n1 to listen to the traffic coming from node n2

  Ptr<SocketFactory> socketFactory2 = n2.Get(0)->GetObject<UdpSocketFactory> ();
  Ptr<Socket> socket2  = socketFactory2->CreateSocket ();
  socket2->Bind (InetSocketAddress ( localIp2, 7775));  //53330
  socket2->SetRecvCallback (MakeCallback (&SocketPrinter1));

//  Ptr<SocketFactory> socketFactorySend = n2.Get(0)->GetObject<UdpSocketFactory> ();
//     socketSend  = socketFactorySend->CreateSocket ();
//      socketSend->Bind (InetSocketAddress (localIp2, 7001));  //53330


  //LANInterfaces.GetAddress(0)


  emu2.EnablePcapAll ("emuex2", true);
  emu2.EnableAsciiAll ("emuex2.tr");
  emu1.EnablePcapAll ("emuex1", true);
    emu1.EnableAsciiAll ("emuex1.tr");
    p2p.EnablePcapAll("p2p", true);

  //
  // Now, do the actual simulation.
  //
  NS_LOG_INFO ("Run Simulation.");
  Simulator::Stop (Seconds (1000));
  Simulator::Run ();

  //std::cout << "Number of packets received:" << packetsreceived << std::endl;
  Simulator::Destroy ();
  NS_LOG_INFO ("Done.");


}





