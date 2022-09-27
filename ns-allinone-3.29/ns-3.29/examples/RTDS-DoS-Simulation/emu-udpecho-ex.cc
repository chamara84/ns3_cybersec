

#include <fstream>
#include "ns3/core-module.h"
#include "ns3/internet-module.h"
#include "ns3/applications-module.h"
#include "ns3/fd-net-device-module.h"

#define DDOS_RATE "1Mb/s"

using namespace ns3;


NS_LOG_COMPONENT_DEFINE ("EmulatedUdpEchoExample");

/*void SendStuff (Ptr<Socket> sock, Ipv4Address dstaddr, uint16_t port)
{
  NS_LOG_INFO ("SendStuff () called ...");
  Ptr<Packet> p = Create<Packet> (reinterpret_cast<uint8_t const *> ("I am long 20 bytes!"), 20);
  p->AddPaddingAtEnd (100);
  sock->SendTo (p, 0, InetSocketAddress (dstaddr,port));
  return;
}*/



static void 
SocketPrinter (Ptr<Socket> socket)
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
     

    
   
    }
    
    
     
}

void sendhandler (Ptr<Socket> socket,Ptr<Packet> pkt )
{
  std::cout << "Sending" << std::endl;
  socket->Send(pkt);
  Simulator::Schedule(Seconds(1), &sendhandler,socket,pkt);
}


int
main (int argc, char *argv[])
{

  PacketMetadata::Enable ();
  std::string deviceName ("enp4s0");
  std::string encapMode ("Dix");
  //bool clientMode = false;
 // bool serverMode = false;
  //double stopTime = 10;
  uint32_t nNodes = 1;
  //uint32_t packetsreceived = 0;

  //
  // Allow the user to override any of the defaults at run-time, via command-line
  // arguments
  //
 // CommandLine cmd (__FILE__);
  //cmd.AddValue ("client", "client mode", clientMode);
  //cmd.AddValue ("server", "server mode", serverMode);
  //cmd.AddValue ("deviceName", "device name", deviceName);
  //cmd.AddValue ("stopTime", "stop time (seconds)", stopTime);
 // cmd.AddValue ("encapsulationMode", "encapsulation mode of emu device (\"Dix\" [default] or \"Llc\")", encapMode);
 // cmd.AddValue ("nNodes", "number of nodes to create (>= 2)", nNodes);
  

  std::string remote ("172.24.2.62");
  Ipv4Address remoteIp (remote.c_str ());
  std::string localAddress ("172.24.2.178");
  std::string localGateway ("172.24.0.1");
  Ipv4Address localIp (localAddress.c_str ());
  Ipv4Mask localMask ("255.255.0.0");

  //cmd.Parse (argc, argv);

  GlobalValue::Bind ("SimulatorImplementationType",
                     StringValue ("ns3::RealtimeSimulatorImpl"));

  GlobalValue::Bind ("ChecksumEnabled", BooleanValue (true));
  

 // Creating the ns3 node
 
  NodeContainer n;
  n.Create (nNodes);
  
 
  
  // Adding internet stacks
  
  InternetStackHelper internet;
  internet.Install (n);
  
  
  //EmuHelper emu;
        EmuFdNetDeviceHelper emu;
        //emu.SetAttribute ("deviceName", StringValue (deviceName));
          emu.SetDeviceName (deviceName);
          emu.SetAttribute ("EncapsulationMode", StringValue (encapMode));
 
    // installing Fdemunetdevice on the node
  
          NetDeviceContainer d = emu.Install (n);
          d.Get(0)->SetAttribute ("Address", Mac48AddressValue (Mac48Address::Allocate ()));
          //d.Get(0)->SetFileDescriptor (fd);
        

   
   
  //Assign IP 192.168.1.3 to the ns3 node
  NS_LOG_INFO ("Create IPv4 Interface");
  Ptr<Ipv4> ipv4 = n.Get(0)->GetObject<Ipv4> ();
  uint32_t interface = ipv4->AddInterface (d.Get(0));
  Ipv4InterfaceAddress address = Ipv4InterfaceAddress (localIp , localMask);
  ipv4->AddAddress (interface, address);
  ipv4->SetMetric (interface, 1);
  ipv4->SetUp (interface);
  
  
  //Routing through the gateway
  
  Ipv4Address gateway (localGateway.c_str ());
  Ipv4StaticRoutingHelper ipv4RoutingHelper;
  Ptr<Ipv4StaticRouting> staticRouting = ipv4RoutingHelper.GetStaticRouting (ipv4);
  staticRouting->SetDefaultRoute (gateway, interface);

  
  
  // Create onoff application

  /*OnOffHelper onoff("ns3::UdpSocketFactory", Address(InetSocketAddress(remoteIp, 9001)));
  onoff.SetConstantRate(DataRate(DDOS_RATE));
  onoff.SetAttribute("OnTime", StringValue("ns3::ConstantRandomVariable[Constant=20]"));
  onoff.SetAttribute("OffTime", StringValue("ns3::ConstantRandomVariable[Constant=0]"));
//ApplicationContainer onOffApp;
  ApplicationContainer onoffapp=onoff.Install(n.Get(0)); //Installing the onoff Appication on node 0
  onoffapp.Start(Seconds(1));
  onoffapp.Stop(Seconds(30));*/
  
  
  
  // When the packets are received 
  
  Ptr<SocketFactory> socketFactory = n.Get(0)->GetObject<UdpSocketFactory> ();
  Ptr<Socket> socket  = socketFactory->CreateSocket ();
  //socket->Bind (InetSocketAddress (Ipv4Address::GetAny (), 80));
  //socket->Connect (InetSocketAddress (remoteIp, 53330));
  //socket->Bind (InetSocketAddress (localIp);
  socket->Bind (InetSocketAddress (localIp, 53330));  //53330

  //Packet::EnablePrinting();

  socket->SetRecvCallback (MakeCallback (&SocketPrinter));
  
  
  
  // Here I create the packet I want to send to windows machine 192.168.1.2
  Ptr<Packet> pkt = Create<Packet> (reinterpret_cast<const uint8_t*> ("hello"), 6);
  socket->Connect (InetSocketAddress (remoteIp, 2000));

  Simulator::Schedule(Seconds(1), &sendhandler,socket,pkt);
  
  
  
  emu.EnablePcapAll ("fd-emu-udp-echo", true);
  emu.EnableAsciiAll ("fd-emu-udp-echo.tr");


  //
  // Now, do the actual simulation.
  //
  NS_LOG_INFO ("Run Simulation.");
  Simulator::Stop (Seconds (30));
  Simulator::Run ();
  
  //std::cout << "Number of packets received:" << packetsreceived << std::endl;
  Simulator::Destroy ();
  NS_LOG_INFO ("Done.");
}



