#include <iomanip>
#include "ns3/command-line.h"
#include "ns3/config.h"
#include "ns3/uinteger.h"
#include "ns3/boolean.h"
#include "ns3/double.h"
#include "ns3/string.h"
#include "ns3/log.h"
#include "ns3/yans-wifi-helper.h"
#include "ns3/spectrum-wifi-helper.h"
#include "ns3/ssid.h"
#include "ns3/mobility-helper.h"
#include "ns3/internet-stack-helper.h"
#include "ns3/ipv4-address-helper.h"
#include "ns3/udp-client-server-helper.h"
#include "ns3/yans-wifi-channel.h"
#include "ns3/multi-model-spectrum-channel.h"
#include "ns3/propagation-loss-model.h"
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
#include "ns3/animation-interface.h"
#include "ns3/data-rate.h"
#include "ns3/udp-socket-factory.h"
#include "ns3/packet-sink-helper.h"
#include "ns3/ipv4-global-routing-helper.h"


using namespace ns3;
using namespace std;

class MyApp : public Application
{
public:

  MyApp ();
  virtual ~MyApp();

  void Setup (Ptr<Node> node,Address raddress, Address address, uint32_t packetSize, uint32_t nPackets, DataRate dataRate);

private:
  virtual void StartApplication (void);
  virtual void StopApplication (void);

  void ScheduleTx (void);
  void SendPacket (void);
  void ReceivePacket (Ptr<Socket>);

  Ptr<Socket>     m_socket;
  Ptr<Socket>     m_rsocket;
  Address         m_peer;
  uint32_t        m_packetSize;
  uint32_t        m_nPackets;
  DataRate        m_dataRate;
  EventId         m_Event;
  bool            m_running;
  uint32_t        m_packetsReceived;
  uint32_t        m_packetsSent;
  Ptr<Packet>     m_spacket;
  Ptr<Packet>     m_rpacket;
  uint8_t*        rxPayload;
  Address         m_raddress;
  Ptr<Node>            node;
};

MyApp::MyApp ()
  : m_socket (0),
    m_peer (),
    m_packetSize (0),
    m_nPackets (0),
    m_dataRate (0),
    m_Event (),
    m_running (false),
    m_packetsSent (0)
{
}

MyApp::~MyApp()
{
  m_socket = 0;
}

void
MyApp::Setup (Ptr<Node> node,Address raddress ,Address address, uint32_t packetSize, uint32_t nPackets, DataRate dataRate)
{
  //m_socket = socket;
  this->node=node;
  m_peer = address;
  m_packetSize = packetSize;
  m_nPackets = nPackets;
  m_dataRate = dataRate;
  m_raddress=raddress;
  //Socket::CreateSocket (nodes.Get (0), UdpSocketFactory::GetTypeId ())
}

void
MyApp::StartApplication (void)
{
  m_socket = Socket::CreateSocket (node, UdpSocketFactory::GetTypeId ());
  m_running = true;
  m_packetsSent = 0;
  m_packetsReceived=0;
  m_socket->Bind ();

  Ptr<SocketFactory> sockFactory = node->GetObject<UdpSocketFactory> ();
  m_rsocket=sockFactory->CreateSocket ();
  m_rsocket->Bind (InetSocketAddress (Ipv4Address::GetAny (), 8085));

  m_rsocket->Connect (m_peer);
  m_socket->Connect (m_peer);
    m_socket->SetRecvCallback (MakeCallback(&MyApp::ReceivePacket,this));
     m_rsocket->SetRecvCallback (MakeCallback(&MyApp::ReceivePacket,this));
  SendPacket ();
}

void
MyApp::StopApplication (void)
{
  m_running = false;

  if (m_Event.IsRunning ())
    {
      Simulator::Cancel (m_Event);
    }

  if (m_socket)
    {
      m_socket->Close ();
    }
}
void
MyApp::SendPacket (void)
{
  std::stringstream msg;//msg2;

  msg << "My pay load is my payload";
  m_packetSize=msg.str ().length ();
  m_spacket = Create<Packet> ((uint8_t*) msg.str().c_str(), msg.str().length());

  uint8_t *buffer = new uint8_t  [m_spacket->GetSize ()];
  memset(buffer, 0, m_spacket->GetSize () +1);
  m_spacket->CopyData (buffer, m_spacket->GetSize ());

  std::cout<<m_packetsReceived<< "\n";
  if(m_packetsReceived>0)std::cout<<"received payload:"<<rxPayload;
  m_socket->Send (m_spacket);
  if (++m_packetsSent < m_nPackets)
    {
      ScheduleTx ();
    }
}

void
MyApp::ReceivePacket (Ptr<Socket> socket)
{

  //uint32_t availableData;
  //availableData = socket->GetRxAvailable ();
  ++m_packetsReceived;
  m_rpacket = socket->Recv (std::numeric_limits<uint32_t>::max (), 0);


    rxPayload = new uint8_t  [m_rpacket->GetSize ()];
   memset(rxPayload, 0, m_packetSize );

   m_rpacket->CopyData (rxPayload, m_rpacket->GetSize ());
}

void
MyApp::ScheduleTx (void)
{
  if (m_running)
    {
      Time tNext (Seconds (m_packetSize * 8 / static_cast<double> (m_dataRate.GetBitRate ())));
      m_Event = Simulator::Schedule (tNext, &MyApp::SendPacket, this);

    }
}


int
main (int argc, char *argv[])
{
  NodeContainer wifiStaNodes;
  wifiStaNodes.Create (1);
  NodeContainer wifiApNode;
  wifiApNode.Create (1);

  YansWifiChannelHelper channel = YansWifiChannelHelper::Default ();
  YansWifiPhyHelper phy = YansWifiPhyHelper::Default ();
  phy.SetChannel (channel.Create ());

  WifiHelper wifi;
  wifi.SetRemoteStationManager ("ns3::AarfWifiManager");

  WifiMacHelper mac;
  Ssid ssid = Ssid ("ns-3-ssid");
  mac.SetType ("ns3::StaWifiMac",
               "Ssid", SsidValue (ssid),
               "ActiveProbing", BooleanValue (false));

  NetDeviceContainer staDevices;
  staDevices = wifi.Install (phy, mac, wifiStaNodes);

  mac.SetType ("ns3::ApWifiMac",
               "Ssid", SsidValue (ssid));

  NetDeviceContainer apDevices;
  apDevices = wifi.Install (phy, mac, wifiApNode);

  NodeContainer nodes;
  nodes.Add (wifiStaNodes);
  nodes.Add (wifiApNode);

  NetDeviceContainer devices;
  devices.Add (staDevices);
  devices.Add (apDevices);

  MobilityHelper mobility;

  mobility.SetMobilityModel ("ns3::SteadyStateRandomWaypointMobilityModel",
                             "MinSpeed",DoubleValue (5.0),"MaxSpeed",DoubleValue (10.0),
                             "MinPause",DoubleValue (0.04),"MaxPause",DoubleValue (0.04),
                             "MinX", DoubleValue (0.0),"MaxX", DoubleValue (20.0),
                             "MinY", DoubleValue (0.0),"MaxY", DoubleValue (20.0));

  mobility.Install (nodes);

  /*Ptr<RateErrorModel> em = CreateObject<RateErrorModel> ();
  em->SetAttribute ("ErrorRate", DoubleValue (0.00001));
  devices.Get (1)->SetAttribute ("ReceiveListErrorModel", PointerValue (em));
*/

  InternetStackHelper stack;
  stack.Install (nodes);

  Ipv4AddressHelper address;
  address.SetBase ("10.1.1.0", "255.255.255.252");
  Ipv4InterfaceContainer interfaces = address.Assign (devices);
  //address.Assign (apDevices);

  Ipv4GlobalRoutingHelper::PopulateRoutingTables ();

  //device 0 is sta and device 1 is ap

  PacketSinkHelper packetSinkHelper ("ns3::UdpSocketFactory", InetSocketAddress (Ipv4Address::GetAny (), 8080));
  ApplicationContainer sinkApps = packetSinkHelper.Install (nodes.Get (0));
  sinkApps.Start (Seconds (0.));
  sinkApps.Stop (Seconds (20.));

  PacketSinkHelper packetSinkHelper2 ("ns3::UdpSocketFactory", InetSocketAddress (Ipv4Address::GetAny (), 8085));
  ApplicationContainer sinkApps2 = packetSinkHelper2.Install (nodes.Get (1));
  sinkApps2.Start (Seconds (0.));
  sinkApps2.Stop (Seconds (20.));

  Ptr<MyApp> app = CreateObject<MyApp> ();
  app->Setup (nodes.Get(1),InetSocketAddress (interfaces.GetAddress (1), 8085),InetSocketAddress (interfaces.GetAddress (0), 49153), 1040, 5, DataRate ("1Mbps"));
  nodes.Get (1)->AddApplication (app);
  app->SetStartTime (Seconds (1.));
  app->SetStopTime (Seconds (20.));

  Ptr<MyApp> app2 = CreateObject<MyApp> ();
  app2->Setup (nodes.Get(0),InetSocketAddress (interfaces.GetAddress (0),8080), InetSocketAddress (interfaces.GetAddress (1), 49153), 1040, 5, DataRate ("1Mbps"));
  nodes.Get (0)->AddApplication (app2);
  app2->SetStartTime (Seconds (1.));
  app2->SetStopTime (Seconds (20.));

  AnimationInterface anim("test.xml");
  anim.EnablePacketMetadata (true);

  Simulator::Stop (Seconds (5));
  Simulator::Run ();
  Simulator::Destroy ();

  return 0;
}

