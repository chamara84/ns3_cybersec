/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * Copyright 2007 University of Washington
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

#include "ns3/log.h"
#include "ns3/ipv4-address.h"
#include "ns3/address-utils.h"
#include "ns3/nstime.h"
#include "ns3/inet-socket-address.h"
#include "ns3/socket.h"
#include "ns3/tcp-socket.h"
#include "ns3/simulator.h"
#include "ns3/socket-factory.h"
#include "ns3/packet.h"
#include "ns3/uinteger.h"
//#include "ns3/malicious-tag.h"
#include "tcp-echo-server.h"
#include "ns3/rtt-estimator.h"
#include "ns3/tcp-congestion-ops.h"
#include "ns3/tcp-recovery-ops.h"
#include "ns3/tcp-socket-base.h"
#include "ns3/tcp-l4-protocol.h"
#include "ns3/ipv4-address.h"
#include "ns3/internet-stack-helper.h"
#include <sys/socket.h>
#include <arpa/inet.h>

namespace ns3 {

NS_LOG_COMPONENT_DEFINE ("TcpEchoServerApplication");
NS_OBJECT_ENSURE_REGISTERED (TcpEchoServer);

NS_OBJECT_ENSURE_REGISTERED (TcpSocketMsgBase);

TypeId
TcpSocketMsgBase::GetTypeId (void)
{
  static TypeId tid = TypeId ("ns3::TcpSocketMsgBase")
    .SetParent<TcpSocketBase> ()
    .SetGroupName ("Internet")
    .AddConstructor<TcpSocketMsgBase> ()
  ;
  return tid;
}

Ptr<TcpSocketBase>
TcpSocketMsgBase::Fork (void)
{
  return CopyObject<TcpSocketMsgBase> (this);
}

void
TcpSocketMsgBase::SetRcvAckCb (AckManagementCb cb)
{
  NS_ASSERT (!cb.IsNull ());
  m_rcvAckCb = cb;
}



void
TcpSocketMsgBase::SetProcessedAckCb (AckManagementCb cb)
{
  NS_ASSERT (!cb.IsNull ());
  m_processedAckCb = cb;
}

void
TcpSocketMsgBase::SetAfterRetransmitCb (RetrCb cb)
{
  NS_ASSERT (!cb.IsNull ());
  m_afterRetrCallback = cb;
}

void
TcpSocketMsgBase::SetBeforeRetransmitCb (RetrCb cb)
{
  NS_ASSERT (!cb.IsNull ());
  m_beforeRetrCallback = cb;
}

void
TcpSocketMsgBase::ReceivedAck (const Ptr<Packet> packet, const TcpHeader& tcpHeader)
{

//  NS_ASSERT (!(m_rcvAckCb.IsNull () || m_processedAckCb.IsNull ()));
//  m_rcvAckCb (packet, tcpHeader, this);

  TcpSocketBase::ReceivedAck (packet, tcpHeader);

  //m_processedAckCb (packet, tcpHeader, this);
}

void
TcpSocketMsgBase::ReTxTimeout ()
{
  m_beforeRetrCallback (m_tcb, this);
  TcpSocketBase::ReTxTimeout ();
  m_afterRetrCallback (m_tcb, this);
}

void
TcpSocketMsgBase::SetForkCb (Callback<void, Ptr<TcpSocketMsgBase> > cb)
{
  NS_ASSERT (!cb.IsNull ());
  m_forkCb = cb;
}

void
TcpSocketMsgBase::SetUpdateRttHistoryCb (UpdateRttCallback cb)
{
  NS_ASSERT (!cb.IsNull ());
  m_updateRttCb = cb;
}

void
TcpSocketMsgBase::UpdateRttHistory (const SequenceNumber32 &seq, uint32_t sz,
                                    bool isRetransmission)
{
  TcpSocketBase::UpdateRttHistory (seq, sz, isRetransmission);
  if (!m_updateRttCb.IsNull ())
    {
      m_updateRttCb (this, seq, sz, isRetransmission);
    }
}

void
TcpSocketMsgBase::CompleteFork (Ptr<Packet> p, const TcpHeader &tcpHeader,
                                const Address &fromAddress, const Address &toAddress)
{
  TcpSocketBase::CompleteFork (p, tcpHeader, fromAddress, toAddress);

  if (!m_forkCb.IsNull ())
    {
      m_forkCb (this);
    }
}


TypeId
TcpEchoServer::GetTypeId (void)
{
  static TypeId tid = TypeId ("ns3::TcpEchoServer")
    .SetParent<Application> ()
    .AddConstructor<TcpEchoServer> ()
    .AddAttribute ("Local", "The Address on which to Bind the rx socket.",
                   Ipv4AddressValue(),
                   MakeIpv4AddressAccessor (&TcpEchoServer::m_local),
                   MakeIpv4AddressChecker ())
    .AddAttribute ("Port", "Port on which we listen for incoming packets.",
                   UintegerValue (9),
                   MakeUintegerAccessor (&TcpEchoServer::m_port),
                   MakeUintegerChecker<uint16_t> ())
  ;
  return tid;
}

TcpEchoServer::TcpEchoServer ()
{
  NS_LOG_FUNCTION_NOARGS ();
}

TcpEchoServer::~TcpEchoServer()
{
  NS_LOG_FUNCTION_NOARGS ();
  m_socket = 0;
}

void
TcpEchoServer::DoDispose (void)
{
  NS_LOG_FUNCTION_NOARGS ();
  Application::DoDispose ();
}
void
TcpEchoServer::SetRcvDataCb (ReceivedData cb)
{
  NS_ASSERT (!cb.IsNull ());
  m_receiveCb = cb;
}

void
TcpEchoServer::StartApplication (void)
{
  NS_LOG_FUNCTION_NOARGS ();

  if (m_socket == 0)
	{
	  ObjectFactory rttFactory;
	  ObjectFactory congestionAlgorithmFactory;
	  ObjectFactory recoveryAlgorithmFactory;
	  ObjectFactory socketFactory;

	  rttFactory.SetTypeId (RttMeanDeviation::GetTypeId ());
	  congestionAlgorithmFactory.SetTypeId (TcpNewReno::GetTypeId ());
	  recoveryAlgorithmFactory.SetTypeId (TcpClassicRecovery::GetTypeId ());
	  socketFactory.SetTypeId(TcpSocketMsgBase::GetTypeId ());

	  Ptr<RttEstimator> rtt = rttFactory.Create<RttEstimator> ();

	  //socket = DynamicCast<TcpSocketMsgBase> (Socket::CreateSocket (m_node, tid));
//	  TypeId tid = TypeId::LookupByName ("ns3::TcpSocketFactory");
//	  socket = DynamicCast<TcpSocketMsgBase> (Socket::CreateSocket (m_node, tid));
	  m_socket = DynamicCast<TcpSocketMsgBase> (socketFactory.Create ());
	  Ptr<TcpCongestionOps> algo = congestionAlgorithmFactory.Create<TcpCongestionOps> ();
	  Ptr<TcpRecoveryOps> recovery = recoveryAlgorithmFactory.Create<TcpRecoveryOps> ();
	  //TypeId tid = TypeId::LookupByName ("ns3::TcpSocketFactory");
	  //m_socket = DynamicCast<TcpSocketMsgBase> (Socket::CreateSocket (GetNode (), tid));
	  m_socket->SetNode (this->m_node);
	  m_socket->SetTcp (this->m_node->GetObject<TcpL4Protocol> ());
	  m_socket->SetRtt (rtt);
	  m_socket->SetCongestionControlAlgorithm (algo);
	  m_socket->SetRecoveryAlgorithm (recovery);

	  //socket->SetAttribute("RcvBufSize", ns3::UintegerValue(60000));
  	InetSocketAddress local = InetSocketAddress (m_local, m_port);
		Ptr<Ipv4> ipV4Info = this->m_node->GetObject<Ipv4>();
		int interfaceIndex = ipV4Info->GetInterfaceForAddress(m_local);
						std::cout<<"NetDev:"<<interfaceIndex;
						m_socket->BindToNetDevice(this->m_node->GetDevice(interfaceIndex));
		int res = m_socket->Bind (local);
		//socket->Initialize();
		m_socket->Listen();


		NS_LOG_INFO("Echo Server local address:  " << m_local << " port: " << m_port << " bind: " << res);
	}


//  TypeId tid = TypeId::LookupByName ("ns3::TcpSocketFactory");
//  const Ptr<TcpSocketBase>	  Tcpsocket =  Socket::CreateSocket (m_node, tid);
//   TcpHeader hdr;
//socket->SetRcvAckCb(MakeCallback(&TcpSocketBase::ReceivedAck,Tcpsocket), hdr,Tcpsocket);
 m_socket->SetRecvCallback (MakeCallback (&TcpEchoServer::HandleRead, this));
  m_socket->SetAcceptCallback (
    MakeCallback (&TcpEchoServer::HandleAcceptRequest, this),
    //MakeNullCallback<bool, Ptr<Socket>, const Address &> (),
    MakeCallback (&TcpEchoServer::HandleAccept, this));
  m_socket->SetCloseCallbacks(MakeCallback(&TcpEchoServer::HandleClose, this), MakeCallback(&TcpEchoServer::HandleClose, this));

}

void TcpEchoServer::HandleClose(Ptr<Socket> s1)
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
		s1=NULL;
	}
}

bool TcpEchoServer::HandleAcceptRequest (Ptr<Socket> s, const Address& from)
{
	NS_LOG_INFO(" HANDLE ACCEPT REQUEST FROM " <<  InetSocketAddress::ConvertFrom(from));

	return true;
}

void TcpEchoServer::HandleAccept (Ptr<Socket> s, const Address& from)
{
	NS_LOG_FUNCTION (this << s << from);
	NS_LOG_INFO("ACCEPT IN ECHO SERVER from " << InetSocketAddress::ConvertFrom(from).GetIpv4());
	s->SetRecvCallback (MakeCallback (&TcpEchoServer::HandleRead, this));

	// JCS: Something like this needs to happen here...
//	Ipv4Address dst = s->m_orgDestIP;
//	if (InetSocketAddress::ConvertFrom (from).GetIpv4 () == m_local) {
//		NS_LOG_INFO(" FROM MY TAP - set dest: " << dst);
//	} else {
//		dst = m_local;
//		NS_LOG_INFO(" FROM  OUTSIDE - set dest: " << dst);
//	}
//	NS_LOG_INFO("ORIGINAL DST: " << dst << " original src: " << s->m_srcNode);
//	NS_LOG_INFO("FROM: " << InetSocketAddress::ConvertFrom(from).GetIpv4());
//
//	//open other tcp connection...
//	Ptr<Socket> new_socket = Socket::CreateSocket(GetNode(), TypeId::LookupByName("ns3::TcpSocketFactory"));
//	if (InetSocketAddress::ConvertFrom (from).GetIpv4 () == m_local) {
//		new_socket->Bind(m_local);
//		//new_socket->Bind(InetSocketAddress(m_local, m_port));
//	} else {
//		NS_LOG_INFO("BIND WITH REMOTE ADDRESS\n");
//		//new_socket->Bind(from);
//		new_socket->Bind(InetSocketAddress::ConvertFrom (from).GetIpv4 () );
//	}
//	// let the socket know orginial source information
//	new_socket->m_orgSrcIP = InetSocketAddress::ConvertFrom(from).GetIpv4();
//	new_socket->m_orgSrcPort = InetSocketAddress::ConvertFrom(from).GetPort();
//	NS_LOG_INFO(" CONNECT TO " << dst << " : " << m_port);
//	new_socket->Connect(InetSocketAddress(dst, m_port));
//	new_socket->SetRecvCallback (MakeCallback (&TcpEchoServer::HandleRead, this));
//	//new_socket->SetRecvCallback (MakeCallback (&TcpEchoServer::HandleRead, this));
//	//should do something if it fails...
//
//
//	m_conn[new_socket] = dst;
//	m_conn[s] = InetSocketAddress::ConvertFrom(from).GetIpv4();
//	m_pair[s] = new_socket;
//	m_pair[new_socket] = s;
//	s->m_pair = new_socket;
//	new_socket->m_pair = s;
}

void
TcpEchoServer::StopApplication ()
{
  NS_LOG_FUNCTION_NOARGS ();

  if (m_socket != 0)
    {
      m_socket->Close ();
   //   m_socket->SetRecvCallback (MakeNullCallback<void, Ptr<Socket> > ());
    }
}

void TcpEchoServer::PrintPairs() {
	std::map<Ptr<Socket>, Ptr<Socket> >::iterator pi;
	NS_LOG_INFO("**********************************************************");
	for (pi = m_pair.begin(); pi != m_pair.end(); pi++) {
		NS_LOG_INFO(" [ " << (*pi).first << " ] -> [ " << (*pi).second << " ]");
	}
	std::map<Ptr<Socket>, Ipv4Address>::iterator ci;
	NS_LOG_INFO("**********************************************************");
	for (ci = m_conn.begin(); ci != m_conn.end(); ci++) {
		NS_LOG_INFO(" [ " << (*ci).first << " ] -> [ " << (*ci).second << " ]");
	}

}

void
TcpEchoServer::HandleRead (Ptr<Socket> socket)
{
	Ptr<Packet> packet;
	Ptr<Packet> packet2;
	Address from;

	NS_LOG_INFO ("In Handle Read");
if (!m_receiveCb.IsNull())
{
	m_receiveCb(socket);
	NS_LOG_INFO ("Callback not null");
}
else{
	while ((socket->GetRxAvailable())>0)
	{
		 uint32_t toRead =socket->GetRxAvailable ();
		 packet = socket->Recv (toRead, 0);
		 std::cout << "at=" << Simulator::Now ().GetSeconds () << "s, rx bytes=" << packet->GetSize () << std::endl;
		uint8_t *msg;
		msg = new uint8_t[packet->GetSize()];
		packet->CopyData(msg, packet->GetSize());
		unsigned int bufferFloat[packet->GetSize()];
		float floatingPointData;
		NS_LOG_INFO (m_local << "Received " << packet->GetSize () << " bytes  ");

		memcpy(&bufferFloat, msg, 8);

			       bufferFloat[0] = ntohl(bufferFloat[0]);
			       bufferFloat[1] = ntohl(bufferFloat[1]);
			       memcpy(&floatingPointData, &bufferFloat[1], 4);
		NS_LOG_INFO ("PACKET ID: " << packet->GetUid() << "====> CONTENT: %f" << floatingPointData << " SIZE: " << packet->GetSize());


		delete msg;
	}
}
}

} // Namespace ns3


