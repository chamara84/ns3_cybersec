/*
 * tcp-syn-flood.cc
 *
 *  Created on: May. 16, 2019
 *
 *   Copyright (c) 2019 Chamara Devanarayana <chamara@rtds.com>
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




#include "tcp-syn-flood.h"
#include "ns3/socket-factory.h"
#include "ns3/ipv4-raw-socket-factory.h"
#include "ns3/applications-module.h"
#include <iostream>
#include <string>


using namespace ns3;
using namespace std;


NS_LOG_COMPONENT_DEFINE ("TcpSynFloodApplication");

NS_OBJECT_ENSURE_REGISTERED (TcpSynFlood);

TypeId TcpSynFlood::GetTypeId (void)
{
	static TypeId tid = TypeId ("ns3::TcpSynFlood")
	    .SetParent<Application> ()
	    .SetGroupName("Applications")
	    .AddConstructor<TcpSynFlood> ();
	  return tid;
}

TcpSynFlood::TcpSynFlood()
:m_node(0),
m_expPort(7001),
m_running(false),
m_interSynTime(0.0)
{
	NS_LOG_FUNCTION (this);
}


TcpSynFlood::~TcpSynFlood()
{

}

void TcpSynFlood::Setup(Ptr<Node> node,Ipv4Address victimIP, Ipv4Address sourceIP, uint exploitedPort,float interSynTime )
{
m_node =  node;
m_victimAddress = victimIP;
m_sourceAddress = sourceIP;
m_expPort = exploitedPort;
m_interSynTime=interSynTime;

}

void TcpSynFlood::StartApplication(void)
{

	m_running = true;
	Ptr<SocketFactory> rxSocketFactory = this->m_node->GetObject<Ipv4RawSocketFactory> ();

		m_rsocket = DynamicCast<Ipv4RawSocketImpl>(rxSocketFactory->CreateSocket ());
		//m_rsocket->SetRecvPktInfo (true);
		m_rsocket->SetProtocol(TcpL4Protocol::PROT_NUMBER);
		Ptr<Ipv4> ipV4Info = this->m_node->GetObject<Ipv4>();
		std::cout<<"IP:"<<m_sourceAddress;
		int interfaceIndex = ipV4Info->GetInterfaceForAddress(m_sourceAddress);
		std::cout<<"NetDev:"<<interfaceIndex;
		m_rsocket->BindToNetDevice(this->m_node->GetDevice(interfaceIndex));

		 if (m_running)
		    {
		      Time tNext (MilliSeconds(m_interSynTime));
		      m_sendEvent = Simulator::Schedule (tNext, &TcpSynFlood::SendSyn,this);
		    }
}


void TcpSynFlood::SendSyn(void)
{
	Ptr<UniformRandomVariable> rand = CreateObject<UniformRandomVariable> ();
								       rand->SetAttribute( "Min", DoubleValue( 1 ) );
								       rand->SetAttribute( "Max", DoubleValue( 65525 ) );

					   Ptr<UniformRandomVariable> randIp = CreateObject<UniformRandomVariable> ();
								       				       randIp->SetAttribute( "Min", DoubleValue( 1 ) );
								       				       randIp->SetAttribute( "Max", DoubleValue( 255 ) );
       				    int sourcePort;
						sourcePort = rand->GetInteger ();
						//m_rsocket->Bind(InetSocketAddress (m_sourceAddress, sourcePort));
						m_rsocket->Initialize();
						uint8_t flags = TcpHeader::SYN ;
						Ptr<Packet> p = Create<Packet> ();
						TcpHeader header;
						Ipv4Header ipv4Header;
						header.SetFlags(flags);
						header.SetDestinationPort(m_expPort);
						header.SetSourcePort(sourcePort);
						header.SetWindowSize(65000);
						header.SetSequenceNumber ((SequenceNumber32)rand->GetInteger ());
						header.SetAckNumber ((SequenceNumber32)0);

						//Generate Random IP
						int ip1, ip2, ip3,ip4;
						ip1 = randIp->GetInteger();
						ip2 = randIp->GetInteger();
						ip3 = randIp->GetInteger();
						ip4 = randIp->GetInteger();
						std::string str = std::to_string(ip1)+"."+std::to_string(ip2)+"."+std::to_string(ip3)+"."+std::to_string(ip4);

						ipv4Header.SetDestination(m_victimAddress);
						ipv4Header.SetSource(Ipv4Address(str.c_str ()));
						ipv4Header.SetProtocol(6); // 6 stands for TCP
						ipv4Header.SetTtl(255);



						header.InitializeChecksum(Ipv4Address(str.c_str()),m_victimAddress,6);
						header.EnableChecksums();
						p->AddHeader(header);
						ipv4Header.SetPayloadSize(p->GetSize());
						m_rsocket->SetAttribute ("IpHeaderInclude", BooleanValue (true));
						p->AddHeader(ipv4Header);
			m_rsocket->SendTo(p,0,InetSocketAddress (m_victimAddress, m_expPort));

			 if (m_running)
					    {
					      Time tNext (MilliSeconds(m_interSynTime));
					      m_sendEvent = Simulator::Schedule (tNext, &TcpSynFlood::SendSyn,this);
					    }
}

void TcpSynFlood::StopApplication (void)
{
	if (m_sendEvent.IsRunning ())
	    {
	      Simulator::Cancel (m_sendEvent);
	    }
}




