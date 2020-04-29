/*
 * tcp-syn-flood.h
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


#ifndef TCP_SYN_FLOOD_H
#define TCP_SYN_FLOOD_H

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
#include "ns3/node.h"
#include <sstream>
#include <iostream>


namespace ns3 {

class Socket;
class Packet;

class TcpSynFlood : public Application
{
public:
	static TypeId GetTypeId (void);
	TcpSynFlood();
	virtual ~TcpSynFlood();
	void Setup(Ptr<Node> node,Ipv4Address victimIP, Ipv4Address sourceIP, uint exploitedPort,float interSynTime );

private:
  virtual void StartApplication (void);
  virtual void StopApplication (void);
  void SendSyn(void);

  Ptr<Node> m_node;
  Ipv4Address m_victimAddress;
  Ipv4Address m_sourceAddress;
  uint m_expPort;
  Ptr<Ipv4RawSocketImpl>     m_rsocket;
  EventId         m_sendEvent;
  bool            m_running;
  float m_interSynTime;
};

}



#endif /* TCP_SYN_FLOOD_H */
