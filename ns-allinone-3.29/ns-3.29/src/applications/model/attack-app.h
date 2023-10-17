/*
 * arp-spoofing.h
  *  Created on: Mar. 19, 2019
 *      Copyright (c) 2019 Chamara Devanarayana <chamara@rtds.com>
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

#ifndef ATTACK_APP_H_
#define ATTACK_APP_H_ context
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
#include "ns3/net-device.h"
#include <sstream>
#include <iostream>
#include <fstream>
#include <vector>
#include <map>
#include<string>
#include <arpa/inet.h>
#include <stddef.h>
#include<cstring>
#include<cstdio>
#include<stdlib.h>
#include"ns3/dnp3-app.h"
#include"ns3/modbus-app.h"
#include"ns3/iec104-app.h"
#include"ns3/pmu-app.h"
#include"ns3/goose-app.h"
#include"ns3/sv-app.h"
#include <algorithm>

#define FIR_MASK 0x40

namespace ns3 {

typedef struct _configuration
  {
	  dnp3_config_t dnp3;
	  modbus_config_t modbus;
	  iec104_config_t iec104;
	  pmu_config_t pmu;
	  iec61850_config_t goose;
	  sv_config_t sv;
  }configuration;

typedef struct _modbusAlternateSwitchCoilParameters
{

	int index;
	int period;
	Ipv4Header ipV4Hdr;
	bool state;
	TcpHeader tcpHdr;
	uint16_t protocol;
	Address from;
	Address to;
	NetDevice::PacketType packetType;
	Ptr<NetDevice> device;
	bool promisc;

}modbusAlternateSwitchCoilParameters;

class AttackApp : public Application
{
public:
   static TypeId GetTypeId (void);
  AttackApp ();
  virtual ~AttackApp();

  void
  Setup (Ptr<Node> aNode, Ptr<NetDevice> aDev, Ptr<Ipv4Interface> iface, std::vector<Ipv4Address> vAddr1, std::vector<Ipv4Address> vAddr2, std::vector<Address> vMac);

  bool NonPromiscReceiveFromDevice (Ptr<NetDevice> device, Ptr<const Packet> packet, uint16_t protocol,
                                     const Address &from);
  bool PromiscReceiveFromDevice (Ptr<NetDevice> device, Ptr<const Packet> packet, uint16_t protocol,
                                     const Address &from, const Address &to, NetDevice::PacketType );
  bool ReceiveFromDevice (Ptr<NetDevice> device, Ptr<const Packet> packet, uint16_t protocol,
                           const Address &from, const Address &to, NetDevice::PacketType packetType, bool promiscuous);
  std::vector<std::string>  giveParsingString(int msgType);
  int readConfigFile( ns3::configuration *);

  void SendPacketAlterCoilValue (modbusAlternateSwitchCoilParameters * parameters);

  void ScheduleTxAlterCoil (modbusAlternateSwitchCoilParameters *parameters);

  void SendPacketAlterBinaryOutputValue (modbusAlternateSwitchCoilParameters * parameters);

    void ScheduleTxAlterBinaryOutput(modbusAlternateSwitchCoilParameters *parameters);



private:
  virtual void StartApplication (void);
  virtual void StopApplication (void);
  void ScheduleTx (void);
  void SendPacket (void);

  Ptr<Node> m_node;
  Ptr<NetDevice> m_device;
  Ptr<Ipv4Interface> m_iface;
  std::vector<Ipv4Address> m_fakeAddr;

  // victim info
  std::vector<Ipv4Address>m_vAddr;
  std::vector<Address> m_vMac;

  EventId         m_sendEvent;
  bool            m_running;

  ArpL3Protocol m_attacker;
  Ptr<ArpCache> m_arpCache;
  std::multimap<uint64_t,dnp3_session_data_t *> mmapOfdnp3Data;
  std::multimap<uint64_t,modbus_session_data_t *> mmapOfModbusData;
  std::multimap<uint64_t,iec104_session_data_t *> mmapOfIec104Data;
  std::multimap<uint64_t,pmu_session_data_t *> mmapOfPmuData;
  ns3::configuration config;
  bool enableAlternatingCoilValuesMODBUS;
  int indexOfCoil;
  int periodOfCoilStateSwitch;
  int currentCoilState;
};


}

#endif /* ATTACK_APP_H_ */
