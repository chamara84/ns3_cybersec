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

#ifndef TCP_ECHO_SERVER_H
#define TCP_ECHO_SERVER_H
#include <map>
#include "ns3/application.h"
#include "ns3/event-id.h"
#include "ns3/ptr.h"
#include "ns3/ipv4-address.h"
#include "ns3/inet-socket-address.h"
#include "ns3/rtt-estimator.h"
#include "ns3/tcp-congestion-ops.h"
#include "ns3/tcp-recovery-ops.h"
#include "ns3/tcp-socket-base.h"
#include "ns3/tcp-l4-protocol.h"

namespace ns3 {

class Socket;
class Packet;

/**
 * \ingroup applications
 * \defgroup tcpecho TcpEcho
 */

/**
 * \ingroup tcpecho
 * \brief A Tcp Echo server
 *
 * Every packet received is sent back.
 */
class TcpSocketMsgBase : public ns3::TcpSocketBase
{
public:
  /**
   * \brief Get the type ID.
   * \return the object TypeId
   */
  static TypeId GetTypeId (void);

  TcpSocketMsgBase () : TcpSocketBase ()
  {
  }

  /**
   * \brief Constructor.
   * \param other The object to copy from.
   */
  TcpSocketMsgBase (const TcpSocketMsgBase &other) : TcpSocketBase (other)
  {
    m_rcvAckCb = other.m_rcvAckCb;
    m_processedAckCb = other.m_processedAckCb;
    m_beforeRetrCallback = other.m_beforeRetrCallback;
    m_afterRetrCallback = other.m_afterRetrCallback;
    m_forkCb = other.m_forkCb;
    m_updateRttCb = other.m_updateRttCb;
  }

  /// Callback for the ACK management.
  typedef Callback<void, Ptr<const Packet>, const TcpHeader&,
                   Ptr<const TcpSocketBase> > AckManagementCb;
  /// Callback for the packet retransmission management.
  typedef Callback<void, Ptr<const TcpSocketState>,
                   Ptr<const TcpSocketBase> > RetrCb;
  /// Callback for the RTT update management.
  typedef Callback<void, Ptr<const TcpSocketBase>, const SequenceNumber32&,
                   uint32_t, bool> UpdateRttCallback;
  //typedef Callback<void, Ptr<Socket> > ReceivedData;         //!< data received callback



  /**
    * \brief Set the callback invoked when an ACK is received (at the beginning
    * of the processing)
    *
    * \param cb callback
    */
   void SetRcvAckCb (AckManagementCb cb);

  /**
   * \brief Set the callback invoked when an ACK is received and processed
   * (at the end of the processing)
   *
   * \param cb callback
   */
  void SetProcessedAckCb (AckManagementCb cb);

  /**
   * \brief Set the callback invoked after the processing of a retransmit timeout
   *
   * \param cb callback
   */
  void SetAfterRetransmitCb (RetrCb cb);

  /**
   * \brief Set the callback invoked before the processing of a retransmit timeout
   *
   * \param cb callback
   */
  void SetBeforeRetransmitCb (RetrCb cb);

  /**
   * \brief Set the callback invoked after the forking
   * \param cb callback
   */
  void SetForkCb (Callback<void, Ptr<TcpSocketMsgBase> > cb);

  /**
   * \brief Set the callback invoked when we update rtt history
   *
   * \param cb callback
   */
  void SetUpdateRttHistoryCb (UpdateRttCallback cb);

protected:
  virtual void ReceivedAck (Ptr<Packet> packet, const TcpHeader& tcpHeader);
  virtual void ReTxTimeout (void);
  virtual Ptr<TcpSocketBase> Fork (void);
  virtual void CompleteFork (Ptr<Packet> p, const TcpHeader& tcpHeader,
                             const Address& fromAddress, const Address& toAddress);
  virtual void UpdateRttHistory (const SequenceNumber32 &seq, uint32_t sz,
                                 bool isRetransmission);

private:
  AckManagementCb m_rcvAckCb;       //!< Receive ACK callback.
  AckManagementCb m_processedAckCb; //!< Processed ACK callback.
  RetrCb m_beforeRetrCallback;      //!< Before retransmission callback.
  RetrCb m_afterRetrCallback;       //!< After retransmission callback.
  Callback<void, Ptr<TcpSocketMsgBase> > m_forkCb;  //!< Fork callback.
  UpdateRttCallback m_updateRttCb;  //!< Update RTT callback.

};


class TcpEchoServer : public Application
{
public:
  static TypeId GetTypeId (void);
  TcpEchoServer ();
  virtual ~TcpEchoServer ();
  typedef Callback<void, Ptr<Socket> > ReceivedData;         //!< data received callback
  void SetRcvDataCb (ReceivedData cb);

protected:
  virtual void DoDispose (void);

private:

  virtual void StartApplication (void);
  virtual void StopApplication (void);

  void HandleRead (Ptr<Socket> socket);
  void HandleReadFromRemote (Ptr<Socket> socket);
  void HandleAccept (Ptr<Socket> socket, const Address& from);
  bool HandleAcceptRequest (Ptr<Socket> socket, const Address& from);
  void HandleClose (Ptr<Socket> socket);
	void PrintPairs();

  uint16_t m_port;
  Ptr<TcpSocketMsgBase>  m_socket;
  Ipv4Address m_local;
	std::map<Ptr<Socket>, Ipv4Address> m_conn;
	std::map<Ptr<Socket>, Ptr<Socket> > m_pair;

	ReceivedData m_receiveCb;
	 /**
	   * \brief Set the callback invoked when data is received (at the beginning
	   * of the processing)
	   *
	   * \param cb callback
	   */

};

} // namespace ns3

#endif /* TCP */
