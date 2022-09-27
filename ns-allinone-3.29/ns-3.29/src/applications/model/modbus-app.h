/*
 * modbus-app.h
 *
 *  Created on: Sep. 16, 2022
 *      Author: chamara
 */

#ifndef SRC_APPLICATIONS_MODEL_MODBUS_APP_H_
#define SRC_APPLICATIONS_MODEL_MODBUS_APP_H_

/*
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License Version 2 as
 * published by the Free Software Foundation.  You may not use, modify or
 * distribute this program under any other version of the GNU General
 * Public License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 * Copyright (C) 2014-2019 Cisco and/or its affiliates. All rights reserved.
 * Copyright (C) 2011-2013 Sourcefire, Inc.
 *
 * Author: Ryan Jordan
 *
 * Dynamic preprocessor for the Modbus protocol
 *
 */

#ifndef MODBUS_DECODE_H
#define MODBUS_DECODE_H

#include <stdint.h>


#include <arpa/inet.h>
#include <stddef.h>
#include<cstring>
#include<cstdio>
#include<stdlib.h>
#include "ns3/core-module.h"
#include "ns3/network-module.h"
#include "ns3/csma-module.h"
#include "ns3/internet-module.h"
#include "ns3/node.h"
#include "ns3/packet.h"
#include "ns3/ptr.h"
#include <sstream>
#include <iostream>
#include <vector>
#include<string>
#include <stdbool.h>

/* Need 8 bytes for MBAP Header + Function Code */
#define MODBUS_MIN_LEN 8

/* GIDs, SIDs, and Strings */
#define GENERATOR_SPP_MODBUS 144

#define MODBUS_BAD_LENGTH 1
#define MODBUS_BAD_PROTO_ID 2
#define MODBUS_RESERVED_FUNCTION 3
#define MODBUS_MISSED_TRANSACTION 4

#define MODBUS_BAD_LENGTH_STR "(spp_modbus): Length in Modbus MBAP header does not match the length needed for the given Modbus function."
#define MODBUS_BAD_PROTO_ID_STR "(spp_modbus): Modbus protocol ID is non-zero."
#define MODBUS_RESERVED_FUNCTION_STR "(spp_modbus): Reserved Modbus function code in use."
#define MAX_PORTS 65536

/* Default MODBUS port */
#define MODBUS_PORT 502

#define MODBUS_CLIENT 1
#define MODBUS_SERVER 0

/* Convert port value into an index for the modbus_config->ports array */
#define PORT_INDEX(port) port/8

/* Convert port value into a value for bitwise operations */
#define CONV_PORT(port) 1<<(port%8)

/* Session data flags */
#define MODBUS_FUNC_RULE_FIRED  0x0001
#define MODBUS_UNIT_RULE_FIRED  0x0002
#define MODBUS_DATA_RULE_FIRED  0x0004


/* DNP3 preprocessor configuration */


typedef struct _modbus_alter_values //structure introduced to keep the obj, variance, identifier , newvalue data
{
	uint8_t type;
	uint16_t identifier;
	uint16_t integer_value;
	bool done;

}modbus_alter_values_t;

/* Modbus preprocessor configuration */
typedef struct _modbus_config
{

    modbus_alter_values_t values_to_alter[50];
    int numAlteredVal;

} modbus_config_t;

typedef struct _modbus_request
{	uint16_t transactionID;
	uint8_t unitID;
	uint8_t function;
	uint16_t address;
	uint16_t quantity;
}modbus_request_t;


/* Modbus session data */
typedef struct _modbus_session_data
{
    uint8_t func;
    uint8_t unit;
    uint16_t flags;
    modbus_request_t request_data; //used to map the indices of coils and registers this information is not available in the responce
    uint8_t direction;
} modbus_session_data_t;


#define MODBUS_PORTS_KEYWORD    "ports"
#define MODBUS_MEMCAP_KEYWORD   "memcap"
/* Memcap limits. */
#define MIN_MODBUS_MEMCAP 4144
#define MAX_MODBUS_MEMCAP (100 * 1024 * 1024)

#define MODBUS_OK 1
#define MODBUS_FAIL (-1)
int ModbusDecode(modbus_session_data_t *session, modbus_config_t *config, uint8_t *pdu_start, uint16_t pdu_length);

#endif /* MODBUS_DECODE_H */




#endif /* SRC_APPLICATIONS_MODEL_MODBUS_APP_H_ */
