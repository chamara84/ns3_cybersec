/*
 * pmu-app.h
 *
 *  Created on: Oct. 12, 2022
 *      Author: chamara
 */

#ifndef SRC_APPLICATIONS_MODEL_PMU_APP_H_
#define SRC_APPLICATIONS_MODEL_PMU_APP_H_

#include <stdint.h>

#include <complex.h>
#include <math.h>
#include <stdint.h>
#include <bits/stdc++.h>
#include<list>
#include<array>
#include<string>
#include<iostream>
#include<map>
#include<netinet/in.h>

/* Need 8 bytes for PMU frame header */
#define PMU_MIN_LEN 14
#define PMU_PORT1 4712
#define PMU_PORT2 4722

#define PMU_CLIENT 1
#define PMU_SERVER 0


/* GIDs, SIDs, and Strings */
#define GENERATOR_SPP_PMU 144

#define PMU_BAD_LENGTH 1
#define PMU_BAD_PROTO_ID 2
#define PMU_RESERVED_FUNCTION 3
#define PMU_MISSED_TRANSACTION 4

#define PMU_BAD_LENGTH_STR "(spp_pmu): Length in PMU MBAP header does not match the length needed for the given PMU function."
#define PMU_BAD_PROTO_ID_STR "(spp_pmu): PMU protocol ID is non-zero."
#define PMU_RESERVED_FUNCTION_STR "(spp_pmu): Reserved PMU function code in use."



#define MAX_PORTS 65536

/* Default PMU port */
#define PMU_PORT 4712

/* Convert port value into an index for the pmu_config->ports array */
#define PORT_INDEX(port) port/8

/* Convert port value into a value for bitwise operations */
#define CONV_PORT(port) 1<<(port%8)

/* Session data flags */
#define PMU_FUNC_RULE_FIRED  0x0001
#define PMU_UNIT_RULE_FIRED  0x0002
#define PMU_DATA_RULE_FIRED  0x0004


typedef struct _pmu_alter_values //structure introduced to keep the obj, variance, identifier , newvalue data
{
	std::string pmuName;
	uint8_t type;
	std::string identifier;
	float real_value;
	float imaginary_value;
	uint16_t digValue;
	bool done;

}pmu_alter_values_t;

/* PMU preprocessor configuration */
typedef struct _pmu_config
{
    uint8_t ports[MAX_PORTS/8];

    int ref_count;
    pmu_alter_values_t values_to_alter[50];
    uint16_t numAlteredVal;
    uint32_t memcap;
    int disabled;
} pmu_config_t;




typedef struct _C37118FracSec
	{
	uint32_t FractionOfSecond;
			uint8_t TimeQuality;


	}C37118FracSec;

typedef enum
	{
		DATA_FRAME = 0,
		HEADER_FRAME = 1,
		CONFIGURATION_FRAME_1 = 2,
		CONFIGURATION_FRAME_2 = 3,
		CONFIGURATION_FRAME_3 = 5,
		COMMAND_FRAME = 4
	}C37118HdrFrameType;


typedef struct _C37118PhasorUnit
		{

			uint8_t Type; // 0=Volt, 1=Current;
			uint32_t PhasorScalar;
		}C37118PhasorUnit;



typedef	struct _C37118AnalogUnit
		{

			// 0 = Single point on wave
			// 1 = RMS of analog input
			// 2 = peak of analog input
			// 5-64 = reserved
			int Type_X;
			int32_t AnalogScalar;
		}C37118AnalogUnit;





typedef	struct _C37118DigitalUnit
		{

			uint16_t DigNormalStatus;
			uint16_t DigValidInputs;
		}C37118DigitalUnit;



		typedef enum
		{
			PHC0_ZERO_SEQUENCE = 0,
			PHC1_POSITIVE_SEQUENCE = 1,
			PHC2_NEGATIVE_SEQUENCE= 2,
			PHC3_RESERVED = 3,
			PHC4_PHASE_A = 4,
			PHC5_PHASE_B = 5,
			PHC6_PHASE_C = 6,
			PHC7_RESERVED = 7
		}PhasorComponentCodeEnum;

typedef struct _C37118PmuFormat
			{
				bool Bit0_0xPhasorFormatRect_1xMagnitudeAndAngle;
				bool Bit1_0xPhasorsIsInt_1xPhasorFloat;
				bool Bit2_0xAnalogIsInt_1xAnalogIsFloat;
				bool Bit3_0xFreqIsInt_1xFreqIsFloat;
			}C37118PmuFormat;

typedef	struct _C37118NomFreq
				{
					bool Bit0_1xFreqIs50_0xFreqIs60;


				}C37118NomFreq;
typedef	struct _C37118PmuConfiguration
		{
			std::string StationName ;

			uint16_t IdCode;
			C37118PmuFormat DataFormat;
			std::list<std::string> phasorChnNames ;
			std::list<std::string> analogChnNames;
			std::list<std::string> digitalChnNames;
			std::list<C37118PhasorUnit *> PhasorUnit; // accepts a pointer to C37118PhasorUnit C37118PhasorUnit
			std::list<C37118AnalogUnit *> AnalogUnit;// accepts a pointer to C37118AnalogUnit
			std::list<C37118DigitalUnit *> DigitalUnit; // 16 chn names per unit accepts a pointer to C37118DigitalUnit
			C37118NomFreq NomFreqCode;
			uint16_t ConfChangeCnt;
			uint16_t numPhasors;
			uint16_t numAnalog;
			uint16_t numDigital;
		}C37118PmuConfiguration;


typedef struct _C37118TimeBase
			{
				uint8_t Flags;
				uint32_t TimeBase;
			}C37118TimeBase;

typedef struct
				{


					int16_t m_datarateRaw;
				}C37118DataRate;

typedef struct _C37118PdcConfiguration
			{

				C37118TimeBase TimeBase;
				std::list<C37118PmuConfiguration *>  PMUs; //accepts pointer to C37118PmuConfiguration
				C37118DataRate DataRate;
				uint16_t NumPMU;
				uint16_t FooterCrc16;
			}C37118PdcConfiguration;

typedef struct _C37118SyncField
	{
	char LeadIn; // Should be 0xAA
			C37118HdrFrameType FrameType;
			char Version;

	}C37118SyncField;


typedef struct _C37118FrameHeader
	{
		C37118SyncField Sync;
		uint16_t FrameSize;
		uint16_t IdCode;
		uint32_t SOC;
		C37118FracSec FracSec;
	}C37118FrameHeader;


/* PMU session data */
typedef struct _pmu_session_data
{
	C37118SyncField Sync;
	uint16_t FrameSize;
	uint16_t IdCode;
	uint32_t SOC;
	C37118FracSec FracSec;
	C37118PdcConfiguration pmuConfig2;
	uint8_t partialData; //if 1 on going construction, if 0 newFrame, if 2 fullFrame
	std::string FrameData;
	uint8_t direction;
    bool capturedConfig2;

    std::multimap <std::string,uint32_t*>   pmuRefTable; //this table returns the offset of the message for a given pmu_nameValue_name pair concatenated
} pmu_session_data_t;


#define PMU_PORTS_KEYWORD    "ports"
#define PMU_MEMCAP_KEYWORD   "memcap"
/* Memcap limits. */
#define MIN_PMU_MEMCAP 4144
#define MAX_PMU_MEMCAP (100 * 1024 * 1024)

#define PMU_OK 1
#define PMU_FAIL (-1)

int PMUDecode(pmu_session_data_t *session, pmu_config_t *config, uint8_t *pdu_start, uint16_t pdu_length);
static std::string trimwhitespace(std::string str);



#endif /* SRC_APPLICATIONS_MODEL_PMU_APP_H_ */
