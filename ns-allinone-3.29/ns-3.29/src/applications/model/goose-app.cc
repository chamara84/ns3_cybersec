/* $Id$ */
/*
** Copyright (C) 2014-2019 Cisco and/or its affiliates. All rights reserved.
** Copyright (C) 2004-2013 Sourcefire, Inc.
** Copyright (C) 2001-2004 Jeff Nathan <jeff@snort.org>
**
** This program is free software; you can redistribute it and/or modify
** it under the terms of the GNU General Public License Version 2 as
** published by the Free Software Foundation.  You may not use, modify or
** distribute this program under any other version of the GNU General
** Public License.
**
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
** GNU General Public License for more details.
**
** You should have received a copy of the GNU General Public License
** along with this program; if not, write to the Free Software
** Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
*/

/* Snort GOOSE Preprocessor Plugin
 *   by Chamara Devanarayana <chamara@rtds.com> based on libiec61850-1.4.0 https://github.com/mz-automation/libiec61850
 *   Version 0.1.0
 *
 * Purpose:
 *
 * This preprocessor decodes GOOSE  packets and is able to modify the data
 *
 *
 *
 */

/*  I N C L U D E S  ************************************************/
#include <assert.h>
#include <sys/types.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#ifndef WIN32
# include <sys/time.h>
# include <sys/socket.h>
# include <netinet/in.h>
# include <arpa/inet.h>
#else
# include <time.h>
#endif

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif


#include "goose-app.h"

/*  D E F I N E S  **************************************************/



/*  D A T A   S T R U C T U R E S  **********************************/



/*  G L O B A L S  **************************************************/


 std::multimap<std::string,frame_identifier_t *>  gooseRefTable;

#ifdef PERF_PROFILING
PreprocStats arpPerfStats;
#endif


/*  P R O T O T Y P E S  ********************************************/









int modifyData(uint8_t * pdu_start, uint16_t pdu_length,std::vector<iec61850_Object_header_t*> dataSet, iec61850_asdu_header_t* pdu,iec61850_config_t *config)
{
int modified = 0;
IEC61850Config* aconfig=config;
iec61850_Object_header_t* dataEnty=NULL;


for(int index = 0 ; index<aconfig->numAlteredVal;index++)
	{

		if(pdu->gocbRef.compare(aconfig->values_to_alter[index].gocbRef)==0 && pdu->datSet.compare(aconfig->values_to_alter[index].datSet)==0)
				            		 {
									dataEnty=(iec61850_Object_header_t*)dataSet.at( aconfig->values_to_alter[index].dataItemNo);

									if(dataEnty==NULL)
									{
										return modified;
									}

									switch(dataEnty->type)
									{
									case(0x83):
										{
											modified=1;
											int8_t tempBoolVal = strtol(aconfig->values_to_alter[index].newVal.c_str(),NULL,10);
											memcpy(pdu_start+dataEnty->dataOffsetFromStart,&tempBoolVal ,dataEnty->infElementBytesUsed);


											break;
										}
									case(0x85):
											{
													modified=1;
													int64_t tempIntVal = strtoll(aconfig->values_to_alter[index].newVal.c_str(),NULL,10);
													char * tempCharVal = new char [sizeof(int64_t)];
													memcpy(tempCharVal,&tempIntVal,sizeof(int64_t));

													memcpy(pdu_start+dataEnty->dataOffsetFromStart,tempCharVal ,dataEnty->infElementBytesUsed);

													free(tempCharVal);
													break;
											}


									case(0x86):
											{
											modified=1;
									uint64_t tempUIntVal = strtoull(aconfig->values_to_alter[index].newVal.c_str(),NULL,10);
									char * tempCharVal = new char [sizeof(int64_t)];
									memcpy(tempCharVal,&tempUIntVal,sizeof(uint64_t));

									memcpy(pdu_start+dataEnty->dataOffsetFromStart,tempCharVal ,dataEnty->infElementBytesUsed);

									free(tempCharVal);
									break;
											}

									case(0x87):
											{
																						modified=1;
									uint8_t additionalBits = dataEnty->infElementBytesUsed - 4;
									float tempDoubleVal = strtof(aconfig->values_to_alter[index].newVal.c_str(),NULL);
									int32_t * tempCharVal = new int32_t();
									memcpy(tempCharVal,&tempDoubleVal,sizeof(float));
                                    *tempCharVal = htonl(*tempCharVal);
									memcpy(pdu_start+dataEnty->dataOffsetFromStart+additionalBits,tempCharVal,dataEnty->infElementBytesUsed);

									free(tempCharVal);
									break;
											}

									case(0x84):
										{
										modified=1;
										uint16_t tempCodemEnumVal = strtol(aconfig->values_to_alter[index].newVal.c_str(),NULL,16);
										tempCodemEnumVal = ntohs(tempCodemEnumVal);
										char * tempCharVal = new char [sizeof(uint16_t)];
										memset(tempCharVal,0,2);
										memcpy(tempCharVal,&tempCodemEnumVal,sizeof(uint16_t));

										memcpy(pdu_start+dataEnty->dataOffsetFromStart,tempCharVal ,dataEnty->infElementBytesUsed);

										free(tempCharVal);
										break;
										}

									case(0x89):
										{
										modified=1;
										memcpy(pdu_start+dataEnty->dataOffsetFromStart,aconfig->values_to_alter[index].newVal.c_str() ,dataEnty->infElementBytesUsed);

										break;
										}
									case(0x8a):
										{
										modified=1;
										memcpy(pdu_start+dataEnty->dataOffsetFromStart,aconfig->values_to_alter[index].newVal.c_str() ,dataEnty->infElementBytesUsed);
										break;
										}
									case(0x91):
										{
										modified=1;
										uint64_t tempUIntVal = strtoull(aconfig->values_to_alter[index].newVal.c_str(),NULL,10);
										char * tempCharVal = new char [sizeof(uint64_t)];
										memcpy((void *)tempCharVal,&tempUIntVal,sizeof(uint64_t));

										memcpy(pdu_start+dataEnty->dataOffsetFromStart,tempCharVal ,dataEnty->infElementBytesUsed);

										delete tempCharVal;
										break;
										}









				            		 }


	}
	}
	return modified;
}

static int
BerDecoder_decodeLength(uint8_t* buffer, int* length, int bufPos, int maxBufPos)
{
    if (bufPos >= maxBufPos)
        return -1;

    uint8_t len1 = buffer[bufPos++];


    if (len1 & 0x80) {
        int lenLength = len1 & 0x7f;

        if (lenLength == 0) { /* indefinite length form */
            *length = -1;
        }
        else {
            *length = 0;

            int i;
            for (i = 0; i < lenLength; i++) {
                if (bufPos >= maxBufPos)
                    return -1;

                *length <<= 8;
                *length += buffer[bufPos++];

            }
        }

    }
    else {
        *length = len1;
    }

    if (*length < 0)
        return -1;

    if (bufPos + (*length) > maxBufPos)
        return -1;

    return bufPos;
}


static char*
BerDecoder_decodeString(uint8_t* buffer, int strlen, int bufPos, int maxBufPos)
{
    char* string = (char*) malloc(strlen + 1);
    memcpy(string, buffer + bufPos, strlen);
    string[strlen] = 0;

    return string;
}

static uint32_t
BerDecoder_decodeUint32(uint8_t* buffer, int intLen, int bufPos)
{
    uint32_t value = 0;

    int i;
    for (i = 0; i < intLen; i++) {
        value <<= 8;
        value += buffer[bufPos + i];
    }

    return value;
}

static int32_t
BerDecoder_decodeInt32(uint8_t* buffer, int intlen, int bufPos)
{
    int32_t value;
    int i;

    bool isNegative = ((buffer[bufPos] & 0x80) == 0x80);

    if (isNegative)
        value = -1;
    else
        value = 0;

    for (i = 0; i < intlen; i++) {
        value <<= 8;
        value += buffer[bufPos + i];
    }

    return value;
}

static float
BerDecoder_decodeFloat(uint8_t* buffer, int bufPos)
{
    float value;
    uint8_t* valueBuf = (uint8_t*) &value;

    int i;

    bufPos += 1; /* skip exponentWidth field */

#if (__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__)
    for (i = 3; i >= 0; i--) {
        valueBuf[i] = buffer[bufPos++];
    }
#else
    for (i = 0; i < 4; i++) {
        valueBuf[i] = buffer[bufPos++];
    }
#endif

    return value;
}

static double
BerDecoder_decodeDouble(uint8_t* buffer, int bufPos)
{
    double value;
    uint8_t* valueBuf = (uint8_t*) &value;

    int i;

    bufPos += 1; /* skip exponentWidth field */

#if (__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__)
    for (i = 7; i >= 0; i--) {
        valueBuf[i] = buffer[bufPos++];
    }
#else
    for (i = 0; i < 8; i++) {
        valueBuf[i] = buffer[bufPos++];
    }
#endif

    return value;
}

static bool
BerDecoder_decodeBoolean(uint8_t* buffer, int bufPos) {
    if (buffer[bufPos] != 0)
        return true;
    else
        return false;
}



int IEC61850FullReassembly(ns3::Ptr<ns3::NetDevice> device,iec61850_config_t *config, ns3::Ptr<const ns3::Packet> packet, uint8_t *pdu_start, uint16_t pdu_length)
{


	int offset = 0;
	int stuffUp = 0;
	int dosAttack = 0;
	uint16_t offsetStNum = 0;
	uint16_t offsetTime = 0;
	int elementLengthStNum = 0;
	iec61850_header_t gooseHeader;
	iec61850_asdu_header_t* pdu = new iec61850_asdu_header_t();
	pdu->datSet= "";
	pdu->goID="";
	pdu->gocbRef="";

	std::vector<iec61850_Object_header_t*> dataSet;
	 int dataOffset = 1;
	 uint64_t timeval = 0;
	 uint16_t dataLength = 0;
	 iec61850_Object_header_t* data =NULL;
	  	 iec61850_Object_header_t* dataTemp=NULL;
	  	 uint8_t * stNumPt = new uint8_t[4]  ;
	  	frame_identifier_t* frameID = new frame_identifier_t();
 char nullCharactor = '\0';
	 int modify = 0;


	if (pdu_length < (sizeof(iec61850_header_t) ))
		return -1;

	if ( pdu_length > IEC60870_5_61850_MAX_ASDU_LENGTH + IEC60870_5_61850_APCI_LENGTH )

		return -1;
	//uint8_t *lengthData = malloc(1);
	//memset(lengthData,100,1);
	gooseHeader.appID = pdu_start[offset++]*0x100;
	gooseHeader.appID += pdu_start[offset++];
	gooseHeader.len= pdu_start[offset++]*0x100;
	gooseHeader.len += pdu_start[offset];
	//memcpy(pdu_start+offset,lengthData,1);
	offset++;
	gooseHeader.reserved_1 = pdu_start[offset++]*0x100;
	gooseHeader.reserved_1 += pdu_start[offset++];
	gooseHeader.reserved_2 = pdu_start[offset++]*0x100;
	gooseHeader.reserved_2 += pdu_start[offset++];


	 if (pdu_start[offset++] == 0x61)
	 {
		 int gooseLength;
		 int bytesInLength;
		 int tempOffset;
		 offset = BerDecoder_decodeLength(pdu_start, &gooseLength, offset, gooseHeader.len);
		         if (offset < 0) {

		             return -1;
		         }

		         int gooseEnd = offset + gooseLength;

		         while (offset < gooseEnd) {
		             int elementLength;

		             uint8_t tag = pdu_start[offset++];
		             offset = BerDecoder_decodeLength(pdu_start, &elementLength, offset, gooseHeader.len);
		             if (offset < 0) {

		                 return -1;
		             }



		             switch (tag)
		             {
		             case 0x80: /* gocbRef */
		             {
		            	 std::string tempStr((const char *)pdu_start+offset,(size_t)elementLength);
		            	 pdu->gocbRef = tempStr;
		            	 //frameID->gocbref=g_string_new_len( (pdu_start+offset),elementLength);
		             }
		                 break;

		             case 0x81: /* timeAllowedToLive */

		            	 pdu->timeToLive = BerDecoder_decodeUint32(pdu_start, elementLength, offset);


		                 break;

		             case 0x82:
		             {
		            	 std::string tempStr((const char *)pdu_start+offset,(size_t)elementLength);
		            	 pdu->datSet = tempStr;




		            	 for(int index = 0 ; index<config->numAlteredVal;index++)
		            	 {
		            		 if(pdu->gocbRef.compare(config->values_to_alter[index].gocbRef)==0 && pdu->datSet.compare(config->values_to_alter[index].datSet)==0)
		            		 {

		            			 modify = 1;
		            			 break;
		            		 }

//		            		 else
//		            			 return;


		            	 }

		            	 if(modify==0)
		            	 {


		            		 if(pdu)
		            			 delete pdu;
		            		 return -1;
		            	 }

		             }
		                 break;

		             case 0x83:
		             {
		            	 std::string tempStr((const char *)pdu_start+offset,(size_t)elementLength);
		            	 pdu->goID = tempStr;
		             }
		            	 break;

		             case 0x84:
		             {
		                 memcpy(&(pdu->t.tv_sec), pdu_start + offset,elementLength/2);
		                 memcpy(&(pdu->t.tv_usec), pdu_start + offset+4,4);
		                 //timeval = ntohll(timeval);
		                 offsetTime = offset;
		                 uint32_t fraction = ntohl(pdu->t.tv_usec)*0x100;





		             }
		                 break;

		             case 0x85:
		            	 pdu->stNum = BerDecoder_decodeUint32(pdu_start, elementLength, offset);
		            	 frameID->stNum = pdu->stNum;
		            	 elementLengthStNum = elementLength;
		            	 offsetStNum = offset;

		                 break;

		             case 0x86:
		             {
		            	 pdu->sqNum = BerDecoder_decodeUint32(pdu_start, elementLength, offset);
		            	 frameID->sqNum = pdu->sqNum;
		            	 char *orig_Key;
		            	 frame_identifier_t* tempFrameID;


		            	 tempFrameID =gooseRefTable.find(pdu->gocbRef)->second;

		            	 if(!tempFrameID || (tempFrameID && (frameID->sqNum == 0 && frameID->stNum<=tempFrameID->stNum)))
		            	 		            	 { //we are seeing the gocbRev for the first time or it is a new status by the Org publisher


		            		 if(tempFrameID && tempFrameID->stNum==frameID->stNum && tempFrameID->sqNum==frameID->sqNum)
		            			 return -1;

		            		 if(!dosAttack){
		            		 if(!tempFrameID)          		 // we need to send a fake new status
		            	 			  pdu->stNum ++;
		            	 		  else
		            	 			 pdu->stNum = tempFrameID->stNum+1;
		            		 }

		            		 else
		            		 {
		            			 switch(elementLengthStNum)
		            			 {
		            			 case 1:
		            			 {
		            				 pdu->stNum = 127;
		            				 uint8_t val = ( uint8_t)pdu->stNum;
		            				 frameID->stNum = pdu->stNum;
		            				 memcpy(stNumPt,&val,1);
		            				 break;

		            			 }
		            			 case 2:
		            			 {
		            				 pdu->stNum = 65535;
		            				 uint16_t val16 = ( uint16_t)pdu->stNum;
		            				 memcpy(stNumPt,&val16,2);
		            				 frameID->stNum = pdu->stNum;
		            				 break;
		            			 }
		            			 case 4:
		            			 {
		            				 pdu->stNum = 4294967295;
		            				 uint32_t val32 = ( uint32_t)pdu->stNum;
		            				 frameID->stNum = pdu->stNum;
		            				 memcpy(stNumPt,&val32,4);
		            				 break;
		            			 }


		            			 }
		            		 }
		            		 struct timeval tv;
		            		 		                 gettimeofday(&tv,NULL);
		            		 		                 time_t curtime;
		            		 		                 char buffer[80];
		            		 		                 curtime=tv.tv_sec;
		            		 		                 uint32_t curTimeInc = curtime;
		            		 		                 curTimeInc = htonl(curTimeInc);
		            		 		                 memcpy(pdu_start + offsetTime,&curTimeInc,4);
		            		 		                 curtime=tv.tv_usec;
		            		 		                 curTimeInc = curtime;
		            		 		                 curTimeInc = htonl(curTimeInc);
		            		 		                 memcpy(pdu_start + offsetTime+4,&curTimeInc,4);
		            		 		                memcpy(&(frameID->tv),&tv,sizeof(tv));
		            		 switch(elementLengthStNum)
		            				            	 {
		            				            	 case 1:
		            				            	 {
		            				            		 pdu->stNum = (pdu->stNum)%(256);
		            				            		 uint8_t val = ( uint8_t)pdu->stNum;
		            				            		 frameID->stNum = pdu->stNum;
		            				            		 memcpy(stNumPt,&val,1);
		            				            		 break;
		            				            	 }
		            				            	 case 2:
		            				            	 {
		            				            		 pdu->stNum = (pdu->stNum)%(65536);
		            				            		 uint16_t val16 = ( uint16_t)pdu->stNum;
		            				            		 		            		 memcpy(stNumPt,&val16,2);
		            				            		 		            		frameID->stNum = pdu->stNum;
		            				            		 break;
		            				            	 }
		            				            	 case 4:
		            				            	 {
		            				            	     pdu->stNum = (pdu->stNum)%(4294967296);
		            				            	     uint32_t val32 = ( uint32_t)pdu->stNum;
		            				            	     frameID->stNum = pdu->stNum;
		            				            	     memcpy(stNumPt,&val32,4);
		            				            	     break;
		            				            	 }


		            				            	 }

		            				            	 memcpy(pdu_start+offsetStNum, stNumPt,elementLengthStNum);

		            				            	 if(frameID->sqNum!=0)
		            				            	 {
		            				            		 pdu->sqNum=0;

		            				            		 uint32_t val = 0;
		            				            		 frameID->sqNum = 0;
		            				            		 memcpy(stNumPt,&val,4);
		            				            		 memcpy(pdu_start+offset, stNumPt,elementLength);
		            				            	 }
		            				            	 std::map<std::string,frame_identifier_t*>::iterator it = gooseRefTable.find(pdu->gocbRef);
		            				            	   if (it != gooseRefTable.end())
		            				            		   gooseRefTable.erase (it);


		            	 		            		 gooseRefTable.insert( std::pair<std::string,frame_identifier_t*>(pdu->gocbRef,frameID));

		            	 		            		 printf("KEY: |%s|.SQNum %d StNum %d \n", pdu->gocbRef.c_str(),frameID->sqNum,frameID->stNum);


		            	 		            	 }

		            	 else if(tempFrameID && (frameID->sqNum != 0 && frameID->stNum<tempFrameID->stNum))
		            	 		            	 { //old status by the Org publisher
		            	 		            		 // we need to increase the sqNum saved in hash and send with the old stNum saved

		            		 	 	 	 	 pdu->sqNum=tempFrameID->sqNum+1;
		            		 	 	 	 	pdu->stNum = tempFrameID->stNum;



		            		 	 	 	 switch(elementLengthStNum)
		            		 	 	 	 		            				            	 {
		            		 	 	 	 		            				            	 case 1:
		            		 	 	 	 		            				            	 {
		            		 	 	 	 		            				            		 pdu->stNum = (pdu->stNum)%(256);
		            		 	 	 	 		            				            		 uint8_t val = ( uint8_t)pdu->stNum;
		            		 	 	 	 		            				            		 frameID->stNum = pdu->stNum;
		            		 	 	 	 		            				            		 memcpy(stNumPt,&val,1);
		            		 	 	 	 		            				            		 break;
		            		 	 	 	 		            				            	 }
		            		 	 	 	 		            				            	 case 2:
		            		 	 	 	 		            				            	 {
		            		 	 	 	 		            				            		 pdu->stNum = (pdu->stNum)%(65536);
		            		 	 	 	 		            				            		 uint16_t val16 = ( uint16_t)pdu->stNum;
		            		 	 	 	 		            				            		 val16 = htons(val16);
		            		 	 	 	 		            				            		 memcpy(stNumPt,&val16,2);
		            		 	 	 	 		            				            		 frameID->stNum = pdu->stNum;
		            		 	 	 	 		            				            		 break;
		            		 	 	 	 		            				            	 }

		            		 	 	 	 		            				            	 case 4:
		            		 	 	 	 		            				            	 {
		            		 	 	 	 		            				            	     pdu->stNum = (pdu->stNum)%(4294967296);
		            		 	 	 	 		            				            	     uint32_t val32 = ( uint32_t)pdu->stNum;
		            		 	 	 	 		            				            	     val32 = htonl(val32);
		            		 	 	 	 		            				            	     frameID->stNum = pdu->stNum;
		            		 	 	 	 		            				            	     memcpy(stNumPt,&val32,4);
		            		 	 	 	 		            				            	     break;
		            		 	 	 	 		            				            	 }


		            		 	 	 	 		            				            	 }
		            		 	 	 	 memcpy(pdu_start+offsetStNum, stNumPt,elementLengthStNum);

		            		 	 	 	switch(elementLength)
		            		 	 	 			            				            	 {
		            		 	 	 			            				            	 case 1:
		            		 	 	 			            				            	 {
		            		 	 	 			            				            		 pdu->sqNum = (pdu->sqNum)%(256);
		            		 	 	 			            				            		 uint8_t val = ( uint8_t)pdu->sqNum;
		            		 	 	 			            				            		 frameID->sqNum = pdu->sqNum;
		            		 	 	 			            				            		 memcpy(stNumPt,&val,1);
		            		 	 	 			            				            		 break;
		            		 	 	 			            				            	 }
		            		 	 	 			            				            	 case 2:
		            		 	 	 			            				            	 {
		            		 	 	 			            				            		 pdu->sqNum = (pdu->sqNum)%(65536);
		            		 	 	 			            				            		 uint16_t val16 = ( uint16_t)pdu->sqNum;
		            		 	 	 			            				            		val16 = htons(val16);
		            		 	 	 			            				            		 memcpy(stNumPt,&val16,2);
		            		 	 	 			            				            		frameID->sqNum = pdu->sqNum;
		            		 	 	 			            				            		 break;
		            		 	 	 			            				            	 }
		            		 	 	 			            				            	 case 4:
		            		 	 	 			            				            	 {
		            		 	 	 			            				            	     pdu->sqNum = (pdu->sqNum)%(4294967296);
		            		 	 	 			            				            	     uint32_t val32 = ( uint32_t)pdu->sqNum;
		            		 	 	 			            				            	     val32 =  htonl(val32);
		            		 	 	 			            				            	     frameID->sqNum = pdu->sqNum;
		            		 	 	 			            				            	     memcpy(stNumPt,&val32,4);
		            		 	 	 			            				            	     break;
		            		 	 	 			            				            	 }


		            		 	 	 			            				            	 }


		            		 	 	 	 	 memcpy(pdu_start+offset, stNumPt,elementLength);


		            		 	 	 	 	time_t curtime;
		            		 	 	 	 			            		 		                 char buffer[80];
		            		 	 	 	 			            		 		                 curtime=tempFrameID->tv.tv_sec;
		            		 	 	 	 			            		 		                 uint32_t curTimeInc = curtime;
		            		 	 	 	 			            		 		                 curTimeInc = htonl(curTimeInc);
		            		 	 	 	 			            		 		                 memcpy(pdu_start + offsetTime,&curTimeInc,4);
		            		 	 	 	 			            		 		                 curtime=tempFrameID->tv.tv_usec;
		            		 	 	 	 			            		 		                 curTimeInc = curtime;
		            		 	 	 	 			            		 		                 curTimeInc = htonl(curTimeInc);
		            		 	 	 	 			            		 		                 memcpy(pdu_start + offsetTime+4,&curTimeInc,4);
		            		 	 	 	 			            		 		            memcpy(&(frameID->tv),&(tempFrameID->tv),sizeof(tempFrameID->tv));

		            		 	 	 	 			            		 		            std::map<std::string,frame_identifier_t*>::iterator it = gooseRefTable.find(pdu->gocbRef);
		            		 	 	 	 			            		 		            if (it != gooseRefTable.end())
		            		 	 	 	 			            		 		            	gooseRefTable.erase (it);


		            		 	 	 	 			            		 		            gooseRefTable.insert( std::pair<std::string,frame_identifier_t*>(pdu->gocbRef,frameID));

		            		 	 	 	 			            		 		            printf("No Change KEY: |%s| SQNum %d StNum %d \n", pdu->gocbRef.c_str(),frameID->sqNum,frameID->stNum);
		            	 		            	 }
		            	 else if(tempFrameID &&  tempFrameID->stNum==frameID->stNum && tempFrameID->sqNum==frameID->sqNum)
		            	 		            	 {
		            	 		            		 //This is a packet that the snort sent
		            	 		            		// LogMessage("KEY: |%s|.SQNum %d \n", pdu->gocbRef->str,tempFrameID->sqNum);

		            	 		            	//	 g_hash_table_insert (gooseRefTable,temp1,frameID); why put old packet information in the hash
		            	 		            	printf("Not Sent KEY: |%s|.SQNum %d StNum %d \n", pdu->gocbRef.c_str(),frameID->sqNum,frameID->stNum);
		            	 		            	 return -1;
		            	 		            	 }
		            	 else
		            	 {
		            		 printf("No Match KEY: |%s|.SQNum %d:%d StNum %d:%d \n", pdu->gocbRef.c_str(),frameID->sqNum,tempFrameID->sqNum,frameID->stNum,tempFrameID->stNum);
		            		 return -1;
		            	 }
		             }
		                 break;

		             case 0x87:
		             {
		            	 pdu->simulation = BerDecoder_decodeBoolean(pdu_start, offset);
		             }
		                 break;

		             case 0x88:
		             {
		            	 pdu->confRev = BerDecoder_decodeUint32(pdu_start, elementLength, offset);
		             }
		                 break;

		             case 0x89:
		             {
		            	 pdu->ndsCom = BerDecoder_decodeBoolean(pdu_start, offset);
		             }
		                 break;

		             case 0x8a:
		             {
		            	 pdu->numDataSetEntries = BerDecoder_decodeUint32(pdu_start, elementLength, offset);
		             }
		                 break;

		             case 0xab:
		             {
		            	  dataOffset = offset;
		            	  dataLength = 0;
		            	 data = new iec61850_Object_header_t [pdu->numDataSetEntries];
		            	 dataTemp = data;
		                 for(int j=0;j<pdu->numDataSetEntries;j++)
		                 {
		                	 uint8_t dataTag = pdu_start[dataOffset++];

		                	 dataOffset = BerDecoder_decodeLength(pdu_start, (int *)&dataLength, dataOffset, (int)gooseHeader.len);


		                		 dataTemp->dataNum = j;
		                		 dataTemp->dataOffsetFromStart =  dataOffset;
		                		 dataTemp->infElementBytesUsed = dataLength;
		                		 dataTemp->type = dataTag;
		                		 memcpy(dataTemp->informationElements,pdu_start+dataOffset,dataLength);




		                	 dataOffset+=dataLength;


		                	 dataSet.push_back( dataTemp);
		                	 dataTemp++;



		                 }
		             }
		                 break;


		             default:

		                 break;
		             }

		             offset += elementLength;
		         }


		         }




 if(modify==1)
 {
		if(modifyData(pdu_start, pdu_length,dataSet,pdu,config))
		{
			//packet->packet_flags|=PKT_MODIFIED;

		}

//		if(stuffUp==0){
//		uint8_t * dataPlusEth= NULL;
//
//			//memcpy(dataPlusEth+sizeof(EtherHdr),packet->vh,sizeof(VlanTagHdr));
//			dataPlusEth = (uint8_t *)malloc(pdu_length+sizeof(EtherHdr));
//			memcpy(dataPlusEth,packet->eh,sizeof(EtherHdr));
//			memcpy(dataPlusEth+sizeof(EtherHdr),pdu_start,pdu_length);
//			Active_SendEth (
//					   packet->pkth, !(packet->packet_flags & ENC_FLAG_FWD),dataPlusEth, pdu_length+sizeof(EtherHdr));
//
//		}
//		}
//
//		else
//		{
//			uint8_t * dataPlusEth = (uint8_t *)malloc(1500); //pdu_length+sizeof(EtherHdr)+sizeof(VlanTagHdr)
//
//					memset(dataPlusEth,'$',1500);
//					memcpy(dataPlusEth,packet->eh,sizeof(EtherHdr));
//					if(packet->vh)
//					{
//					memcpy(dataPlusEth+sizeof(EtherHdr),packet->vh,sizeof(VlanTagHdr));
//					memcpy(dataPlusEth+sizeof(EtherHdr)+sizeof(VlanTagHdr),pdu_start,pdu_length);
//
//
//
//					Active_SendEth (
//							   packet->pkth, !(packet->packet_flags & ENC_FLAG_FWD),dataPlusEth, 1500);
//
//					}
//					else
//					{
//						//memcpy(dataPlusEth+sizeof(EtherHdr),packet->vh,sizeof(VlanTagHdr));
//						memcpy(dataPlusEth+sizeof(EtherHdr),pdu_start,pdu_length);
//						Active_SendEth (
//								   packet->pkth, !(packet->packet_flags & ENC_FLAG_FWD),dataPlusEth, 1500);
//
//					}
//		}
//		struct timespec *requested_time = malloc(sizeof(struct timespec));
//		requested_time->tv_sec = 0;
//		requested_time->tv_nsec =100000;
//		struct timespec *remaining = malloc(sizeof(struct timespec));
//		remaining->tv_nsec = 0;
//		remaining->tv_sec = 0;
		// nanosleep (requested_time, remaining);

 }

 if(pdu)
 delete pdu;
 dataSet.clear();


	return modify;
}







