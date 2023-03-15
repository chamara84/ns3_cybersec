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

/* Snort SV Preprocessor Plugin
 *   by Chamara Devanarayana <chamara@rtds.com> based on libiec61850-1.4.0 https://github.com/mz-automation/libiec61850
 *   Version 0.1.0
 *
 * Purpose:
 *
 * This preprocessor decodes SV packets and is able to modify the data
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

#include "sv-app.h"

 std::multimap<std::string,sv_frame_identifier_t *>  svRefTable;
/*  D E F I N E S  **************************************************/



/*  D A T A   S T R U C T U R E S  **********************************/



/*  G L O B A L S  **************************************************/

/*  P R O T O T Y P E S  ********************************************/
















/**
 * Parse arguments passed to the sv keyword.
 *
 * @param args preprocessor argument string
 *
 * @return void function
 */





int modifyData(uint8_t * pdu_start, uint16_t pdu_length, sv_asdu_header_t* pdu,uint8_t numASDU,SVConfig * config)
{
int modified = 0;
SVConfig* aconfig=config;
sv_Object_header_t* dataEnty=NULL;



for(int index = 0 ; index<aconfig->numAlteredVal;index++)
{
	for(int asduIndex = 0;asduIndex<numASDU;asduIndex++)
	{


		if(pdu[asduIndex].svID.compare(aconfig->values_to_alter[index].svID)==0 )
				            		 {



													modified=1;
													char nullCharactor = '\0';
													int32_t tempIntVal = strtol(aconfig->values_to_alter[index].newVal.c_str(),NULL,10);
													tempIntVal = htonl(tempIntVal);
													//int32_t tempVal = 0;
													int valNumber = aconfig->values_to_alter[index].asduNo;
													char * tempCharVal = (char *)malloc(sizeof(int32_t));
													memcpy(tempCharVal,&tempIntVal,sizeof(int32_t));
													sv_frame_identifier_t* frameID = new sv_frame_identifier_t();
													for(int i=0;i<8;i++)
													{
														//memcpy(&tempVal,pdu_start+pdu[asduIndex].offset+i*8,sizeof(int32_t));
														//memcpy(&tempVal,tempCharVal,4);
														//tempVal*=tempIntVal;
														if(i==valNumber)
															memcpy(pdu_start+pdu[asduIndex].offset+i*8,tempCharVal ,4);
													if(i==0 && asduIndex==0)
													{
														 std::string temp1(pdu[asduIndex].svID);
														 temp1.append(&nullCharactor);

														 frameID->phsor1 = tempIntVal;
														 svRefTable.insert( std::pair<std::string,sv_frame_identifier_t*>(temp1,frameID));

													}

													}
													free(tempCharVal);




	}
	}
}
	return modified;
}

int
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


char*
BerDecoder_decodeString(uint8_t* buffer, int strlen, int bufPos, int maxBufPos)
{
    char* string = (char*) malloc(strlen + 1);
    memcpy(string, buffer + bufPos, strlen);
    string[strlen] = 0;

    return string;
}

 uint32_t
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

 int32_t
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
 float
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

double
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

bool
BerDecoder_decodeBoolean(uint8_t* buffer, int bufPos) {
    if (buffer[bufPos] != 0)
        return true;
    else
        return false;
}




int SVFullReassembly(ns3::Ptr<ns3::NetDevice> device,sv_config_t *config, ns3::Ptr<const ns3::Packet> packet, uint8_t *pdu_start, uint16_t pdu_length)
{


	uint16_t offset = 0;
	sv_header_t svHeader;
	sv_asdu_header_t* pdu = NULL;
	uint8_t noASDU;

	std::vector<sv_Object_header_t*> dataSet;

	 uint16_t dataOffset = 0;
	 uint64_t timeval = 0;
	 uint16_t dataLength = 0;
	 sv_Object_header_t* data =NULL;
	  	 sv_Object_header_t* dataTemp=NULL;
	  	 uint8_t * smpCntPt = (uint8_t *)malloc(2);
	  	 memset(smpCntPt,0,2);
	  	sv_frame_identifier_t* frameID = new sv_frame_identifier_t();

	  	SVConfig* aconfig=config;

 char nullCharactor = '\0';
	 int modify = 0;


	if (pdu_length < (sizeof(sv_header_t) ))
		return -1;

	if ( pdu_length > SV_MAX_ASDU_LENGTH + SV_APCI_LENGTH )

		return -1;
	svHeader.appID = pdu_start[offset++]*0x100;
	svHeader.appID += pdu_start[offset++];
	svHeader.len = pdu_start[offset++]*0x100;
	svHeader.len += pdu_start[offset++];
	svHeader.reserved_1 = pdu_start[offset++]*0x100;
	svHeader.reserved_1 += pdu_start[offset++];
	svHeader.reserved_2 = pdu_start[offset++]*0x100;
	svHeader.reserved_2 += pdu_start[offset++];


	 if (pdu_start[offset] == 0x60)
	 {
		 offset++;
		 int svLength = 0;
		 int bytesInLength = 0;
		 int tempOffset = 0;
		 int elementLength=0;
		  noASDU=0;
		 uint8_t indexASDU = -1;

		 offset = BerDecoder_decodeLength(pdu_start, &svLength, offset, svHeader.len);
		         if (offset < 0) {

		             return -1;
		         }
		         int svEnd = offset + svLength;


		       if(  pdu_start[offset]==0x80)
		       {
		    	   offset++;
		    	   offset = BerDecoder_decodeLength(pdu_start, &elementLength, offset, svHeader.len);
		    	   memcpy(&noASDU,(pdu_start+offset),elementLength);
		    	   offset += elementLength;
		       }


               if(  pdu_start[offset]==0x81)
		       		       {
            	   offset++;
		       		    	   printf("Secure ASDU not processed\n");
		       		    	   return -1;
		       		       }
		       if(  pdu_start[offset]==0xa2)
		    	   offset++;
		       		         		             offset = BerDecoder_decodeLength(pdu_start, &elementLength, offset, svHeader.len);


		       if(pdu_start[offset++]!=0x30)
		       {

		    	   printf("ASDU data not found\n");
		    	   return -1;
		       }

		       offset = BerDecoder_decodeLength(pdu_start, &elementLength, offset, svHeader.len);
		       pdu = new sv_asdu_header_t[noASDU];

		    	   while (offset < svEnd) {


		             uint8_t tag = pdu_start[offset++];
		             offset = BerDecoder_decodeLength(pdu_start, &elementLength, offset, svHeader.len);
		             if (offset < 0) {

		                 return -1;
		             }



		             switch (tag)
		             {
		             case 0x80: /* SV ID */
		             {
		            	 indexASDU++;
		            		 pdu[indexASDU].datSet="";
		            		 	pdu[indexASDU].dataBuffer="";
		            		 	pdu[indexASDU].svID="";
		            		 	std::string tempStr((const char *)(pdu_start+offset),elementLength);
		            	 pdu[indexASDU].svID = tempStr;
		            	 for(int index = 0 ; index<aconfig->numAlteredVal;index++)
		            	 {
		            		 if(modify==0 && pdu[indexASDU].svID.compare(aconfig->values_to_alter[index].svID)==0 )
		            		 {

		            			 modify = 1;
		            			 break;
		            		 }
		            	 }

		            	 if(modify==0)
		            	 {
		            		 if(pdu!=nullptr)
		            		 delete [] pdu;
		            		 return modify;
		            	 }
		             }

		            	 //frameID->gocbref=g_string_new_len( (pdu_start+offset),elementLength);
		                 break;

		             case 0x81: /* dataset */
		             {
		            	 std::string tempStr((const char *)(pdu_start+offset),elementLength);
		            	 pdu[indexASDU].datSet =tempStr;

		            	 for(int index = 0 ; index<aconfig->numAlteredVal;index++)
		            	 		            	 {
		            	 		            		 if(pdu[indexASDU].svID.compare(aconfig->values_to_alter[index].svID)==0 && pdu[indexASDU].datSet.compare(aconfig->values_to_alter[index].datSet))
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


		            	 		            		 return modify;
		            	 		            	 }
		             }
		                 break;

		             case 0x82: /* smpCnt */
		             {
		            	 pdu[indexASDU].smpCnt = BerDecoder_decodeUint32(pdu_start, elementLength, offset);

		            	// frameID->smpCnt = pdu->smpCnt;
		            	// pdu[indexASDU].smpCnt+=1;

		            	 pdu[indexASDU].smpCnt = (pdu[indexASDU].smpCnt)%(4800);
		            	 uint16_t val16 = ( uint16_t)pdu[indexASDU].smpCnt;
		            	 val16 = htons(val16);
		            	 memcpy(smpCntPt,&val16,2);






		            	 memcpy(pdu_start+offset, smpCntPt,elementLength);
		             }

		                 break;

		             case 0x83:
		            	 pdu[indexASDU].confRev =  BerDecoder_decodeUint32(pdu_start, elementLength, offset);
		                 break;

		             case 0x84:
		             {
		                 memcpy(&(pdu[indexASDU].refrTm.tv_sec), pdu_start + offset,elementLength/2);
		                 memcpy(&(pdu[indexASDU].refrTm.tv_usec), pdu_start + offset+4,4);
		                 //timeval = ntohll(timeval);

		                 uint32_t fraction = ntohl(pdu[indexASDU].refrTm.tv_usec)*0x100;


		                 time_t curtime;
		                 char buffer[80];
		                 curtime=ntohl(pdu[indexASDU].refrTm.tv_sec);
		                 uint32_t curTimeInc = curtime+1;
		                 curTimeInc = htonl(curTimeInc);
		                 memcpy(pdu_start + offset,&curTimeInc,4);
		                 struct tm *info = localtime(&curtime );
		                 strftime(buffer,80,"%c %Z", info);
		                 uint32_t nanoseconds = (uint32_t)( ((uint64_t)fraction * 1000000000U) / 0x100000000U ) ;


		             }
		                 break;

		             case 0x85:
		            	 pdu[indexASDU].smpSynch = BerDecoder_decodeUint32(pdu_start, elementLength, offset);




		                 break;

		             case 0x86:
		            	 pdu[indexASDU].smpRate = BerDecoder_decodeUint32(pdu_start, elementLength, offset);

		                 break;

		             case 0x87:
		             {
		            	 pdu[indexASDU].offset = offset;
		            	 std::string tempStr((const char *)(pdu_start+offset),elementLength);
		            	 pdu[indexASDU].dataBuffer = tempStr;
		            	 pdu[indexASDU].dataBufferLength=elementLength;
		            	 //should know which data there is to decode the data buffer. In 9-2LE there are 10 phasors all are scaled to int32
		            	 int32_t tempPhasor;
		            	 memcpy(&tempPhasor,pdu[indexASDU].dataBuffer.c_str(),4);
		            	 frameID->phsor1 = tempPhasor;
		            	 char *orig_Key;
		            	 		            	 		            	 sv_frame_identifier_t* tempFrameID;
		            	 		            	 		            	 std::string tempLookup =pdu[indexASDU].svID;
		            	 		            	 		            	 tempLookup.append(&nullCharactor);
		            	 		            	 		            	 if(dataSet.size()==0)
		            	 		            	 		            	 {
		            	 		            	 		            	 tempFrameID = svRefTable.find(tempLookup)->second;

		            	 		            	 		            	 if(tempFrameID && tempFrameID->phsor1==frameID->phsor1 )
		            	 		            	 		            	 {
		            	 		            	 		            		printf("Dropped KEY: |%s|.SQNum %d \n", pdu[indexASDU].svID.c_str(),pdu[indexASDU].smpCnt);

		            	 		            	 		            				 if(pdu)
		            	 		            	 		            						 delete pdu;
		            	 		            	 		            	 return modify;
		            	 		            	 		            	 }
		            	 		            	 		            	 }


		            	 //		  moved to modify          	 		            	 else
		            	 //		            	 		            	 {
		            	 //		            	 		            		frameID->smpCnt++;
		            	 //		            	 		            		frameID->smpCnt=(frameID->smpCnt)%(4800) ;
		            	 //		            	 		            		 char * temp2 = strdup(pdu->svID->str);
		            	 //		            	 		            		 		            	 strcat(temp2,&nullCharactor);
		            	 //		            	 		            		 g_hash_table_insert (svRefTable,temp2,frameID);
		            	 //
		            	 //
		            	 //		            	 		            	 }
		            	 		            	 		            	printf("Accept KEY: |%s|.SQNum %d \n", pdu[indexASDU].svID.c_str(),pdu[indexASDU].smpCnt);
		             }
		                 break;

		             case 0x88:
		             		            	 pdu[indexASDU].smpMod = BerDecoder_decodeUint32(pdu_start, elementLength, offset);

		             		                 break;


//		             case 0xab:
//
//		            	  dataOffset = offset;
//		            	  dataLength = 0;
//		            	 data = g_new0(sv_Object_header_t,pdu->numDataSetEntries);
//		            	 dataTemp = data;
//		                 for(int j=0;j<pdu->numDataSetEntries;j++)
//		                 {
//		                	 uint8_t dataTag = pdu_start[dataOffset++];
//
//		                	 dataOffset = BerDecoder_decodeLength(pdu_start, &dataLength, dataOffset, svHeader.len);
//
//
//		                		 dataTemp->dataNum = j;
//		                		 dataTemp->dataOffsetFromStart =  dataOffset;
//		                		 dataTemp->infElementBytesUsed = dataLength;
//		                		 dataTemp->type = dataTag;
//		                		 memcpy(dataTemp->informationElements,pdu_start+dataOffset,dataLength);
//
//
//
//
//		                	 dataOffset+=dataLength;
//
//
//		                	 dataSet = g_slist_append(dataSet,dataTemp);
//		                	 dataTemp++;
//
//
//
//		                 }
//
//		                 break;

		             default:

		                 break;
		             }

		             offset += elementLength;


		         }


		         }




 if(modify==1)
 {
		if(modifyData(pdu_start,pdu_length, pdu,noASDU, config))

		{
//		Active_SendEth (
//		   packet->pkth, !(packet->packet_flags & ENC_FLAG_FWD),dataPlusEth, packet->dsize+sizeof(EtherHdr));
		for(int asduIndex = 0;asduIndex<noASDU;asduIndex++)
		 	{
			printf("In Modify KEY: |%s|.SQNum %d \n", pdu[asduIndex].svID.c_str(),pdu[asduIndex].smpCnt);


		 	}
		}
		 if(pdu)
				  delete [] pdu;
 }

	return modify;
}

