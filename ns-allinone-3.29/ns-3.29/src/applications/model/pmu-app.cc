/*
 * pmu-app.cc
 *
 *  Created on: Oct. 12, 2022
 *      Author: chamara
 */

#include "pmu-app.h"

static unsigned short CalcCrc16(uint8_t* data, int length)
		{
		  unsigned short crc = 0xFFFF; /*0xFFFF -> 0x0 -> 0xFFFF;*/
		  unsigned short temp;
		  unsigned short quick;
		  unsigned int crcIdx;
		  unsigned char *bufPtr = (unsigned char *)data;

		  for(crcIdx = 0; crcIdx < length ;crcIdx++){
		    temp = (crc >> 8) ^ bufPtr[crcIdx];
		    crc <<= 8;
		    quick = temp ^ (temp >> 4);
		    crc ^= quick;
		    quick <<= 5;
		    crc ^= quick;
		    quick <<= 7;
		    crc ^= quick;
		  }
		  return crc;
		}

static std::string trimwhitespace(std::string str)
{
	const std::string WHITESPACE = " \n\r\t\f\v";
	size_t start = str.find_first_not_of(WHITESPACE);
	str = (start == std::string::npos) ? "" : str.substr(start);
	size_t end = str.find_last_not_of(WHITESPACE);

	return (end == std::string::npos) ? "" : str.substr(0, end + 1);

}


static int modifyData(pmu_config_t *config, pmu_session_data_t *session,uint8_t *pdu_start, uint16_t pdu_length)
{
	int modified = 0;
	int pmuNumber =0;
	int phasorNumber = 0;
	int analogNumber = 0;
	int digitalNumber = 0;
	int startingIndex = 0;
	int numPhasors, numAnalog, numDigital;
	int bytesToSkip=16;
	int bytesPerPhasor=4;
	int bytesPerAnalog=4;
	int bytesPerDigital=4;
	int bytesPerFrequency=4;
	std::string phasorName;
	std::string analogName;
	std::string digitalName;
	uint32_t* pktOffset ;

	std::string PMUName  ;
	unsigned short crc;
	float temp=0;
	uint32_t a=0;
	uint32_t b = 0;
	uint16_t aShort= 0;
	uint16_t bShort = 0;
	std::string tempArray;
	uint8_t  tempValueToCopy[4];
	double realValue, imaginaryValue;
	if(session->FrameData.length() >= pdu_length){
		for(int index =0;index<config->numAlteredVal;index++)
			{
				tempArray.clear();
				std::string PMUId = config->values_to_alter[index].pmuName;
				tempArray = trimwhitespace(PMUId);

				std::string Id = config->values_to_alter[index].identifier;
				tempArray = tempArray + trimwhitespace(Id);

				if((session->pmuRefTable).find(tempArray)==(session->pmuRefTable).end())
					continue;

				pktOffset = ((session->pmuRefTable).find(tempArray))->second;


				startingIndex = *pktOffset-(session->FrameData.length() -pdu_length);    // buflen is the length of data in the current packet

				if(config->values_to_alter[index].type == 0){
					if(startingIndex<0 && abs(startingIndex)>=(*(pktOffset+1))/2)
					{

						printf("you have missed the point\n");
						//you have missed the point
						continue;
					}

					else if(startingIndex<0 && abs(startingIndex)<(*(pktOffset+1))/2)
					{
						printf("the data is split between two packets\n");
						//the data is split between two packets


					}

					else if(startingIndex > pdu_length)
					{
						printf("the data is in a future packet\n");
						continue;

					}
					else{
						printf("the data is in the current packet\n");
						//entire data is in the current packet
					}
					//TODO: need to change the modification to match the data type
					temp = config->values_to_alter[index].real_value;

					a = *((uint32_t*)&temp ); // reinterpret as uint32
					b = htonl(a);			 // switch endianness: host-to-net
					temp = *((float*)&b);
					memcpy((pdu_start+startingIndex),&temp,(*(pktOffset+1))/2);
					temp = config->values_to_alter[index].imaginary_value;
					a = *((uint32_t*)&temp ); // reinterpret as uint32
					b = htonl(a);			 // switch endianness: host-to-net
					temp = *((float*)&b);

					memcpy((pdu_start+startingIndex+(*(pktOffset+1))/2),&temp,(*(pktOffset+1))/2);

					modified = 1;


				}
				else if(config->values_to_alter[index].type == 1){
					if(startingIndex<0 && abs(startingIndex)>=(*(pktOffset+1)))
					{

						printf("you have missed the point\n");
						//you have missed the point
						continue;
					}

					else if(startingIndex<0 && abs(startingIndex)<(*(pktOffset+1)))
					{
						printf("the data is split between two packets\n");
						//the data is split between two packets


					}

					else if(startingIndex > pdu_length)
					{
						printf("the data is in a future packet\n");
						continue;

					}
					else{
						printf("the data is in the current packet\n");
						//entire data is in the current packet
					}
					//TODO: need to change the modification to match the data type
					temp = config->values_to_alter[index].real_value;

					a = *((uint32_t*)&temp ); // reinterpret as uint32
					b = htonl(a);			 // switch endianness: host-to-net
					temp = *((float*)&b);
					memcpy((pdu_start+startingIndex),&temp,(*(pktOffset+1)));


					modified = 1;


				}

				else if(config->values_to_alter[index].type == 2){
					if(startingIndex<0 && abs(startingIndex)>=(*(pktOffset+1)))
					{

						printf("you have missed the point\n");
						//you have missed the point
						continue;
					}

					else if(startingIndex<0 && abs(startingIndex)<(*(pktOffset+1)))
					{
						printf("the data is split between two packets\n");
						//the data is split between two packets


					}

					else if(startingIndex > pdu_length)
					{
						printf("the data is in a future packet\n");
						continue;

					}
					else{
						printf("the data is in the current packet\n");
						//entire data is in the current packet
					}
					//TODO: need to change the modification to match the data type
					aShort = config->values_to_alter[index].digValue;


					bShort = htons(aShort);			 // switch endianness: host-to-net

					memcpy((pdu_start+startingIndex),&bShort ,(*(pktOffset+1)));


					modified = 1;


				}


				if(modified)
				{
					crc = CalcCrc16(pdu_start, pdu_length-2);
					crc = htons(crc);
					memcpy((pdu_start+pdu_length-2),&crc,2);
				}
			}
//	for(int index =0;index<config->numAlteredVal;index++)
//	{
//		GString *PMUId = config->values_to_alter[index].pmuName;
//		GString *Id = config->values_to_alter[index].identifier;
//		uint8_t type = config->values_to_alter[index].type;
//		C37118PmuConfiguration *pmuIntest = (C37118PmuConfiguration *)session->pmuConfig2.PMUs->data;
//			GSList *nextPMU = (C37118PmuConfiguration *)session->pmuConfig2.PMUs->next;
//			bytesToSkip=16;
//			pmuNumber = 0;
//		while(pmuIntest){
//			numPhasors = pmuIntest->numPhasors;
//						numAnalog = pmuIntest->numAnalog;
//						numDigital = pmuIntest->numDigital;
//
//						if(pmuIntest->DataFormat.Bit1_0xPhasorsIsInt_1xPhasorFloat)
//														{
//															bytesPerPhasor=8;
//														}
//						if(pmuIntest->DataFormat.Bit2_0xAnalogIsInt_1xAnalogIsFloat)
//																				{
//																					bytesPerAnalog=8;
//																				}
//						if(pmuIntest->DataFormat.Bit3_0xFreqIsInt_1xFreqIsFloat)
//																									{
//																										bytesPerFrequency=8;
//																									}
//
//			PMUName = g_string_overwrite_len(PMUName, 0,pmuIntest->StationName->str,((GString *)pmuIntest->StationName)->len);
//
//			PMUName = g_string_truncate(PMUName,PMUId->len);
//			if(!g_string_equal(PMUId,PMUName) )
//			{
//				if(nextPMU!=NULL){
//							pmuNumber++;
//							pmuIntest = (C37118PmuConfiguration *)nextPMU->data;
//							nextPMU = (C37118PmuConfiguration *)nextPMU ->next;
//							}
//
//
//							else
//								pmuIntest = NULL;
//
//				bytesToSkip+=2+numPhasors*bytesPerPhasor+bytesPerFrequency+numAnalog*bytesPerAnalog+numDigital*2;
//				phasorNumber = 0;
//				continue;
//
//				//need to find the offset of the phasor data for subsequent PMUs
//			}
//			GSList * nextPhasor = pmuIntest->phasorChnNames->next;
//            if(pmuIntest->phasorChnNames->data)
//			phasorName = g_string_overwrite_len(phasorName, 0,((GString *)pmuIntest->phasorChnNames->data)->str,((GString *)pmuIntest->phasorChnNames->data)->len);
//            if(pmuIntest->analogChnNames && pmuIntest->analogChnNames->data)
//			analogName = g_string_overwrite_len(analogName, 0,((GString *)pmuIntest->analogChnNames->data)->str,((GString *)pmuIntest->analogChnNames->data)->len);
//            if(pmuIntest->digitalChnNames && pmuIntest->digitalChnNames->data)
//			digitalName = g_string_overwrite_len(digitalName, 0,((GString *)pmuIntest->digitalChnNames->data)->str,((GString *)pmuIntest->digitalChnNames->data)->len);
//			// phasor values
//			if(config->values_to_alter[index].type == 0){
//
//			while(phasorName)
//			{
//				phasorName = g_string_truncate(phasorName,Id->len);
//				if(g_string_equal(Id,phasorName) )
//				{
//					bytesToSkip+=phasorNumber*bytesPerPhasor;
//					_dpd.logMsg("PMU %d bytes to skip :%d\n",pmuNumber,bytesToSkip);
//					if(bytesPerPhasor==8)
//					{
//						temp = config->values_to_alter[index].real_value;
//
//						uint32_t a = *((uint32_t*)&temp ); // reinterpret as uint32
//							uint32_t b = htonl(a);			 // switch endianness: host-to-net
//							temp = *((float*)&b);
//
//							// should calculate the offset of the packet taking the multi fragment message to account
//
//
//
//							startingIndex = bytesToSkip-(session->FrameData->len-packet->payload_size);    // buflen is the length of data in the current packet
//											if(startingIndex<0 && abs(startingIndex)>=(bytesPerPhasor))
//											{
//
//												_dpd.logMsg("you have missed the point\n");
//												//you have missed the point
//												continue;
//											}
//
//											else if(startingIndex<0 && abs(startingIndex)<(bytesPerPhasor))
//											{
//												_dpd.logMsg("the data is split between two packets\n");
//												//the data is split between two packets
//
//
//											}
//
//											else if(startingIndex > packet->payload_size)
//											{
//												_dpd.logMsg("the data is in a future packet\n");
//												continue;
//
//											}
//											else{
//												_dpd.logMsg("the data is in the current packet\n");
//												//entire data is in the current packet
//											}
//
//						memcpy((packet->payload+startingIndex),&temp,4);
//						temp = config->values_to_alter[index].imaginary_value;
//						 a = *((uint32_t*)&temp ); // reinterpret as uint32
//													 b = htonl(a);			 // switch endianness: host-to-net
//													temp = *((float*)&b);
//
//						memcpy((packet->payload+startingIndex+4),&temp,4);
//						crc = CalcCrc16(packet->payload, packet->payload_size-2);
//						crc = htons(crc);
//						memcpy((packet->payload+packet->payload_size-2),&crc,2);
//						modified = 1;
//						break;
//					}
//					//write a function to modify the packet data
//
//
//				}
//				phasorNumber++;
//				if(nextPhasor){
//					phasorName = g_string_overwrite_len(phasorName, 0,((GString *)nextPhasor->data)->str,((GString *)nextPhasor->data)->len);
//
//				nextPhasor = nextPhasor->next;
//				}
//				else
//					phasorName = NULL;
//			}
//
//			}
//
//			//analog values
//
//
//			if(config->values_to_alter[index].type == 1){
//
//			while(analogName)
//			{
//				analogName = g_string_truncate(analogName,Id->len);
//				if(g_string_equal(Id,analogName) )
//				{
//					bytesToSkip+=analogNumber*bytesPerPhasor;
//					_dpd.logMsg("PMU %d bytes to skip :%d\n",pmuNumber,bytesToSkip);
//					if(bytesPerPhasor==8)
//					{
//						temp = config->values_to_alter[index].real_value;
//
//						uint32_t a = *((uint32_t*)&temp ); // reinterpret as uint32
//							uint32_t b = htonl(a);			 // switch endianness: host-to-net
//							temp = *((float*)&b);
//
//							// should calculate the offset of the packet taking the multi fragment message to account
//
//
//
//							startingIndex = bytesToSkip-(session->FrameData->len-packet->payload_size);    // buflen is the length of data in the current packet
//											if(startingIndex<0 && abs(startingIndex)>=(bytesPerPhasor))
//											{
//
//												_dpd.logMsg("you have missed the point\n");
//												//you have missed the point
//												continue;
//											}
//
//											else if(startingIndex<0 && abs(startingIndex)<(bytesPerPhasor))
//											{
//												_dpd.logMsg("the data is split between two packets\n");
//												//the data is split between two packets
//
//
//											}
//
//											else if(startingIndex > packet->payload_size)
//											{
//												_dpd.logMsg("the data is in a future packet\n");
//												continue;
//
//											}
//											else{
//												_dpd.logMsg("the data is in the current packet\n");
//												//entire data is in the current packet
//											}
//
//						memcpy((packet->payload+startingIndex),&temp,4);
//						temp = config->values_to_alter[index].imaginary_value;
//						 a = *((uint32_t*)&temp ); // reinterpret as uint32
//													 b = htonl(a);			 // switch endianness: host-to-net
//													temp = *((float*)&b);
//
//						memcpy((packet->payload+startingIndex+4),&temp,4);
//						crc = CalcCrc16(packet->payload, packet->payload_size-2);
//						crc = htons(crc);
//						memcpy((packet->payload+packet->payload_size-2),&crc,2);
//						modified = 1;
//						break;
//					}
//					//write a function to modify the packet data
//
//
//				}
//				phasorNumber++;
//				if(nextPhasor){
//					phasorName = g_string_overwrite_len(phasorName, 0,((GString *)nextPhasor->data)->str,((GString *)nextPhasor->data)->len);
//
//				nextPhasor = nextPhasor->next;
//				}
//				else
//					phasorName = NULL;
//			}
//
//			}
//
//			if(nextPMU!=NULL){
//			pmuNumber++;
//			pmuIntest = (C37118PmuConfiguration *)nextPMU->data;
//			nextPMU = (C37118PmuConfiguration *)nextPMU ->next;
//			}
//
//
//			else
//				pmuIntest = NULL;
//		}
//	}
	}


return modified;
}

static int extractFrameHdr(pmu_session_data_t *session,const uint8_t *data,int length, int *offsetOrg)
{
	int offset = *offsetOrg;
	offset = 0;
	session->Sync.LeadIn = *(data+offset);
	offset++;
	uint8_t rawVerType = *(data+offset);
	session->Sync.Version = rawVerType & 0xF;
	session->Sync.FrameType = (C37118HdrFrameType)((rawVerType & 0x70) >> 4);
	offset++;
	memcpy(&(session->FrameSize),(data+offset),2);
	session->FrameSize = ntohs(session->FrameSize);
	offset+=2;
	memcpy(&(session->IdCode),(data+offset),2);
	session->IdCode = ntohs(session->IdCode);
	offset+=2;
	memcpy(&(session->SOC),(data+offset),4);
	session->SOC = ntohl(session->SOC);
	offset+=4;

	uint32_t raw;
	memcpy(&raw,(data+offset),4);
	raw = ntohl(raw);
	(session->FracSec).TimeQuality = (raw & 0xFF000000) >> 24;
	session->FracSec.FractionOfSecond = (raw & 0x00FFFFFF);
	offset+=4;
	*offsetOrg = offset;


return 0;
}

//this function should save the configuration data and build a hash table to have PMU_NAMEValueName as the key and the offset of data in the message



static int extractConfig2Data(pmu_session_data_t *session,const uint8_t *data,int length, int *offsetOrg)
{
	uint32_t raw;
	int offset = *offsetOrg;
	int offsetDataFrame = 14;
	int sizeOfPhasor = 4;
	int sizeOfAnalog = 2;
	int sizeOfFreq = 4;
	uint32_t * tempPointer;
	printf("init offset:%d\n",offset);
	memcpy(&raw,(data+offset),4);
	session->pmuConfig2.TimeBase.Flags = (raw & 0xFF000000) >> 24;
	session->pmuConfig2.TimeBase.TimeBase = (raw & 0x00FFFFFF);
	offset+=4;
	memcpy(&(session->pmuConfig2.NumPMU),(data+offset),2);
	session->pmuConfig2.NumPMU = ntohs(session->pmuConfig2.NumPMU);
	std::list<C37118PmuConfiguration *> tmp;
	std::string tempString ;

	std::list<C37118PmuConfiguration *>::iterator it;


	offset+=2;
	// Read STN
	for( int ipmu = 0; ipmu < session->pmuConfig2.NumPMU; ++ipmu )
	{	 sizeOfPhasor = 4;
	 	 sizeOfAnalog = 2;
	 	sizeOfFreq = 4;
	 	offsetDataFrame+=2;
		printf("PMU %d offset:%d\n",ipmu,offset);
		C37118PmuConfiguration* pmuCfg = new C37118PmuConfiguration;
       char string[17];
       std::
       memset(string,NULL,17);
		// Read STN
       memcpy(string,(data+offset),16);
       std::string temp(string);
    	   pmuCfg->StationName = temp;


       offset+=16;

	// Read IDCODE
       memcpy(&pmuCfg->IdCode,(data+offset),2);
       pmuCfg->IdCode = ntohs(pmuCfg->IdCode);
       offset+=2;

		// Read FORMAT

	uint16_t rawformat=0;
	memcpy(&rawformat,(data+offset),2);
	rawformat =  ntohs(rawformat);
	pmuCfg->DataFormat.Bit0_0xPhasorFormatRect_1xMagnitudeAndAngle	= (rawformat & (1 << 0)) != 0;
	pmuCfg->DataFormat.Bit1_0xPhasorsIsInt_1xPhasorFloat				= (rawformat & (1 << 1)) != 0;
	if(pmuCfg->DataFormat.Bit1_0xPhasorsIsInt_1xPhasorFloat)
		sizeOfPhasor=8;
	pmuCfg->DataFormat.Bit2_0xAnalogIsInt_1xAnalogIsFloat				= (rawformat & (1 << 2)) != 0;
	if (pmuCfg->DataFormat.Bit2_0xAnalogIsInt_1xAnalogIsFloat)
		sizeOfAnalog = 4;
	pmuCfg->DataFormat.Bit3_0xFreqIsInt_1xFreqIsFloat					= (rawformat & (1 << 3)) != 0;

	if(pmuCfg->DataFormat.Bit3_0xFreqIsInt_1xFreqIsFloat)
		sizeOfFreq = 8;
	offset+=2;
		// Read PHNMR / ANNMR / DGNMR

	memcpy(&rawformat,(data+offset),2);
	pmuCfg->numPhasors =   ntohs(rawformat);
	offset+=2;

	memcpy(&rawformat,(data+offset),2);
	pmuCfg->numAnalog =   ntohs(rawformat);
	offset+=2;



		memcpy(&rawformat,(data+offset),2);
		pmuCfg->numDigital =   ntohs(rawformat);
			offset+=2;

	// Read CHNAM - phasors


				pmuCfg->phasorChnNames.clear();
				pmuCfg->digitalChnNames.clear();
				pmuCfg->analogChnNames.clear();
		for( int i = 0; i < pmuCfg->numPhasors; ++i ){
			memcpy(string,(data+offset),16);
            offset+=16;
            pmuCfg->phasorChnNames.push_back( std::string(string));

            tempString = trimwhitespace(pmuCfg->StationName);
            tempString = tempString+trimwhitespace(std::string(string));

            uint32_t *offsetAndSizeOfData = (uint32_t *)malloc(sizeof(uint32_t)*2);
            		            *offsetAndSizeOfData = offsetDataFrame;
            		            tempPointer = offsetAndSizeOfData;
            		            offsetAndSizeOfData++;
            		            *offsetAndSizeOfData = sizeOfPhasor;
            		            session->pmuRefTable.insert( std::pair<std::string,uint32_t*>(std::string(tempString), tempPointer));
          printf("Key %.*s offset:%d size of one point %d\n",tempString.length(),tempString.c_str(),*tempPointer,*offsetAndSizeOfData);
            offsetDataFrame+=sizeOfPhasor;
           tempString.clear();
		}
		offsetDataFrame+=sizeOfFreq;
		// Read CHNAM - analog
	for( int i = 0; i < pmuCfg->numAnalog; ++i ){

		memcpy(string,(data+offset),16);
		            offset+=16;
		            pmuCfg->analogChnNames.push_back( std::string(string));
		            tempString = trimwhitespace(pmuCfg->StationName);
		            tempString += trimwhitespace(string);
		            uint32_t *offsetAndSizeOfData = (uint32_t *)malloc(sizeof(uint32_t)*2);
		                        		            *offsetAndSizeOfData = offsetDataFrame;
		                        		            tempPointer = offsetAndSizeOfData;
		                        		            offsetAndSizeOfData++;
		            *offsetAndSizeOfData = sizeOfAnalog;
		                        session->pmuRefTable.insert(std::make_pair(tempString, tempPointer));


		                        printf("Key %.*s offset:%d size of one point %d\n",tempString.length(),tempString.c_str(),*tempPointer,*offsetAndSizeOfData);
		                        offsetDataFrame+=sizeOfAnalog;
		                        tempString.clear();


	}
		// Read CHNAM - dig chns
		for( int i = 0; i < pmuCfg->numDigital*16; ++i ){
			memcpy(string,(data+offset),16);
			offset+=16;
			pmuCfg->digitalChnNames.push_back( std::string(string)) ;
			tempString = trimwhitespace(pmuCfg->StationName);
			tempString += trimwhitespace(std::string(string));
			uint32_t *offsetAndSizeOfData = (uint32_t *)malloc(sizeof(uint32_t)*2);
			*offsetAndSizeOfData = offsetDataFrame;
			tempPointer = offsetAndSizeOfData;
			offsetAndSizeOfData++;
			*offsetAndSizeOfData = 2;
			session->pmuRefTable.insert(std::make_pair(tempString,tempPointer));

			printf("Key %.*s offset:%d size of one point %d\n",tempString.length(),tempString.c_str(),*tempPointer,*offsetAndSizeOfData);
			if(i!=0 && i%15==0)
				offsetDataFrame+=2;
			tempString.clear();

		}
		// Read PHUNIT
		pmuCfg->PhasorUnit.clear();
		for( int i = 0; i < pmuCfg->numPhasors; ++i )
		{
			uint32_t raw;
			C37118PhasorUnit * phunit = (C37118PhasorUnit * )malloc(sizeof(C37118PhasorUnit));
			memcpy(&raw,(data+offset),4);
			offset+=4;
			raw = ntohl(raw);
			phunit->Type = (raw & 0xFF000000) >> 24;
			phunit->PhasorScalar = (raw & 0x00FFFFFF);

			pmuCfg->PhasorUnit.push_back(phunit) ;
		}
		// Read ANUNIT
		pmuCfg->AnalogUnit.clear();

		for( int i = 0; i < pmuCfg->numAnalog; ++i )
		{
			uint32_t raw;
			C37118AnalogUnit * anunit =  new C37118AnalogUnit ;
			memcpy(&raw,(data+offset),4);
			offset+=4;
			raw = ntohl(raw);
			anunit->Type_X = (raw & 0xFF000000) >> 24;
			anunit->AnalogScalar = (raw & 0x00FFFFFF); // TODO: REVIEW - UNSIGNED / SIGNED

			pmuCfg->AnalogUnit.push_back(anunit) ;
		}


		// Read DIGUINT
		pmuCfg->DigitalUnit.clear();
		for( int i = 0; i < pmuCfg->numDigital; ++i )
		{
			uint16_t raw;
			C37118DigitalUnit * digUnit =  new C37118DigitalUnit;
			memcpy(&raw,(data+offset),2);
			offset+=2;
			raw = ntohs(raw);

			digUnit->DigNormalStatus = raw;
			memcpy(&raw,(data+offset),2);
			offset+=2;
			raw = ntohs(raw);

			digUnit->DigValidInputs = raw;
			pmuCfg->DigitalUnit.push_back(digUnit);
		}


		// Read FNOM

		uint16_t raw;
		memcpy(&raw,(data+offset),2);
		offset+=2;
		raw = ntohs(raw);
		pmuCfg->NomFreqCode.Bit0_1xFreqIs50_0xFreqIs60 = raw & 0x1;


		// Read CFGCNT
		memcpy(&raw,(data+offset),2);
		offset+=2;
		raw = ntohs(raw);
		pmuCfg->ConfChangeCnt = raw;

		// Add PMU to the list
		session->pmuConfig2.PMUs.push_back(pmuCfg);
		printf("End PMU %d offset:%d\n",ipmu,offset);
	}

	// Read DATA_RATE
	memcpy(&raw,(data+offset),2);
	offset+=2;
	raw = ntohs(raw);
	session->pmuConfig2.DataRate.m_datarateRaw = raw;
	memcpy(&raw,(data+offset),2);
	offset+=2;
	raw = ntohs(raw);
	// Read CRC16
	session->pmuConfig2.FooterCrc16 = raw;
	*offsetOrg = offset;

	session->capturedConfig2 = 1;
return 0;
}




int PMUDecode(pmu_session_data_t *session,pmu_config_t *config,uint8_t *pdu_start, uint16_t pdu_length)
{




    if(*(pdu_start)!=0xaa && session->partialData!=1) //1 is for on going construction
    	return 0 ;


    int offset = 0;

    if(session->partialData==0 && *(pdu_start)==0xaa)
    {
    	memcpy(&(session->FrameSize),(pdu_start +2),2);
    	    session->FrameSize = ntohs(session->FrameSize);

    session->FrameData = std::string((const char *)pdu_start,pdu_length);
    if(session->FrameSize>pdu_length)
    {

    	session->partialData=1;
    }
    else
    	session->partialData=3;

    }

    else if(session->partialData==1 && *(pdu_start)!=0xaa )
    {

    	session->FrameData +=std::string((const char *)pdu_start,pdu_length);
    	if(session->FrameSize<=session->FrameData.length())
    	    {

    	    	session->partialData=3;
    	    }
    }

    else if((session->partialData==3 || session->partialData==1) && *(pdu_start)==0xaa)
        {
        	session->FrameData.clear();

        	memcpy(&(session->FrameSize),(pdu_start +2),2);
        	    session->FrameSize = ntohs(session->FrameSize);


        	        session->FrameData = std::string((const char *)pdu_start,pdu_length);

        	if(session->FrameSize>session->FrameData.length())
        	    {

        	    	session->partialData=1;
        	    }
        	else
        		session->partialData=3;
        }
    else
    {

    	session->FrameData.clear();
    	session->partialData=0;
    	printf("Wrong condition\n");
    	return 0;
    }



    /* Lay the header struct over the payload */
    if(session->FrameData.length()>=PMU_MIN_LEN)
    {
    	offset = 0;
       extractFrameHdr(session,(const unsigned char *)session->FrameData.c_str(),session->FrameData.length(), &offset);

   switch( session->Sync.FrameType)
   {
   case(DATA_FRAME):
		/*
		         * Add code here to modify the data
		         */
		    if(session->capturedConfig2){
		        if(modifyData(config, session, pdu_start, pdu_length))
		        {

		        printf("Got to Modify Data\n");
		        }
		    }
	  printf("Got a Data frame\n");
   break;
   case(CONFIGURATION_FRAME_2):

		if(session->partialData==3)
		{
		   if(!(session->pmuConfig2).PMUs.empty())
		   {
			   //should free individual memory
		   std::list<C37118PmuConfiguration *>::iterator temp;
			   for ( temp =(session->pmuConfig2.PMUs).begin();temp!=(session->pmuConfig2).PMUs.end(); ++temp){delete(*temp);}

			   (session->pmuConfig2).PMUs.clear();
	   }
		extractConfig2Data(session,(const unsigned char *)session->FrameData.c_str(),session->FrameData.length(), &offset);

		    	session->FrameData.clear();
		    	session->partialData=0;
		}
		 printf("Got a Config 2 frame\n");
		   break;
   case(COMMAND_FRAME):
		if(session->partialData==3)
				{



				    	session->FrameData.clear();
				    	session->partialData=0;
				}
   		 printf("Got a command frame\n");
   		   break;
   default:
	   break;
   }


    }

    return PMU_OK;
}



