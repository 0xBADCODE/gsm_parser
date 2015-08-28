/* GSM Network Parser
 * Copyright (c) Xeon 2015
 *
 * gcc gsm_parser.c -o gsm_parser -ggdb -W -l sqlite3 -m64
 *
 * Pull GSM Network information from stream captures.
 * (network(MCC), country(MNC), cell id, LAC, TMSI, IMSI, cell barred, list of ARFCNs)
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */
 
/* TODO
 * load from cfile
 * calc bcd IMSI from hex
 */

#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <sqlite3.h>

#include "xeon.h"

#define PROG_NAME "GSM Network Parser"
#define BUFFER_SIZE 6291456 //6 Mibibytes
#define GSMheader_size 16
#define GSMframe_size 23

unsigned int verbosity = 0;

void usage()
{
	printf("\nUsage: %s [options]\n", PROG_NAME);
	printf( "\n\t-d \tDownlink frequency captured in MHz. (e.g. 900)"
			"\n\t-f \tFile to be parsed. (Pcap|cfile)"
			"\n\t\tUse \"-\" for stdin"
			"\n\t-h \thelp!"
			"\n\t-v \tverbosity\n\n");
	exit(-1);
}

void greeting()
{
	printf("\n%s. %s 2015\n\n", PROG_NAME, COPYRIGHT);
	return;
}

void main(int argc, char **argv)
{
	greeting();

	char x, *f = NULL, *d = NULL, GSMband[9] = {0};

	int fflag = 0, dflag = 0;

	opterr = 0;

	while ((x = getopt(argc, argv, "f:d:hv")) != -1)
		switch (x)
		{
			case 'f':
				if(fflag)
					printf("Warning: -f is set multiple times\n");
				fflag = 1;
				f = optarg;
				
				break;

			case 'd':
				if(dflag)
					printf("Warning: -d is set multiple times\n");
				dflag = 1;
				d = optarg;

				break;

			case 'h':
				usage();

				break;
			
			case 'v':
				verbosity++;

				break;

			default:
				usage();
		}

	if(f == NULL) {
		fprintf(stderr, "missing -f option, no capture file provided\n");
		usage();
	}
	if(d == NULL) {
		fprintf(stderr, "*missing downlink frequency, will not calculate TDMA\n");
	}
	else {
		int freq = strtol(d, NULL, 10);

		/* Determine GSM band from downlink freq */
		if(freq < 460.6 || freq > 1989.8) {
			fprintf(stderr, "*frequency out of range.\n");
			exit(1);
		}
		else if(freq >= 460 && freq < 468)
			strncpy(GSMband, "GSM-450", 7);
		else if(freq >= 489 && freq < 496)
			strncpy(GSMband, "GSM-480", 7);
		else if(freq >= 747 && freq < 763)
			strncpy(GSMband, "GSM-750", 7);
		else if(freq >= 869 && freq < 894)
			strncpy(GSMband, "GSM-850", 7);
		else if(freq >= 935 && freq < 960)
			strncpy(GSMband, "GSM-900", 7);
		else if(freq >= 1805 && freq < 1880)
			strncpy(GSMband, "GSM-1800", 8);
		else if(freq >= 1930 && freq < 1990)
			strncpy(GSMband, "GSM-1900", 8);
		else {
		printf("*frequency does not correspond to a known GSM downlink.\n");
			exit(1);
		}

		printf("Selecting %s as GSM band.\n", GSMband);
	}

	unsigned int 	i, j, m, n, c, v,
					bytes,
					IA, IAext, PR1, PR2, SYS1, SYS2, SYS2ter, SYS2quater, SYS3, SYS4, SYS13,
					LAI[5] = {0},
					MCC,
					MNC,
					LAC,
					ARFCN[124] = {0};

	long			cellID;

	bool			cellBarred,
					binary[8],
					cid[16];

	unsigned char 	buffer[BUFFER_SIZE] = {0},
					array[90000][GSMframe_size],
					pcapheader[40] = {0},
					GSMheader[GSMheader_size] = {0x02, 0x04, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00};

	/* Database */
	sqlite3 *database;
	sqlite3_stmt *result;
	int retval;

	retval = sqlite3_open("mccmnc.sqlite3", &database);
	if(retval){
		fprintf(stderr, "*database connection failed\n");
		exit(-1);
    } 
    else printf("Database connection successful (SQLite version: ");

    retval = sqlite3_prepare_v2(database, "SELECT SQLITE_VERSION()", -1, &result, 0);
    if(retval){
        fprintf(stderr, "*selecting data from database failed\n");
        exit(-1);
    }
	else if(sqlite3_step(result))
        printf("%s)\n", sqlite3_column_text(result, 0));

    sqlite3_finalize(result);

	/* Load file */
	printf("\nScraping capture file for packets.\n");

	if(verbosity > 0)
		printf("Opening capture file... ");

	FILE *file = NULL;
	if(*f == '-') {
		/* feed in from stdin */
		file = stdin;
	} else {
		/* feed in from file */
		file = fopen (f, "rb");
	}
	if(file != NULL)
	{
		bytes = fread(&buffer, 1, BUFFER_SIZE, file); /* load capture file into memory */
		if(verbosity > 0)
			printf("Bytes read: %d\n", bytes);
		fclose(file);

		if(verbosity > 1)
			hexdump(buffer, bytes);

		/* Scrape pcap header fields */
		memcpy(&pcapheader, buffer, 40);
		if(pcapheader[0] == 0xd4 && pcapheader[1] == 0xc3 && pcapheader[2] == 0xb2 && pcapheader[3] == 0xa1) //check valid
			printf("Valid pcap file type (ver. %d.%d)\n", pcapheader[4], pcapheader[6]);
		else {
			printf("Could not read pcap file type\n");
			exit(1);
		}
		
		/* Parse GSM packets */
		for(i=0; i < bytes; i++)
		{
			if(buffer[i] == GSMheader[0] && buffer[i+2] == GSMheader[2] && (buffer[i+12] == 0x01 || buffer[i+12] == 0x02)) //check header
			{
				if(buffer[i + GSMheader_size] != 0x01 && buffer[i + GSMheader_size + 1] != 0x2b) //filter CCCH packet content
				{
					memcpy(&array[j++], &buffer[i + GSMheader_size], GSMframe_size);
					if(verbosity > 1) {
						printf("\nGSM CCCH #%d: ", j);
						hexdump(array[j-1], GSMframe_size);
					}

					i += (GSMheader_size + GSMframe_size);

				} else {
					i += GSMheader_size;
				}
			}
		}

		/* Parse data from each GSM packet */
		i = 0;
		while(i++ < j){
			x = array[i][2];
			switch(x)
			{
				case 0x3f:
					if(verbosity > 0) {
						printf("\nType: IA\t");
						printf("Subchannel = 0x%02x ", (array[i][4] & 0x38) >> 3);
						printf("Timeslot = 0x%02x\n", array[i][4] & 0x7);
					}

					IA++;
					break;

				case 0x39:
					if(verbosity > 0)
						//printf("\nType: IAext\t\n");

					IAext++;
					break;

				case 0x21:
					if(verbosity > 0) {
						if((array[i][5] & 0x07) == 0x04){
							printf("\nType: PR1\tTMSI = 0x");
							for(n = 0; n < 4; n++)
								printf("%02x", array[i][6+n]);
							if((array[i][12] & 0x07) != 0x04)
								printf("\n");
						}
						else if((array[i][5] & 0x07) == 0x01){
							printf("Type: PR1\tIMSI = ");
							for(n = 0; n < 7; n++)
								printf("%02x", array[i][6+n]);
							if((array[i][12] & 0x07) != 0x04)
								printf("\n");
						}
						if((array[i][12] & 0x07) == 0x04){
							printf("\tTMSI 2 = ");
							for(n = 0; n < 4; n++)
								printf("%02x", array[i][13+n]);
							printf("\n");
						}
					}

					PR1++;
					break;

				case 0x22:
					if(verbosity > 0) {
						if((array[i][14] & 0x07) == 0x04){
							printf("\nType: PR2\t\tTMSI = 0x");
							for(n = 0; n < 4; n++)
								printf("%02x", array[i][4+n]);

							printf("\t\tTMSI 2 = ");
							for(n = 0; n < 4; n++)
								printf("%02x", array[i][8+n]);

							printf("\tTMSI 3 = ");
							for(n = 0; n < 4; n++)
								printf("%02x", array[i][15+n]);
						}
						else if((array[i][14] & 0x07) == 0x01){
							printf("Type: PR2\tTMSI = 0x");
							for(n = 0; n < 4; n++)
								printf("%02x", array[i][4+n]);

							printf("\t\tTMSI 2 = ");
							for(n = 0; n < 4; n++)
								printf("%02x", array[i][8+n]);

							printf("\tIMSI = ");
							for(n = 0; n < 7; n++)
								printf("%02x", array[i][15+n]);

						}
						printf("\n");
					}

					PR2++;
					break;

				case 0x19:
					c = 128; v = 0;
					cellBarred = array[i][19] & 0x2;
					if(verbosity > 0) {
						printf("\nType: SYS1\tCell barred: ");
						cellBarred == 0x1 ? printf("true\t") : printf("false\t");
					
						// print ARCFN binary table
					/*	printf("ARCFN binary table: ");
						for(n = 3; n < 16 + 3; n++){
							int2binary(binary, array[i][n]);
							for(m = 0; m < 8; m++) 
								printf("%d", binary[m]);
						} */
					}
					if(verbosity > 0) printf("List of ARFCNs: ");
					for(n = 3; n < 16 + 3; n++){
						int2binary(binary, array[i][n]);
						for(m = 0; m < 8; m++){
							if(c <= 124 && binary[m] & 0x1) {
								ARFCN[v++] = c;
								if(verbosity > 0) printf("%d ", c);
							}
							c--;
						}
					}	
					//printf("\n");

					SYS1++;
					break;

				case 0x1a:
					c = 128;
					if(verbosity > 0) {
						printf("\nType: SYS2\t");

						// print ARCFN binary table
					/*	printf("ARCFN binary table: ");
						for(n = 3; n < 16 + 3; n++){
							int2binary(binary, array[i][n]);
							for(m = 0; m < 8; m++) 
								printf("%d", binary[m]);
						} */
					
						printf("List of neighbour cell ARFCNs: ");
						for(n = 3; n < 16 + 3; n++){
							int2binary(binary, array[i][n]);
							for(m = 0; m < 8; m++){
								if(c <= 124 && binary[m] & 0x1)
									printf("%d ", c);
								c--;
							}
						}
					}	
					//printf("\n");

					SYS2++;
					break;

				case 0x03:
					if(verbosity > 0)
						//printf("Type: SYS2ter |\n");

					SYS2ter++;
					break;
			
				case 0x07:
					if(verbosity > 0)
						//printf("Type: SYS2quater |\n");

					SYS2quater++;
					break;

				case 0x1b:
					
					if(verbosity > 0) printf("\nType: SYS3\t");
					cellID = (array[i][3] << 8) | array[i][4];
					if(verbosity > 0) {
						long2binary(cid, cellID);
						printf("Cell ID: %lu (", cellID);
						for(m = 0; m < 16; m++)
							printf("%d", cid[m]);
						printf(")\tLAI: 0x");
						for(n = 0; n < 5; n++){
							LAI[n] = array[i][5 + n];
							printf("%02x", LAI[n]);
						}
					}

					MCC = LO_NIBBLE(array[i][5]) * 100 + HI_NIBBLE(array[i][5]) * 10 + LO_NIBBLE(array[i][6]); 
					MNC = LO_NIBBLE(array[i][7]) * 10 + HI_NIBBLE(array[i][7]);
					LAC = (array[i][8] << 8) | array[i][9];

					if(verbosity > 0) printf(" (%d/%d/%d)\n", MCC, MNC, LAC);
					
					SYS3++;
					break;

				case 0x1c:
					if(verbosity > 0){
						//printf("\nType: SYS4 |\n");

					}

					SYS4++;
					break;

				case 0x00:
					if(verbosity > 0) 
						printf("Type: SYS13 |\n");

					SYS13++;
					break;
					
			}
		}

	} else {
		perror("Error while opening the capture file"); /* why didn't the file open? */
	}

	char sql[100], mcc[3], mnc[3];

    sprintf(mcc, "%d", MCC);
    sprintf(mnc, "%d", MNC);

	printf("\nCapture Information\nCell ID: %lu (0x%04lx)\n", cellID, cellID);

    strcat(sql, "select country from mccmnc where mcc is ");
    strcat(sql, mcc);
    strcat(sql, " and mnc is ");
    strcat(sql, mnc);

	retval = sqlite3_prepare_v2(database, sql, -1, &result, 0);
    if(retval){
        fprintf(stderr, "*selecting data from database failed\n");
        exit(-1);
    }
	else if(sqlite3_step(result))
		printf("Mobile Country Code: %d (%s)\n", MCC, sqlite3_column_text(result, 0));
    
    sqlite3_finalize(result);

    memset(sql, 0, sizeof sql);
    strcat(sql, "select operator from mccmnc where mcc is ");
    strcat(sql, mcc);
    strcat(sql, " and mnc is ");
    strcat(sql, mnc);

	retval = sqlite3_prepare_v2(database, sql, -1, &result, 0);
    if(retval){
        fprintf(stderr, "*selecting data from database failed\n");
        exit(-1);
    }
	else if(sqlite3_step(result))
		printf("Mobile Network Code: %d (%s)\n", MNC, sqlite3_column_text(result, 0));
    
    sqlite3_finalize(result);
	
	printf("Location Area Code: %d (0x%04x)\n", LAC, LAC);
	printf("Cell barred: "); cellBarred & 0x1 ? printf("true\t") : printf("false\t");

/* Absolute Radio Frequency Channel Number
GSM Band	ARFCN(N)	Uplink Frequency equation(FUL)	Downlink Frequency equation
GSM 450		259-293		450.6 + 0.2*(N-259)				FUL(N) + 10
GSM 480		306-340		479+0.2*(N-306)					FUL(N) + 10
GSM 750		438-511		747.2 + 0.2*(N-438)				FUL(N) + 30
GSM 850		128-251		824.2+0.2*(N-128)				FUL(N) + 45
P-GSM		1-124		890+0.2*N						FUL(N) + 45
E-GSM		975-1023	890+0.2*(N-1024)				FUL(N) + 45
GSM-R		955-1023	890+0.2*(N-1024)				FUL(N) + 45
DCS 1800	512-885		1710.2+0.2*(N-512)				FUL(N) + 95
PCS 1900	512-810		1850.2 + 0.2*(N-512)			FUL(N) + 80
*/
	
	printf("\n\nTDMA frequencies");

	i = 0;
	if(strncmp(GSMband, "GSM-450", 6) == 0) {
		while(ARFCN[i] != 0) {
			printf("ARFCN: %d\t"
			"Downlink Frequency: %.1fMHz\t"
			"Uplink Frequency: %.1fMHz"
			, ARFCN[i], 450.6 + 0.2*(ARFCN[i]-259), (450.6 + 0.2*(ARFCN[i]-259)) + 10);
			i++;
		}
	}
	else if(strncmp(GSMband, "GSM-470", 6) == 0) {
		while(ARFCN[i] != 0) {
			printf("ARFCN: %d\t"
			"Downlink Frequency: %.1fMHz\t"
			"Uplink Frequency: %.1fMHz"
			, ARFCN[i], 479+0.2*(ARFCN[i]-306), (479+0.2*(ARFCN[i]-306)) + 10);
			i++;
		}
	}
	else if(strncmp(GSMband, "GSM-750", 6) == 0) {
		while(ARFCN[i] != 0) {
			printf("ARFCN: %d\t"
			"Downlink Frequency: %.1fMHz\t"
			"Uplink Frequency: %.1fMHz"
			, ARFCN[i], 747.2 + 0.2*(ARFCN[i]-438), (747.2 + 0.2*(ARFCN[i]-438)) + 30);
			i++;
		}
	}
	else if(strncmp(GSMband, "GSM-850", 6) == 0) {
		while(ARFCN[i] != 0) {
			printf("ARFCN: %d\t"
			"Downlink Frequency: %.1fMHz\t"
			"Uplink Frequency: %.1fMHz"
			, ARFCN[i], 824.2+0.2*(ARFCN[i]-128), (824.2+0.2*(ARFCN[i]-128)) + 45);
			i++;
		}
	}
	else if(strncmp(GSMband, "GSM-900", 6) == 0) {
		while(ARFCN[i] != 0) {
			printf("\nARFCN: %d\t"
			"Downlink Frequency: %.1fMHz\t"
			"Uplink Frequency: %.1fMHz"
			, ARFCN[i], 890+0.2*ARFCN[i], (890+0.2*ARFCN[i]) + 45);
			i++;
		}
	}
	else if(strncmp(GSMband, "GSM-1800", 6) == 0) {
		while(ARFCN[i] != 0) {
			printf("\nARFCN: %d\t"
			"Downlink Frequency: %.1fMHz\t"
			"Uplink Frequency: %.1fMHz"
			, ARFCN[i], 1710.2+0.2*(ARFCN[i]-512), (1710.2+0.2*(ARFCN[i]-512)) + 95);
			i++;
		}
	}
	else if(strncmp(GSMband, "GSM-1900", 6) == 0) {
		while(ARFCN[i] != 0) {
			printf("\nARFCN: %d\t"
			"Downlink Frequency: %.1fMHz\t"
			"Uplink Frequency: %.1fMHz"
			, ARFCN[i], 1850.2 + 0.2*(ARFCN[i]-512), (1850.2 + 0.2*(ARFCN[i]-512)) + 80);
			i++;
		}
	}
	else printf("Unrecognised GSMband.");

//**************************TEST AREA************************/

//	printf("\n\n******TESTING******\n");

/*	const unsigned char *bcd_to_ascii = "0123456789*#abc";
	const unsigned char ascii_to_bcd[] = {
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0,11, 0, 0, 0, 0, 0, 0,10, 0, 0, 0, 0, 0,
		0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0,12,13,14
	};

	int bcd[16];
	unsigned char ascii[] = {0x39, 0x01, 0x62, 0x20, 0x71, 0x44, 0x76, 0x21};
	for (i = 0; ascii[i]; i++)
    	bcd[i] = ascii_to_bcd[ascii[i]];

    hexdump((unsigned char *)bcd, 16);

    for(i=1;ascii[i];i++)
    	printf("%02x", hex2bcd(ascii[i]));
*/

 //	printf("\n******TESTING******\n\n");

//**************************************************************/

    printf("\n\n");
	if(verbosity > 0) {
		printf("%d bytes were processed in total."
		"\n%d GSM packets were found and extracted."
		"\n\t\t%d Immediate Request"
		"\n\t\t%d Immediate Request Extended"
		"\n\t\t%d Paging Request Type 1"
		"\n\t\t%d Paging Request Type 2"
		"\n\t\t%d System Information Type 1"
		"\n\t\t%d System Information Type 2"
		"\n\t\t%d System Information Type 2ter"
		"\n\t\t%d System Information Type 2quater"
		"\n\t\t%d System Information Type 3"
		"\n\t\t%d System Information Type 4"
		"\n\t\t%d System Information Type 13"
		"\n\n", bytes, j, IA, IAext, PR1, PR2, SYS1, SYS2, SYS2ter, SYS2quater, SYS3, SYS4, SYS13);
	}
	sqlite3_close(database);
}

// GSM packet types: IA,IAext,PR1,PR2,SYS1,SYS2,SYS2ter,SYS2quater,SYS3,SYS4,SYS13

/*
PCAP Header    |  MAC Header  Ethernet Type  Version  Packet Type  Packet Body Length  Packet Body  Frame Check Sequence
40 bytes       |  12 bytes    2 bytes        1 byte   1 byte       2 bytes             variable     4 bytes

Immdediate Assignment - Channel designation
Paging Request type 1 - Mobile Identity (TMSI/P-TMSI/IMSI)
System Information type 1 - Cell description - List of ARFCNs within cell and cell barred.
System Information type 2 - Neighbour cell description - List of ARFCNs for GSM band and cell barred.
System Information type 2ter - Neighbour cell description 2 - List of ARFCNs of other available GSM band.
System Information type 2quater - 3g information
System Information type 3 - Cell ID, LAI (MNC, MCC, LAC) and cell barred.
System Information type 4 - LAI (MNC, MCC, LAC) and cell barred.
System Information type 13 - RAC, GPRS information
*/