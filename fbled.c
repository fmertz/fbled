///           // fbled.c
//
// Copyright (C) 2011 - F Mertz
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; either version 2 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program. If not, see <http://www.gnu.org/licenses/>.

//  Wed March 16
//  Copyright  2011  F Mertz
//  <fireboxled@gmail.com>
//
// This project aims at providing a simple deamon to update the front LEDs on a Watchguard Firebox II/III. This code is
// logically separated into a Driver and a Client.
//
// The Driver is responsible for updating the LEDs based on input parameters, and deals with low-level I/O ports.
// This driver might be reimplemented as a real Linux driver/module at a later point.
//
// The Client is responsible for gathering the live values from the running system, parse them, normalize them, then pass them
// to the Driver.
//=============================================================================
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/io.h>
#include <sys/time.h>
#include <errno.h>
#include <time.h>
#include <signal.h>
#include <features.h>

//#define LED_DEBUG
#include "fbled.h"
#include "config.h"

//This array holds all LED worker functions
//	Base wait time is defined in WRK_WAIT
//	All workers are running once every uSkipCount times
//
static tExecTable tLEDProcTable[] = {
	{ .pfConstr=	NULL,	.pfCode=	DoLoad,	.pfDestr=	NULL,	.uSkipCount=	2,	.uRunningCount=	0},
	{						NULL,					DoTraffic,					NULL,							2,								1},
	{						NULL,					DoBlink,					NULL,							3,								0}
};

//This is used to control the main loop of workers
// The worker LED threads will read it, the signal handler can change it
// Turn-off any optimization by the compiler by declaring it volatile
//
static unsigned volatile uKeepGoing=1;

//This is used for stck style
static unsigned uStackStyle=STACK_BAR;

//DRIVER: Initialize function
//
static int DrvInit(unsigned char uMode)
{
	int 				iRetVal;
	unsigned	u;
	char			cEthNum;
	FILE				*tEthFile=NULL;
	char			acMACAddress[256];
	char			acFileName[256];

	//Try and find out if this code is running on a Firebox
	//Look at the MAC addresses of eth0-4 and see if at least 1 is part of the Watchguard range
	for (cEthNum='0';cEthNum!='5';cEthNum++)
	{
		snprintf(acFileName,sizeof(acFileName),"/sys/class/net/eth%c/address",cEthNum);
		if (NULL==(tEthFile=fopen(acFileName,"r")))
			continue;
		if (fgets(acMACAddress,sizeof(acMACAddress), tEthFile))
		{
			fclose(tEthFile);
			if (0 == memcmp(acMACAddress,WATCHGUARD_OUI,sizeof(WATCHGUARD_OUI)-1))
				//Found one, but no guarantee it is a Firebox II or III 
				break;
		}
	}
	//if ('5' == cEthNum)
		//Did not find a Watchguard OUI
		//return -1;
	//In order to make direct use of I/O ports from user space, access has to be requested
	// Tutorial: http://www.faqs.org/docs/Linux-mini/IO-Port-Programming.html
	// This needs "root" permission to succeed
	iRetVal = IOPERM(LED_BASEPORT, 3, 255);
	if (iRetVal) return iRetVal;

	//Reset all LEDs
	DrvSetLeds(0x0900);
	DrvSetLeds(0x0B00);
	DrvSetLeds(0x0300);
	DrvSetLeds(0x0700);
	DrvSetLeds(0x0F00);

	if (DRV_SLOW == uMode)
	{
		//Init time animation
		//One LED at a time for Status LEDs
		DrvSetLedsWait(LED_DISARMED,DRV_INIT_WAIT);
		DrvSetLedsWait(LED_ARMED,DRV_INIT_WAIT);
		DrvSetLedsWait(LED_SYS_A,DRV_INIT_WAIT);
		DrvSetLedsWait(LED_SYS_B,DRV_INIT_WAIT);
		DrvSetLeds(0x0900);
		//One LED at a time for Load LEDs
		for (u=1; u<256;u*=2)
			DrvSetLedsWait ((LED_LOAD_LO-1)|u,DRV_INIT_WAIT);
		DrvSetLeds(0x0B00);
		//One LED at a time for Traffic LEDs
		for (u=1; u<256;u*=2)
			DrvSetLedsWait ((LED_TRAFFIC_LO-1)|u,DRV_INIT_WAIT);
		DrvSetLeds(0x0300);
		//Triangle
		DrvSetLedsWait(LED_TRUST | LED_EXTRN | LED_OPTNL,DRV_INIT_WAIT);
		DrvSetLeds(LED_T2E_1 | LED_O2E_1);
		DrvSetLedsWait(LED_E2T_1 | LED_O2T_1| LED_T2O_1 | LED_E2O_1,DRV_INIT_WAIT);
		//Triangle
		DrvSetLeds(LED_T2E_2 | LED_O2E_2);
		DrvSetLedsWait(LED_E2T_2 | LED_O2T_2| LED_T2O_2 | LED_E2O_2,DRV_INIT_WAIT);
		DrvSetLeds(0x0700);
		DrvSetLeds(0x0F00);
	}
	return 0;
}

//DRIVER: Finalize function
//
static int DrvEnd(unsigned uCombo)
{
	//Reset all LEDs
	DrvSetLeds(0x0900);
	DrvSetLeds(0x0B00);
	DrvSetLeds(0x0300);
	DrvSetLeds(0x0700);
	DrvSetLeds(0x0F00);
	//Light left on, if needed
	if (uCombo)
		DrvSetLeds(uCombo);

	//This may need "root" access, and is done by Linux anyway on exit
	// may want to consider dropping this call if we change identity
	return IOPERM(LED_BASEPORT, 3, 0);
}

//DRIVER: Actually set the LEDs
//  No buffer, no validation
//
static inline void DrvSetLeds(unsigned uCombo)
{
	//uCombo is Group# and bits in 2 bytes
	OUTB((uCombo&0x00FF)^0xFF, LED_DATA);	//Put data for the LEDs, after inversion (bit at 1 means LED is "off")
	OUTB((uCombo>>8)|0x01, LED_CONTROL);	//Put Group # in control, Strobe bit to 1
	OUTB((uCombo>>8)&0xFE, LED_CONTROL);	//Flip Strobe bit to 0, causes Firebox II to output LED_DATA to LEDs
	OUTB((uCombo>>8)|0x01, LED_CONTROL);	//Flip Strobe bit to 1, causes Firebox III to output LED_DATA to LEDs
}

//DRIVER: Set LEDs and wait for a while
//
static void DrvSetLedsWait(unsigned uCombo, unsigned long ulInterval)
{
	const struct timespec tReq = { .tv_sec=0, .tv_nsec=ulInterval};
	struct timespec tRem = {.tv_sec=0, .tv_nsec=0};
	
	DrvSetLeds(uCombo);
	//Now wait for a while
	nanosleep(&tReq,&tRem);
	//Technically, can have time remaining in tRem
}

//CLIENT: This worker LED function updates the load LEDs based on system load average
//
static void DoLoad(void)
{
	static unsigned uLedBitsOld=0;
	char					acLoadAvg[256];
	unsigned			uLoadLastMinInt;
	unsigned			uLoadLastMinDec;
	unsigned 			uLoad;
	unsigned 			uLedBits;
	
	//Only get 1st number, load avg in last min
	//getloadavg(&dLoadLastMin, 1); //uClibc does not have this
	if (0 == GetInFile ("/proc/loadavg",acLoadAvg,sizeof(acLoadAvg)))
		return;
	//Try and avoid the use of floating point
	if (2 != sscanf(acLoadAvg,"%u.%u ",&uLoadLastMinInt, &uLoadLastMinDec))
		return;
	//Normalize, mapping load to number of LEDs
	uLoad=(unsigned)((uLoadLastMinInt*100+uLoadLastMinDec)/15);

	uLoad=(uLoad >= 128) ? 256 : uLoad<<1; //Anything too high will light all LEDs

	for (uLedBits=1;uLoad>1;uLedBits=uLedBits<<1) //Cheap log function
		uLoad=uLoad>>1;

	//Apply the style modifyer
	if (uStackStyle & STACK_LINE)
		uLedBits>>=1;
	if (uStackStyle & STACK_BAR || uStackStyle & STACK_RAW)
		uLedBits--;
	if (uStackStyle & STACK_REVERSE)
		uLedBits^=0xFF;
	
	//Only update LEDs if necessary
	if (uLedBits != uLedBitsOld)
	{
		uLedBitsOld=uLedBits;
		DrvSetLeds(LED_LOAD_LO-1+uLedBits);
	}
}

//CLIENT: This worker LED function updates the Traffic LEDs based on /proc/net/dev
//
static void DoTraffic(void)
{
	static unsigned 		uLedBitsOld=0;
	static long long		lAllPacketsPrior=0;
	static struct timeval	tWhenPrior = { .tv_sec=0, .tv_usec=0};
	
	FILE 								*tProcFile=NULL;
	char							acLineBuffer[2048]="";

	long long 					lRxPackets;
	long long 					lTxPackets;
	long long					lAllPackets;
	long							lRate;

	struct timeval				tWhenNow;

	unsigned 					uLedBits;

	if((tProcFile=fopen( "/proc/net/dev", "r" )) == NULL)
		return;
	//Read clock, no timezone
	if (gettimeofday(&tWhenNow,NULL))
	{
		fclose(tProcFile);
		return;
	}
	fgets(acLineBuffer, sizeof(acLineBuffer), tProcFile); //Throw away line 1
	fgets(acLineBuffer, sizeof(acLineBuffer), tProcFile); //Throw away line 2
	//Read all lines, 1 by 1
	for (lAllPackets=0;fgets(acLineBuffer, sizeof(acLineBuffer), tProcFile);)
         if(    strstr(acLineBuffer, "eth0:") != NULL
			|| strstr(acLineBuffer, "eth1:") != NULL
			|| strstr(acLineBuffer, "eth2:") != NULL
			|| strstr(acLineBuffer, "eth3:") != NULL
			|| strstr(acLineBuffer, "eth4:") != NULL)
	    {
			//Only parse lines for base hardware interfaces, ignore others like lo, bond, tun, VLAN ethx., pppoe
			//This is done so we avoid counting same packet multiple times
			//Could be boot time rename of interface eth0-> eth1, could be PCI card with eth4
            //Spacing is dynamic, sometimes interface name plus ":" is followed by a space, sometimes not
            if(*( strchr(acLineBuffer,':')+1) == ' ' )
                sscanf(acLineBuffer, "%*s %*u %Lu %*u %*u %*u %*u %*u %*u %*u %Lu %*u %*u %*u %*u %*u %*u",
                                  &lRxPackets, &lTxPackets ); //This is for lines like eth1:<space>123
            else
                sscanf(acLineBuffer, "%*s %Lu %*u %*u %*u %*u %*u %*u %*u %Lu %*u %*u %*u %*u %*u %*u",
                                  &lRxPackets, &lTxPackets ); //This is for lines like eth1:123
			lAllPackets+=lRxPackets+lTxPackets;
		}
	fclose(tProcFile);
	//If first time in, we have neither the old time stamp nor the old packet count
	if (0L != lAllPacketsPrior)
	{
		//Rate is number of packets since last time divided by time diff since last time
		//Normalize rate by dividing by 64
		// 64     packets per second is 1 LED
		lRate=(lAllPackets-lAllPacketsPrior)*1000000/64/((tWhenNow.tv_sec-tWhenPrior.tv_sec)*1000000+tWhenNow.tv_usec-tWhenPrior.tv_usec);
		// 8192 packets per second and above is 8 LEDs
		if (lRate > 8192/64)
			lRate=8192/64;  //Anything higher than 8192 packets/second is all LEDs
		//compute the logarithm of the rate the cheap way
		//basically, find the highest bit set to 1
		for (uLedBits=1;lRate>0;uLedBits=uLedBits<<1)
			lRate=lRate>>1;
		//Apply the style modifyer
		if (uStackStyle & STACK_LINE)
			uLedBits>>=1;
		if (uStackStyle & STACK_BAR)
			uLedBits--;
		if (uStackStyle & STACK_RAW)
			uLedBits=(lAllPackets/64)&0xFF; //This displays the low byte of 64 packet _count_ (not _rate_) in binary
		if (uStackStyle & STACK_REVERSE)
			uLedBits^=0xFF;
		//Only update LEDs if necessary
		if (uLedBits != uLedBitsOld)
		{
			uLedBitsOld=uLedBits;
			//Use thread-safe LED update
			DrvSetLeds(LED_TRAFFIC_LO-1+uLedBits);
		}
	}
	//Set time and count baseline for next run
	lAllPacketsPrior=lAllPackets;
	tWhenPrior=tWhenNow;
}

//CLIENT: This worker LED function blinks a LED, heartbeat sort of thing
//
static void DoBlink(void)
{
	static unsigned uStatusLEDs=LED_ARMED | LED_SYS_A;

	//Flip LED_ARMED
	uStatusLEDs^=LED_ARMED&0x00FF;
	DrvSetLeds(uStatusLEDs);
}
//CLIENT: Helper function to get stuff in text files
//
static int GetInFile(const char *acFileName, char *acDest, const unsigned uSize)
{
	FILE		*tFile=NULL;
	int		iReturnVal=-1;

	if (NULL==(tFile=fopen(acFileName,"r")))
		return 0;
	if (NULL == fgets(acDest, uSize, tFile))
		iReturnVal=0;
	fclose(tFile);
	return iReturnVal;
}

//CLIENT: scheduler
// This function does the infinite loop of wait-run-wait for all workers
//
void Scheduler(tExecTable ptWorkTable[], unsigned uCount)
{
	struct timespec tReq = { .tv_sec=0, .tv_nsec=WRK_WAIT};
	struct timespec tRem = {.tv_sec=0, .tv_nsec=0};
	unsigned	u;

	//Run init code, if present
	for (u=0;u<uCount;u++)
		 if (ptWorkTable[u].pfConstr)
			 (ptWorkTable[u].pfConstr)();

	//loop until global variable changes to 0
	for (;uKeepGoing;)
	{
		//Workers
		for (u=0;u<uCount;u++)
			if (0 == ptWorkTable[u].uRunningCount)
			{
				ptWorkTable[u].uRunningCount=ptWorkTable[u].uSkipCount;
				(*ptWorkTable[u].pfCode)();
			}
			else
				ptWorkTable[u].uRunningCount--;
		//Wait a while
		nanosleep(&tReq,&tRem);
	}

	//Cleanup code, if present
	for (u=0;u<uCount;u++)
		 if (ptWorkTable[u].pfDestr)
			 (*ptWorkTable[u].pfDestr)();
}

//CLIENT: This is the handler for all termination signals.
// Not much can be done here, so just flip a global variable
// to signal worker threads to stop
//
void ExitHandler(int iSigNum)
{
	//Just change flag for any termination signal
	uKeepGoing=0;
}

//CLIENT: This is the handler for the USR signals
// A good place to handle alternative styles
//
void UserHandler(int iSigNum)
{
	//For USR1 and USR2, flip styles
	switch (iSigNum)
	{
		case SIGUSR1:
			if (uStackStyle & STACK_BAR)
			{
				uStackStyle^=STACK_BAR;
				uStackStyle|=STACK_LINE;
				return;
			}
			if (uStackStyle & STACK_LINE)
			{
				uStackStyle^=STACK_LINE;
				uStackStyle|=STACK_RAW;
				return;
			}
			if (uStackStyle & STACK_RAW)
			{
				uStackStyle^=STACK_RAW;
				uStackStyle|=STACK_BAR;
				return;
			}
			//break;
			
		case SIGUSR2:
			uStackStyle^=STACK_REVERSE;
	}
}

//CLIENT: Entry point upon execution
//
int main(int nArgc, char **asArgv)
{
	puts(PACKAGE_STRING);

	//Initialize Driver, requires "root"
	if (DrvInit(DRV_SLOW))
	{
		puts("Cannot Initialize Driver...");
		return errno;
	}
	//Setup handler for all termination signals (Control-c, Control-Backslash, or kill)
	signal(SIGINT, ExitHandler);
	signal(SIGTERM, ExitHandler);
	signal(SIGQUIT, ExitHandler);
	//Setup handler for USR1, USR2 "kill -USR1 <pid>, kill -USR2 <pid>"
	signal(SIGUSR1, UserHandler);
	signal(SIGUSR2, UserHandler);
	//Run the worker scheduler
	Scheduler(tLEDProcTable,SIZE(tLEDProcTable));

	//Finalize, and turn the DISARMED light on
	if (DrvEnd(LED_DISARMED))
	{
		puts("Cannot Finalize Driver...");
		return errno;
	}
	return 0;
}
