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
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/io.h>
#include <sys/time.h>
#include <errno.h>
#include <time.h>
#include <signal.h>
#include <features.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <sys/times.h>
#include <asm/types.h>
#include <linux/netlink.h>
#include <net/if.h>
#include <linux/netfilter_ipv4/ipt_ULOG.h>
//#define LED_DEBUG
#include "fbled.h"
#include "config.h"

//Place to put variables to be shared between the ULOG workers
static tUlogPriv			tUlogPrivData =
{	.iUlogSocket = -1,
 	.pUlogDatagram = NULL
};

//This array holds all LED worker functions
//	Base wait time is defined in WRK_WAIT
//	All workers are running once every uSkipCount times
//
static tExecTable tLEDProcTable[] = {
	{ .pfConstr=	NULL,	.pfCode=	DoLoad,	.pfDestr=	NULL,	.uSkipCount=	2,	.uRunningCount=	0, .pExecData = 	NULL},
	{						NULL,					DoTraffic,					NULL,							1,								1,							NULL},
	{						NULL,					DoBlink,					NULL,							2,								0,							NULL},
	{						SetupULog,			DoUlog,					CloseUlog,					2,								0,							(void *)&tUlogPrivData},
	{						NULL,					DoTips,					NULL,							1,								0,							(void *)&tUlogPrivData}
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
	DrvSetLeds(LED_NO_STATUS);
	DrvSetLeds(LED_NO_LOAD);
	DrvSetLeds(LED_NO_TRAFFIC);
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
		DrvSetLeds(LED_NO_STATUS);
		//One LED at a time for Load LEDs
		for (u=1; u<256;u*=2)
			DrvSetLedsWait ((LED_LOAD_LO-1)|u,DRV_INIT_WAIT);
		DrvSetLeds(LED_NO_LOAD);
		//One LED at a time for Traffic LEDs
		for (u=1; u<256;u*=2)
			DrvSetLedsWait ((LED_TRAFFIC_LO-1)|u,DRV_INIT_WAIT);
		DrvSetLeds(LED_NO_TRAFFIC);
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
	DrvSetLeds(LED_NO_STATUS);
	DrvSetLeds(LED_NO_LOAD);
	DrvSetLeds(LED_NO_TRAFFIC);
	DrvSetLeds(0x0700);
	DrvSetLeds(0x0F00);
	//Light left on, if needed
	if (uCombo)
		DrvSetLeds(uCombo);

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
	//Technically, can have time remaining in tRem if signal received. Ignoring it...
}

//CLIENT: This worker LED function updates the load LEDs based on system load average
//
static void DoLoad(void * p)
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

//CLIENT: This worker LED function updates the Traffic LEDs
//
static void DoTraffic(void *p)
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
	struct timeval				tWhenDiff;

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
		GetTimeDiff (&tWhenPrior, &tWhenNow, &tWhenDiff);
		lRate=(lAllPackets-lAllPacketsPrior)*1000000/64/(tWhenDiff.tv_sec*1000000+tWhenDiff.tv_usec);
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
static void DoBlink(void *p)
{
	static unsigned uStatusLEDs=LED_ARMED | LED_SYS_A;

	//Flip LED_ARMED
	uStatusLEDs^=LED_ARMED&0x00FF;
	DrvSetLeds(uStatusLEDs);
}

//CLIENT: This is the contructor for the triangle tips LEDs
//  It sets up the ULOG socket
void SetupULog(void *p)
{
	//  As part of the Linux kernel, the netfilter architecture includes
	//  the ULOG target. This means that when packets are processed by the
	//  firewall and are sent down a list of rules in search of a match, there
	//  can be a target named ULOG. The ULOG target then gets the packet,
	//  does what it is instructed to do, and then returns the packet to the 
	//  next rule in the original chain. This is done with iptables, e.g.
	//
	//                "iptables -A FORWARD -j ULOG --ulog-nlgroup 32"
	//
	//  This rule appends a rule to the FORWARD chain, and the rule simply
	//  jumps to the ULOG target, with no restriction on the packet (it always
	//  matches).
	//  From a design perspective, the kernel modules implement features, and
	//  it is up the system admin to configure policies. This is done from user-
	//  space. Therefore, the user-space commands need to communicate the 
	//  policies to the kernel. For netfilter, this communication is standardized
	//  in RFC 3549, the netlink protocol.
	//  When ULOG receives a packet, it then turns around and multicasts this
	//  packet inside a netlink wrapper, to all user-space clients that have 
	//  registered to be notified. This multicasting is to be considered as a
	//  datagram. User-space programs register interest with a group mask.
	//  Each netfilter rule for ULOG uses a group number as well. As long as 
	//  a user-space program has a group mask with a bit for the rule group
	//  number, the program gets notified for all packets caught by the rule.
	//
	//  The idea here is to place rules with ULOG targets at whatever place in
	//  the firewall with iptables. Then, have fbled blip the tips of the triangle
	//  when a ULOG notification is received over netlink.
	//
	//NOTE: This code uses the older ULOG target, and is only available in ipv4.
	//           A better way would be to use the newer NFLOG target, available
	//           for both ipv4 and ipv6.
	//
	struct sockaddr_nl	tLocalAddress;
	unsigned				uSize = ULOG_RCVBUF;
	int							iFlags;
	tUlogPriv				*ptUlogPrivData;

	ptUlogPrivData = (tUlogPriv *)p;
	//netlink socket, of the raw sort, with ULOG protocol
	if (-1 == (ptUlogPrivData->iUlogSocket = socket(PF_NETLINK, SOCK_RAW, NETLINK_NFLOG)))
		return;
	//setup the local address
	tLocalAddress.nl_family = AF_NETLINK;
	tLocalAddress.nl_pid = getpid();				//No threads, so the main process id is enough
	tLocalAddress.nl_groups = FBLED_ULOG_GROUP_MASK;	//The group mask
	tLocalAddress.nl_pad = 0;
	//Bind the socket to the local address
	if (-1 == bind(ptUlogPrivData->iUlogSocket,(const struct sockaddr *)&tLocalAddress, sizeof(tLocalAddress)))
		goto SetupULogErr;
	//Set receive buffer size
	if (-1 == setsockopt(ptUlogPrivData->iUlogSocket, SOL_SOCKET, SO_RCVBUF, &uSize, sizeof(uSize)))
		goto SetupULogErr;
	//Set the socket as non-blocking. We want to keep fbled single treaded, so we don't want to wait
	// for packets everytime we read the socket.
	if (-1 == (iFlags = fcntl(ptUlogPrivData->iUlogSocket, F_GETFL, 0)))
		goto SetupULogErr;
	if (-1 == fcntl(ptUlogPrivData->iUlogSocket, F_SETFL, iFlags | O_NONBLOCK))
		goto SetupULogErr;
	//Allocate some memory as a receive buffer for datagrams coming through the socket
	if (NULL == (ptUlogPrivData->pUlogDatagram = (unsigned char *)malloc(ULOG_RCVBUF)))
		goto SetupULogErr;
	return;
	
SetupULogErr:
	close(ptUlogPrivData->iUlogSocket);
	ptUlogPrivData->iUlogSocket = -1;
}

//CLIENT: This is the worker for the triangle tips LEDs
//
void DoUlog(void *p)
{
	// This function is responsible for polling the netlink socket for datagrams.
	// These datagrams are following the general ideas of the network stack,
	// i.e. each layer keeps adding a header around the higher layer's data,
	// considered as the payload. Here, when the ULOG target of netfilter is
	// hit with a packet (because a rule in a chain matched that packet and
	// jumped to ULOG), ULOG looks at its configuration, and packages only N
	// bytes of that packet, with N being the --ulog-cprange parameter. Now,
	// in order to avoid a kernel/user-space switch for every hit, ULOG gathers
	// P packets, with P being the --ulog-qthreshold parameter. In this
	// arrangement, ULOG is considered a protocol (like UDP), while netlink
	// is a protocol family (like IP). So, each N bytes of each packet are the
	// payload, and this payload is preceded by the ULOG header. Then, each
	// one of these ULOG packets becomes the payload for netlink, and then
	// the netlink header is added. This is repeated P times.
	// The next step is to multicast this group of packets over netlink. This is
	// a setup where each netfilter rule hit can be told of a group (the --ulog-nlgroup
	// parameter). That group is made a part of the netlink socket. A ULOG
	// client like this one can listen to any of these groups.
	//
	// The general principle of communication applies: assume nothing about
	// the compliance of what is received, and be as compliant as possible
	// for what is sent.
	//
	static struct sockaddr_nl	tSenderAddress = {.nl_family = AF_NETLINK,
																				.nl_pid = 0,
																				.nl_groups = FBLED_ULOG_GROUP_MASK,
																				.nl_pad = 0};
	ssize_t									tSizeRead;
	socklen_t								tSenderAddressLength = sizeof(tSenderAddress);
	struct nlmsghdr 					*ptNetlinkHeader;
	ulog_packet_msg_t				*ptUlogHeader;
	tUlogPriv							*ptUlogPrivData;

	ptUlogPrivData = (tUlogPriv *)p;
	//Check the socket handle
	if (-1 == ptUlogPrivData->iUlogSocket)
		return;
	//Check that memory was allocated for the receive buffer
	//if (NULL == ptUlogPrivData->pUlogDatagram)
	//	return;
	//Check the socket is non blocking
	//if (0 == (O_NONBLOCK & fcntl(ptUlogPrivData->iUlogSocket, F_GETFL, 0)))
	//	return;	
	//Check for a netlink datagram
	if (-1 == (tSizeRead = recvfrom(ptUlogPrivData->iUlogSocket, ptUlogPrivData->pUlogDatagram, ULOG_RCVBUF,
	                                  0, (struct sockaddr *)&tSenderAddress,  &tSenderAddressLength)))
		return;	//Some error, including non-blocking (errno == EAGAIN) read
	//Check datagram
	if (sizeof(tSenderAddress) != tSenderAddressLength)
		return;
	if (   tSenderAddress.nl_pid != 0										//Packet not from the kernel
		|| tSenderAddress.nl_family != AF_NETLINK 					//Not a netlink packet
		|| 0 == ((1 << (tSenderAddress.nl_groups-1)) & FBLED_ULOG_GROUP_MASK))	//Not from a group we subscribed to
		return;	//Not what we expected
	//Now, look at content of netlink datagram, have to pay attention to alignment, so we use macros
	for ( ptNetlinkHeader = (struct nlmsghdr *)ptUlogPrivData->pUlogDatagram;
	     	//Make sure the netlink packet passes sanity check
	     	NLMSG_OK(ptNetlinkHeader,tSizeRead) &&
	  		//In case multiple netlink packets are sent, the last one is DONE
	     	//NLMSG_DONE != ptNetlinkHeader->nlmsg_type;
	     	//Check that the type indicates the payload is from ULOG
	     	ULOG_TYPE == ptNetlinkHeader->nlmsg_type;
	     	//Update the netlink header pointer to the next one
	     	ptNetlinkHeader = NLMSG_NEXT(ptNetlinkHeader,tSizeRead))
		{
			//At this point, we have isolated a proper netlink packet, maybe one of several,
			// and the data part of the netlink packet is a ULOG packet
			ptUlogHeader = (ulog_packet_msg_t *)NLMSG_DATA(ptNetlinkHeader);
			//Make sure the ULOG packet passes sanity check
			if (ULMSG_OK(ptUlogHeader,ptNetlinkHeader->nlmsg_len - NLMSG_HDRLEN))
			{
				if (0 == memcmp(ptUlogHeader->indev_name,"eth0",4) || 0 == memcmp(ptUlogHeader->outdev_name,"eth0",4))
					ptUlogPrivData->auDevBlipCount[0] = ULOG_BLIPS;
				if (0 == memcmp(ptUlogHeader->indev_name,"eth1",4) || 0 == memcmp(ptUlogHeader->outdev_name,"eth1",4))
					ptUlogPrivData->auDevBlipCount[1] = ULOG_BLIPS;
				if (0 == memcmp(ptUlogHeader->indev_name,"eth2",4) || 0 == memcmp(ptUlogHeader->outdev_name,"eth2",4))
					ptUlogPrivData->auDevBlipCount[2] = ULOG_BLIPS;
			}
		}
}

//CLIENT: This is the destructor for the triangle tips LEDs
//
void CloseUlog(void *p)
{
	tUlogPriv		*ptUlogPrivData;

	ptUlogPrivData = (tUlogPriv *)p;
	if (-1 == ptUlogPrivData->iUlogSocket)
		return;
	free(ptUlogPrivData->pUlogDatagram);
	close(ptUlogPrivData->iUlogSocket);
}

//CLIENT: This worker LED blips the triangle tips
//
void DoTips(void *p)
{
	static unsigned 	uTipLEDs = 0;
	tUlogPriv				*ptUlogPrivData;

	ptUlogPrivData = (tUlogPriv *)p;
	if (uTipLEDs)
	{
		//Transition LEDs from on to off
		uTipLEDs = 0;
		DrvSetLeds(0x0700);
	}
	else
	{
		//Transition from off to on?
		if (ptUlogPrivData->auDevBlipCount[0])
		{
			ptUlogPrivData->auDevBlipCount[0]--;
			uTipLEDs |=  LED_EXTRN;
		}
		if (ptUlogPrivData->auDevBlipCount[1])
		{
			ptUlogPrivData->auDevBlipCount[1]--;
			uTipLEDs |=  LED_TRUST;
		}
		if (ptUlogPrivData->auDevBlipCount[2])
		{
			ptUlogPrivData->auDevBlipCount[2]--;
			uTipLEDs |=  LED_OPTNL;
		}
		if (uTipLEDs)
			DrvSetLeds(uTipLEDs);
	}
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

//UTIL: time difference
//
void GetTimeDiff(
	struct timeval 	*ptFro,
    struct timeval 	*ptTo,
    struct timeval		*ptWait)
{
	int	iSec;
	
	if (ptTo->tv_usec < ptFro->tv_usec)
	{
	 	iSec = (ptFro->tv_usec - ptTo->tv_usec) / 1000000 + 1;
	 	ptFro->tv_usec -= 1000000 * iSec;
	 	ptFro->tv_sec += iSec;
	}
	if (ptTo->tv_usec - ptFro->tv_usec > 1000000)
	{
	 	iSec = (ptTo->tv_usec - ptFro->tv_usec) / 1000000;
	 	ptFro->tv_usec += 1000000 * iSec;
	 	ptFro->tv_sec -= iSec;
	}
	ptWait->tv_sec = ptTo->tv_sec - ptFro->tv_sec;
	ptWait->tv_usec = ptTo->tv_usec - ptFro->tv_usec;
}

//CLIENT: scheduler
// This function does the infinite loop of wait-run-wait for all workers
//
void Scheduler(tExecTable ptWorkTable[], unsigned uCount)
{
	struct timespec	tReq;
	struct timespec	tRem = {.tv_sec=0, .tv_nsec=0};
	struct timeval		tBeginWorkers;
	struct timeval		tEndWorkers;
	struct timeval		tDiff;
	unsigned			u;

	//Run init code, if present
	for (u=0;u<uCount;u++)
		 if (ptWorkTable[u].pfConstr)
			 (ptWorkTable[u].pfConstr)(ptWorkTable[u].pExecData);

	//loop until global variable changes to 0
	for (;uKeepGoing;)
	{
		//Get a time stamp, in calendar time
		gettimeofday(&tBeginWorkers, NULL);
		//Workers
		for (u=0;u<uCount;u++)
			if (0 == ptWorkTable[u].uRunningCount)
			{
				ptWorkTable[u].uRunningCount=ptWorkTable[u].uSkipCount;
				(*ptWorkTable[u].pfCode)(ptWorkTable[u].pExecData);
			}
			else
				ptWorkTable[u].uRunningCount--;
		//Get another time stamp, in calendar time
		gettimeofday(&tEndWorkers, NULL);
		//Wait a while, for the difference between base tick time and actual elapsed time
		GetTimeDiff(&tBeginWorkers, &tEndWorkers, &tDiff);
		if (0 == tDiff.tv_sec && tDiff.tv_usec < WRK_WAIT)
		{
			tReq.tv_sec = tDiff.tv_sec;
			tReq.tv_nsec = (WRK_WAIT - tDiff.tv_usec)*1000; //Correct for micro seconds to nano seconds
			nanosleep(&tReq,&tRem);
		}
	}
	//Cleanup code, if present
	for (u=0;u<uCount;u++)
		 if (ptWorkTable[u].pfDestr)
			 (*ptWorkTable[u].pfDestr)(ptWorkTable[u].pExecData);
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
	struct tms tCPUTicks;

	//For USR1 and USR2
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
			//uStackStyle^=STACK_REVERSE;
			times(&tCPUTicks);
			printf("CPU Utilization: user = %lu sys = %lu\n", tCPUTicks.tms_utime, tCPUTicks.tms_stime);
	}
}

//CLIENT: Entry point upon execution
//
int main(int nArgc, char **asArgv)
{
	struct tms tCPUStats;
	
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
	//Print out some CPU usage
	times(&tCPUStats);
	printf("CPU Utilization: user = %lu, sys = %lu\n",tCPUStats.tms_utime, tCPUStats.tms_stime);
	
	return 0;
}
