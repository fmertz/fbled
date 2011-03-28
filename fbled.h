//           // fbled.h
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
//
// Driver Logic:
//  The LEDs are controlled similarly to controlling a printer on the good old PC parallel port.
//  The general idea is that there are a number of on/off lights that need to be controlled individually. This is done by sending
//  data to specific "ports", 8-bit at a time. As we have more than 8 LEDs, there is the issue of addressing the LEDs and the
//  issue of controlling them. This mapping has been reverse-engineered by Jani Laaksonen.
//  The short version is that the data port, BASEPORT+0, controls a group of up to 8 LEDs, one LED for each bit.
//  What group of 8 LEDs the data is for is controlled by the control port, BASEPORT+2. The actual updating of the LEDs is
//  a 3 steps process:
//  1.The control port is updated with the LED Group Number
//  2.The LED data is placed in the data port, 1 bit for each LED
//  3.Control bit-0 of the control port is then flipped to actually change the LED
//
//  The mapping of LED Group to Control bits is:
//		Group 0, 0x02->0x03, This is for the 4 Status LEDs
//		Group 1, 0x00->0x01, This is for 8 Load LEDs
//		Group 2, 0x08->0x09, This is for 8 Traffic LEDs
//		Group 3, 0x0c->0x0d, This is for part of the triangle (7 LEDs)
//		Group 4, 0x04->0x05, This is for the rest of the triangle (8 LEDs)
//
//  Last, there is hardware inversion for bits 1011, so these bits need to be flipped.
//                      See http://en.wikipedia.org/wiki/Parallel_port
//
//  Note: LEDs are controlled individually, there is no grouping of any kind, i.e. the 8 LEDs for Traffic or Load can
//            be lit up individually, there is no "stack" concept in hardware. It all need to be built in the code.
//  Note: As is tradition, the Driver is just responsible for offering the means to control the LEDs. It is not responsible for
//            policy, i.e. what information in what form goes to what LED.
//  Note: This is a Linux implementation.
//=============================================================================
//
// Client Logic:
//  The LEDs are labelled in a pretty generic way, and can be used to convey a number of statuses. This Client imlements
//  the policies described below. The original policies from the manufacturer are quoted.

//  Disarm: "Red light indicates the Firebox detected an error, shut down its interfaces, and will not forward any packets. Reboot the Firebox."
//               Idea: ready to poweroff, root file system unmounted
//  Armed: "Green light indicates the Firebox has been booted and is running."
//               Idea: WAN has IP address.
//               Idea: Firewall has at least 1 entry
//               Idea: the boot process has completed
//               Idea: flashes to indictate this code is running
//    Sys A: "Indicates that the Firebox is running from its primary user-defined configuration."
//               Idea: os running off of ramdrive, early boot
//    Sys B: "Indicates that the Firebox is running from the readonly factory default system area."
//               Idea: os running off of storage device, root file system mounted, normal operation
//   Power: "Indicates that the Firebox is currently powered up."
//               Direct harware wiring, no software control
// Triangle: "Indicates traffic between Firebox interfaces. Green arrows briefly light to indicate allowed traffic
//                between two interfaces in the direction of the arrows. A red light at a triangle corner indicates 
//                that the Firebox is denying packets at that interface."
//                For External, Trusted and Other, off if no link, on if link AND IP address, blink if link, no IP
//    Traffic: "A stack of lights that functions as a meter to indicate levels of traffic volume through the 
//                Firebox. Low volume indicators are green, while high volume indicators are yellow. The display 
//                updates three times per second. The scale is exponential: the first light represents 64 packets/ 
//                second, the second light represents 128 packets/second, increasing to the eighth light which 
//                represents 8,192 packets/second. "
//                This stack is controlled by /proc/net/dev, with a logarithmic scale.
//     Load: "A stack of lights that functions as a meter to indicate the system load average. The system load 
//               average is the average number of processes running (not including those in wait states) during 
//               the last minute. Low average indicators are green, while high average indicators are yellow. The 
//               display updates three times per second. The scale is exponential with each successive light representing 
//               a doubling of the load average. The first light represents a load average of 0.15. The most 
//               significant load factor on a Firebox is the number of proxies running."
//               This stack is controlled by /proc/loadavg, with a logarithmic scale. The first number is the number of processes
//               actually using CPU cycles to run during the last minute.
//
// Client Architecture
//               Overall, the client is basically an infinite loop of execution threads with a configurable wait time. The
//               implementation is based on multi-threading a number of functions (the Do... functions), one per group
//               of LEDs. The exit condition is the receipt of one of the usual termination signals.
//=============================================================================

//Driver Constants
#define LED_BASEPORT	0x378
#define LED_DATA			(LED_BASEPORT+0)
#define LED_CONTROL		(LED_BASEPORT+2)

//LED Coding; Control bits in 1 byte followed by Data bits for each LED
//LED Group 0: Status LEDs, Control Code 2, 0010 xor'ed with 1011 is 1001, 0x09
#define LED_DISARMED	0x0901
#define LED_ARMED			0x0902
#define LED_SYS_A 			0x0904
#define LED_SYS_B			0x0908
#define LED_ENABLE		0x0940

//LED Group 1: Load, Control Code 0, 0000 xor'ed with 1011 is 1011, 0x0B
#define LED_LOAD_LO		0x0B01
#define LED_LOAD_HI		0x0BFF

//LED Group 2: Traffic, Control Code 8, 1000 xor'ed with 1011 is 0011, 0x03
#define LED_TRAFFIC_LO	0x0301
#define LED_TRAFFIC_HI	0x03FF
     
//LED Group 3: Triangle, Control Code C, 1100 xor'ed with 1011 is 0111, 0x07
#define LED_T2E_1			0x0701
#define LED_T2E_2			0x0702
#define LED_O2E_1			0x0704
#define LED_O2E_2			0x0708
#define LED_EXTRN			0x0710
#define LED_TRUST			0x0720
#define LED_OPTNL			0x0740

//LED Group 4: Triangle, Control Code 4, 0100 xor'ed with 1011 is 1111, 0x0F
#define LED_E2T_1			0x0F01
#define LED_E2T_2			0x0F02
#define LED_O2T_1			0x0F04
#define LED_O2T_2			0x0F08
#define LED_T2O_1			0x0F10
#define LED_T2O_2			0x0F20
#define LED_E2O_1			0x0F40
#define LED_E2O_2			0x0F80

//Driver constants
#define DRV_FAST			0
#define DRV_SLOW			1
#define DRV_INIT_WAIT		200000000 //.2 sec
#define WATCHGUARD_OUI "00:90:7f"

//Driver prototypes
static int DrvInit(unsigned char);
static int DrvEnd(unsigned);
static inline void DrvSetLeds(unsigned);
static void DrvSetLedsWait(unsigned, unsigned long);

//Client Structures
struct ExecTable
{
	void 		(*pfCode)(void);					    //Code to run
	long		lWaitBefore_sec;						//How long before 1st run
	long		lWaitBefore_nsec;
	long		lWaitAfter_sec;							//How long to wait after run
	long		lWaitAfter_nsec;
	pthread_t tThread;
};

typedef struct ExecTable tExecTable;

//Client Contants

//Client Prototypes
static void DoLoad(void);
static void DoTraffic(void);
static void DoBlink(void);
void Scheduler(tExecTable *);
static void SetLeds(unsigned);
void ExitHandler(int);

//Debugging Assist
#ifndef LED_DEBUG
//Run-time version of low-level io routines
#define OUTB(port,val) outb((port),(val))
#define IOPERM(port, count, yesno) ioperm((port), (count), (yesno))
#else
//Debug version of low-level routines
#define OUTB(val,port) printf("outb(%04X,%02X)\n",port,val)
#define IOPERM(port, count, yesno) (printf("ioperm(%04X,%u)\n",port,count)==0)
#endif

#define SIZE(a) sizeof(a)/sizeof(a[0])
