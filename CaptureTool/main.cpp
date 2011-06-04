// Copyright 2011 Joe Ranieri.
//
// Sniffer is free software: you can redistribute it and/or modify it under the
// terms of the GNU General Public License as published by the Free Software
// Foundation, either version 2 of the License, or (at your option) any later
// version.
//
// Sniffer is distributed in the hope that it will be useful, but WITHOUT ANY
// WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
// FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
// details.
//
// You should have received a copy of the GNU General Public License along with
// Sniffer. If not, see <http://www.gnu.org/licenses/>.

#include <CoreFoundation/CoreFoundation.h>
#include <pcap.h>
#include <libproc.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include "VMBuffer.h"
#include "Utils.h"

#define INVALID_PID -1

static CFMessagePortRef gMessagePort;

/**
 * Determines which process has a socket with the given endpoints. This returns
 * the first process found, or INVALID_PID upon failure.
 *
 * CURRENTLY ONLY HANDLES TCP/IPv4 PACKETS!
 */
pid_t PIDForEndpoints(in_addr_t sourceAddress, int sourcePort, in_addr_t destAddress, int destPort) {
	// We need to call proc_listpids once to get the size of the required buffer,
	// then again to get the actual list.
	static VMBuffer<pid_t> pidBuffer;
	pidBuffer.Grow(proc_listpids(PROC_ALL_PIDS, 0, NULL, 0));
	int pidCount = proc_listpids(PROC_ALL_PIDS, 0, pidBuffer.Data(), pidBuffer.Size()) / sizeof(pid_t);
	
	for(int i = 0; i < pidCount; i++) {
		pid_t pid = pidBuffer[i];
		
		// We need to call proc_pidinfo once to get the size of the required buffer,
		// then again to get the actual list.
		static VMBuffer<proc_fdinfo> fdBuffer;
		fdBuffer.Grow(proc_pidinfo(pid, PROC_PIDLISTFDS, 0, NULL, 0));
		int fdCount = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, fdBuffer.Data(), fdBuffer.Size()) / sizeof(struct proc_fdinfo);
		
		for(int j = 0; j < fdCount; j++) {
			// only interested in sockets
			if(fdBuffer[j].proc_fdtype != PROX_FDTYPE_SOCKET) continue;
			
			// get the socket's info
			socket_fdinfo finfo;
			proc_pidfdinfo(pid, fdBuffer[j].proc_fd, PROC_PIDFDSOCKETINFO, &finfo, sizeof(finfo));
			
			// figure out this file's endpoints (holy nesting!)
			int fdDestPort = finfo.psi.soi_proto.pri_in.insi_fport;
			in_addr_t fdDestAddress = finfo.psi.soi_proto.pri_in.insi_faddr.ina_46.i46a_addr4.s_addr;
			int fdSourcePort = finfo.psi.soi_proto.pri_in.insi_lport;
			in_addr_t fdSourceAddress = finfo.psi.soi_proto.pri_in.insi_laddr.ina_46.i46a_addr4.s_addr;
			
			// see if this is our guy
			if((sourceAddress == fdSourceAddress && sourcePort == fdSourcePort && destAddress == fdDestAddress && destPort == fdDestPort) ||
			   (sourceAddress == fdDestAddress && sourcePort == fdDestPort && destAddress == fdSourceAddress && destPort == fdSourcePort)) {
				return pid;
			}
			
		}
	}
	
	return INVALID_PID;
}

/**
 * Sends information that has been gathered about a packet to the GUI tool on the
 * other end of our CFMesssagePort.
 *
 * The format is:
 * - pcap_pkthdr
 * - packet data
 * - application path
 */
static void SendPacketData(const char *appPath, const struct pcap_pkthdr *packHead, const u_char *packData)
{
	static SInt32 msgid;
	static VMBuffer<UInt8> messageBuffer;
	messageBuffer.Grow(sizeof(pcap_pkthdr) + packHead->caplen + strlen(appPath) + 1);
	
	UInt8 *pos = messageBuffer.Data();
	memcpy(pos, packHead, sizeof(pcap_pkthdr));
	pos += sizeof(pcap_pkthdr);
	
	memcpy(pos, packData, packHead->caplen);
	pos += packHead->caplen;
	
	memcpy(pos, appPath, strlen(appPath) + 1);
	pos += strlen(appPath) + 1;
	
	CFDataRef data = CFDataCreateWithBytesNoCopy(NULL, messageBuffer.Data(), pos - messageBuffer.Data(), kCFAllocatorNull);
	CFMessagePortSendRequest(gMessagePort, msgid++, data, -1, -1, NULL, NULL);
	CFRelease(data);
}

/**
 * The libpcap callback function. Invoked every time a packet is sent/received.
 */
void Handler(u_char *one, const struct pcap_pkthdr *packHead, const u_char *packData) {
	const struct ether_header *etherHeader = (const struct ether_header *)packData;
	const struct ip *ipHeader = (const struct ip *)(etherHeader + 1);
	
	// we can only find endpoints for TCP sockets for now
	if(IPPROTO_TCP == ipHeader->ip_p) {
		const struct tcphdr *tcpHeader = (const struct tcphdr *)(ipHeader + 1);
		
		// try to find our pid
		pid_t owningProcess = PIDForEndpoints(ipHeader->ip_src.s_addr, tcpHeader->th_sport, ipHeader->ip_dst.s_addr, tcpHeader->th_dport);
		
		// did we find it?
		if(INVALID_PID != owningProcess) {			
			// grab the path
			char processPath[MAXPATHLEN] = {};
			proc_pidpath(owningProcess, processPath, sizeof(processPath));
			
			SendPacketData(processPath, packHead, packData);
			return;
		} else {
			SendPacketData("(unknown TCP)", packHead, packData);
			return;
		}
	}
	
	SendPacketData("(unknown other)", packHead, packData);
}

bool SetupCapture(const char *interface) {
	pcap_t *handle = pcap_open_live(interface, BUFSIZ, 1, 2, NULL);
	if (handle == NULL) return false;
	
	// We can't run this on the main thread because it'll block, so we need to
	// set it up on a background thread. I tried quite a bit to get this running
	// under a CFRunloop using CFFileDescriptorRef, but it just wouldn't work.
	//
	// If I ran it under libdispach directly, it worked fine (I think), but then
	// I couldn't get notifications about the message port being invalidated.
	RunBlockThreaded(^(void) {
		pcap_loop(handle, -1, Handler, NULL);
		pcap_close(handle);
	});
	
	return true;
}

void MessagePortClosed(CFMessagePortRef ms, void *info) {
	// FIXME: we should think about how this process should gracefully shut down.
	// Currently this doesn't kill the capture thread we set up or allow pcap_close
	// to run.
	//
	// I doubt it matters though.
	CFRunLoopStop(CFRunLoopGetCurrent());
}

int main(int argc, char *argv[]) {
	// The name of the message port we're supposed to be connecting to will be the
	// first argument passed to the program. If it's invalid or not specified,
	// this is a critical error and we must abort the process.
	if (argc >= 2) {
		CFStringRef portName = CFStringCreateWithCString(NULL, argv[1], kCFStringEncodingUTF8);
		gMessagePort = CFMessagePortCreateRemote(NULL, portName);
		CFRelease(portName);
		
		if (!gMessagePort) return 1;
	}
	
	// FIXME: don't hardcode "en1". Instead we should probably have it passed
	// to us in argv.
	if (SetupCapture("en1")) {
		// We need to get notified when this message port gets invalidated because
		// this is our signal by the parent process that capturing needs to stop.
		//
		// Since we're in CF-land and not using Mach ports directly, we need a
		// CFRunLoop and not dispatch_main.
		CFMessagePortSetInvalidationCallBack(gMessagePort, MessagePortClosed);
		CFRunLoopRun();
		return 0;
	}
	
	return 1;
}
