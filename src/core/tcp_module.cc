#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>

#include "tcpstate.h"
#include "sockint.h"
#include "constate.h"

#include <iostream>

#include "Minet.h"


using std::cout;
using std::endl;
using std::cerr;
using std::string;

int main(int argc, char *argv[])
{
  MinetHandle mux, sock;
  ConnectionList<TCPState> clist;

  unsigned char flags = 0;
  unsigned char client_flags = 0;
  unsigned int ack_num = 0;
  unsigned int seq_num = 0;
  unsigned short win_size = 1000;

  MinetInit(MINET_TCP_MODULE);

  mux=MinetIsModuleInConfig(MINET_IP_MUX) ? MinetConnect(MINET_IP_MUX) : MINET_NOHANDLE;
  sock=MinetIsModuleInConfig(MINET_SOCK_MODULE) ? MinetAccept(MINET_SOCK_MODULE) : MINET_NOHANDLE;

  if (MinetIsModuleInConfig(MINET_IP_MUX) && mux==MINET_NOHANDLE) {
    MinetSendToMonitor(MinetMonitoringEvent("Can't connect to mux"));
    return -1;
  }

  if (MinetIsModuleInConfig(MINET_SOCK_MODULE) && sock==MINET_NOHANDLE) {
    MinetSendToMonitor(MinetMonitoringEvent("Can't accept from sock module"));
    return -1;
  }

  MinetSendToMonitor(MinetMonitoringEvent("tcp_module handling TCP traffic"));

  printf("\nRunning Module\n");

  MinetEvent event;

  while (MinetGetNextEvent(event)==0) {
    printf("\nReceived\n");
    // if we received an unexpected type of event, print error
    if (event.eventtype!=MinetEvent::Dataflow 
	|| event.direction!=MinetEvent::IN) {
      MinetSendToMonitor(MinetMonitoringEvent("Unknown event ignored."));
    // if we received a valid event from Minet, do processing
    } else {
      cerr << "invalid event from Minet" << endl;
      //  Data from the IP layer below  //
      if (event.handle==mux) {
        Packet p;
        MinetReceive(mux,p);
        unsigned tcphlen=TCPHeader::EstimateTCPHeaderLength(p);
        cerr << "estimated header len="<<tcphlen<<"\n";
        p.ExtractHeaderFromPayload<TCPHeader>(tcphlen);
        IPHeader ipl=p.FindHeader(Headers::IPHeader);
        TCPHeader tcph=p.FindHeader(Headers::TCPHeader);

        cerr << "TCP Packet: IP Header is "<<ipl<<" and ";
        cerr << "TCP Header is "<<tcph << " and ";

        cerr << "Checksum is " << (tcph.IsCorrectChecksum(p) ? "VALID" : "INVALID");

        Connection c;
        // note that this is flipped around because
        // "source" is interepreted as "this machine"

        ipl.GetDestIP(c.src);
        ipl.GetSourceIP(c.dest);
        c.protocol = IP_PROTO_TCP;
        tcph.GetDestPort(c.srcport);
        tcph.GetSourcePort(c.destport);
        tcph.GetFlags(client_flags);
        tcph.GetSeqNum(seq_num);
        tcph.GetAckNum(ack_num);
        tcph.GetWinSize(win_size);

        ConnectionList<TCPState>::iterator cs = clist.FindMatching(c);

        if (cs == clist.end()) {
            cerr << "\nReceived Packet\n";
        }

        Packet p_send;
        IPHeader ih;
        TCPHeader th;

        ih.SetProtocol(c.protocol);
        ih.SetSourceIP(c.src);
        ih.SetDestIP(c.dest);
        ih.SetTotalLength(TCP_HEADER_BASE_LENGTH + IP_HEADER_BASE_LENGTH);
        ih.SetID(rand() % 10000);

        p_send.PushFrontHeader(ih);

        th.SetDestPort(c.destport, p_send);
        th.SetSourcePort(c.srcport, p_send);

        th.SetSeqNum(seq_num+1, p_send);
        th.SetAckNum(ack_num+1, p_send);
        th.SetWinSize(win_size, p_send);
        // th.SetHeaderLen(hlen, p);
        // th.SetUrgentPtr(urgptr, p);
        SET_SYN(flags);
        SET_ACK(flags);
        th.SetFlags(flags, p_send);

        p_send.PushBackHeader(th);

        cerr << "\nSENDING TCP Packet: IP Header is "<<ih<<" and ";
        cerr << "\nSENDING TCP Header is "<< th << " and ";

        MinetSend(mux, p_send);

      }
          //  Data from the Sockets layer above  //
      if (event.handle==sock) {
        SockRequestResponse s;
        MinetReceive(sock,s);
        cerr << "Received Socket Request:" << s << endl;
      }
    }
  }
  return 0;
}
