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
#include "ip.h"

#include <iostream>

#include "Minet.h"


using std::cout;
using std::endl;
using std::cerr;
using std::string;

void formatAndSendPacket(Connection c, MinetHandle mux, unsigned char flags, unsigned int seq_num, unsigned int ack_num, unsigned short win_size, unsigned int hdr_len){
	Packet p_send;
	IPHeader iph;
	TCPHeader tcph;

	iph.SetProtocol(c.protocol);
	iph.SetSourceIP(c.src);
	iph.SetDestIP(c.dest);
    iph.SetTotalLength(TCP_HEADER_BASE_LENGTH + IP_HEADER_BASE_LENGTH);
    p_send.PushFrontHeader(iph);

    tcph.SetDestPort(c.destport, p_send);
    tcph.SetSourcePort(c.srcport, p_send);
    tcph.SetSeqNum(seq_num, p_send);
    tcph.SetAckNum(ack_num, p_send);
    tcph.SetWinSize(win_size, p_send);
    tcph.SetHeaderLen(hdr_len, p_send);
    tcph.SetChecksum(0);
    // th.SetUrgentPtr(urgptr, p);
    tcph.SetFlags(flags, p_send);
    tcph.SetUrgentPtr(0, p_send);
    tcph.RecomputeChecksum(p_send);

    p_send.PushBackHeader(tcph);

    cerr << "\nSENDING TCP Packet: IP Header is "<<iph<<" and ";
    cerr << "\nSENDING TCP Header is "<< tcph << " and ";
    cerr << "Checksum is: " << (tcph.IsCorrectChecksum(p_send) ? "VALID" : "INVALID") << endl;

    MinetSend(mux, p_send);
}

int main(int argc, char *argv[])
{

  unsigned char client_flags = 0;
  unsigned int ack_num = 0;
  unsigned int seq_num = 0;
  unsigned short win_size = 1000;
  MinetHandle mux, sock;
  ConnectionList<TCPState> clist;
  TCPState state;

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
        tcph.GetSeqNum(ack_num);
        tcph.GetAckNum(seq_num);
        tcph.GetWinSize(win_size);

        ConnectionList<TCPState>::iterator cs = clist.FindMatching(c);

        if (cs == clist.end()) {
            cerr << "\nReceived Packet\n";
        }

        cerr << "STATE is: " << state.GetState();
        unsigned char flags = 0;
        switch(state.GetState()){

      		case LISTEN: {
      			cerr << "Is Syn: " << IS_SYN(client_flags);

      			if (IS_SYN(client_flags)){
      				cerr << "\nSYN RECEIVED\n";
   					SET_SYN(flags);
    				SET_ACK(flags);

    				unsigned int seq_num = rand() % 1000;

	      			formatAndSendPacket(c, mux, flags, seq_num, ack_num + 1, win_size, 5);
			        state.SetState(SYN_RCVD);
			        state.SetLastRecvd(ack_num + 1);
			        state.SetLastSent(seq_num);
			    }
		    	break;
		    }

		    case SYN_RCVD: {
		    	if (IS_ACK(client_flags)){
		    		state.SetState(ESTABLISHED);
		    		cerr << "\nCONNECTION ESTABLISHED\n";
		    	}else{
   					SET_SYN(flags);
    				SET_ACK(flags);
		    		formatAndSendPacket(c, mux, flags, state.GetLastSent(), state.GetLastRecvd(), win_size, 5);
		    	}

		    	break;
		    }

		    case SYN_SENT:{
		    	if (IS_ACK(client_flags) && IS_SYN(client_flags)){
		    		cerr << "Expecting: " << state.GetLastSent() << ", but got: " << seq_num;
		    		if (state.GetLastSent() == seq_num){
		    			SET_ACK(flags);
		    			formatAndSendPacket(c, mux, flags, seq_num, ack_num + 1, win_size, 5);
		    			state.SetLastSent(seq_num);
		    			state.SetLastRecvd(ack_num + 1);
		    			state.SetState(ESTABLISHED);
		    			cerr << "\nCONNECTION ESTABLISHED\n";
		    		}
		    	}
		    	else{
		    		//resent SYN
		    		cerr << "\nSomething Wrong, Resending SYN\n";
		    		unsigned char flags = 0;
       	 			SET_SYN(flags);
		    		//formatAndSendPacket(c, mux, flags, state.GetLastSent() - 1, 0, win_size, 5);
		    	}
		    	
		    	break;
		    }

		    case ESTABLISHED: {
		    	if (IS_FIN(client_flags)){
		    		cerr << "\nFIN RECEIVED\n";

    				SET_ACK(flags);
    				formatAndSendPacket(c, mux, flags, rand() % 1000, ack_num+1, win_size, 5);
		    	}

		    	else if(IS_ACK(client_flags)){
		    		cerr << "\nDATA RECEIVED\n";

		    		SET_ACK(flags);

		    		//ack this packet if we expected it

		    		//cerr << "\nINCOMING SEQ NUM: " << ack_num << ", EXPECTED: " << state.GetLastAcked() << "\n";
		    		if (ack_num == state.GetLastRecvd()){
		    			cerr << "\nRECEIVED IN ORDER PACKET\n";

		    			cerr << "\n\n\n" << p.GetPayload() << "\n\n\n";

		    			unsigned short total_len;
		    			ipl.GetTotalLength(total_len);

    					unsigned char iph_len;
    					ipl.GetHeaderLength(iph_len);

    					unsigned char tcph_len;
    					tcph.GetHeaderLen(tcph_len);

    					ack_num += total_len - ((iph_len + tcph_len) * 4);

		    			formatAndSendPacket(c, mux, flags, seq_num, ack_num, win_size, 5);
		    			state.SetLastSent(seq_num);
		    			state.SetLastRecvd(ack_num);

		    		}else{
		    			cerr << "\nRECEIVED OUT OF ORDER PACKET, RESEND LAST PACKET ACKED\n";

		    			formatAndSendPacket(c, mux, flags, state.GetLastSent(), state.GetLastRecvd(), win_size, 5);
		    		}

		    	}
		    	else{
		    		cerr << "\nNEITHER ACK NOR FIN\n";
		    	}
		    }
      	}

        
      }
          //  Data from the Sockets layer above  //
      if (event.handle==sock) {
        SockRequestResponse s;
        MinetReceive(sock,s);
        cerr << "Received Socket Request:" << s << endl;

        switch (s.type){
        	case ACCEPT:{
        		state.SetState(LISTEN);
        		break;
        	}

        	case CONNECT:{
        		unsigned char flags = 0;
       	 		SET_SYN(flags);
       	 		seq_num = rand() % 1000;
       	 		for (int i = 0; i < 7; i++){
        			formatAndSendPacket(s.connection, mux, flags, seq_num, 0, win_size, 5);
        			state.SetLastSent(seq_num + 1);
       	 		}
       		 	state.SetState(SYN_SENT);
        		break;
        	}
        }

      }
    }
  }
  return 0;
}
