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

void formatAndSendPacket(Connection c, MinetHandle mux, unsigned char flags, unsigned int seq_num, unsigned int ack_num, unsigned short win_size, unsigned int hdr_len, unsigned data_len, Buffer &data){
	Packet p_send;

	IPHeader iph;
	TCPHeader tcph;

	//send the end of the buffer
	if (data_len != 0){
		Packet p(data.ExtractBack(data_len));
		p_send = p;
		cerr << "\nPayload: " << p.GetPayload();
	}

	iph.SetProtocol(c.protocol);
	iph.SetSourceIP(c.src);
	iph.SetDestIP(c.dest);
    iph.SetTotalLength(data_len + TCP_HEADER_BASE_LENGTH + IP_HEADER_BASE_LENGTH);
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
  Buffer& empty = *(new Buffer());

  MinetHandle mux, sock;
  ConnectionList<TCPState> clist;
  TCPState state;
  state.rwnd = 1000;

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
            cerr << "\nReceived New Connection\n";
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

	      			formatAndSendPacket(c, mux, flags, seq_num, ack_num + 1, win_size, 5, 0, empty);
			        state.SetState(SYN_RCVD);
			        state.SetLastRecvd(ack_num + 1);
			        state.SetLastSent(seq_num);
			    }
			    if (IS_FIN(client_flags)){
			    	SET_ACK(flags);
    				formatAndSendPacket(c, mux, flags, rand() % 1000, ack_num+1, win_size, 5, 0, empty);
			    }
		    	break;
		    }

		    case SYN_RCVD: {
		    	if (IS_ACK(client_flags)){
		    		state.SetState(ESTABLISHED);

		    		Buffer empty_data;

		    		SockRequestResponse notif;
	   				notif.type=WRITE;
	   				notif.connection = c;
	    			// buffer is zero bytes
	    			notif.data = empty_data;
	    			notif.bytes= 0;
	    			notif.error=EOK;
	    			MinetSend(sock,notif);

		    		cerr << "\nCONNECTION ESTABLISHED\n";
		    	}else{
   					SET_SYN(flags);
    				SET_ACK(flags);
		    		formatAndSendPacket(c, mux, flags, state.GetLastSent(), state.GetLastRecvd(), win_size, 5, 0, empty);
		    	}

		    	break;
		    }

		    case SYN_SENT:{
		    	if (IS_ACK(client_flags) && IS_SYN(client_flags)){
		    		cerr << "Expecting: " << state.GetLastSent() << ", but got: " << seq_num;

		    		if (state.GetLastSent() == seq_num){
		    			SET_ACK(flags);
		    			formatAndSendPacket(c, mux, flags, seq_num, ack_num + 1, win_size, 5, 0, empty);
		    			state.SetLastSent(seq_num);
		    			state.SetLastRecvd(ack_num + 1);
		    			state.SetLastAcked(seq_num+1);

		    			state.SetState(ESTABLISHED);

		    			SockRequestResponse notif;
	   					notif.type=WRITE;
	   					notif.connection = c;
	    				// buffer is zero bytes
	    				notif.bytes=0;
	    				notif.error=EOK;
	    				MinetSend(sock,notif);

		    			cerr << "\nCONNECTION ESTABLISHED\n";
		    		}
		    	}
		    	else if (IS_FIN(client_flags)){
			    	SET_ACK(flags);
    				formatAndSendPacket(c, mux, flags, rand() % 1000, ack_num+1, win_size, 5, 0, empty);
			    }
		    	else{
		    		//resent SYN
		    		cerr << "\nSomething Wrong, Resending SYN\n";
		    		unsigned char flags = 0;
       	 			SET_SYN(flags);
		    		formatAndSendPacket(c, mux, flags, state.GetLastSent() - 1, 0, win_size, 5, 0, empty);
		    	}
		    	
		    	break;
		    }

		    case ESTABLISHED: {
		    	if (IS_SYN(client_flags)){
		    		cerr << "\nREJECTED SYN\n";
		    		break;
		    	}

		    	
		    	if (IS_FIN(client_flags)){
		    		cerr << "\nFIN RECEIVED\n";

		    		//send ack and notify socket that we are closing connection
    				SET_ACK(flags);
    				formatAndSendPacket(c, mux, flags, rand() % 1000, ack_num+1, win_size, 5, 0, empty);

    				Buffer empty_data;

    				SockRequestResponse closeNotify;
	   				closeNotify.type= WRITE;
	   				closeNotify.connection = c;
	    			// buffer is zero bytes
	    			closeNotify.data = empty_data;
	    			closeNotify.bytes=0;
	    			closeNotify.error=EOK;

	    			cerr << "\nACKING AND NOTIFYING SOCKET\n";

	    			MinetSend(sock, closeNotify);
	    			state.SetState(CLOSE_WAIT);
		    	}
		    	else if(IS_ACK(client_flags)){
		    		cerr << "\nDATA RECEIVED\n";

		    		unsigned short total_len;
		    		ipl.GetTotalLength(total_len);

    				unsigned char iph_len;
    				ipl.GetHeaderLength(iph_len);

    				unsigned char tcph_len;
    				tcph.GetHeaderLen(tcph_len);

    				unsigned short len;
    				//len = tcph_len - TCP_HEADER_BASE_LENGTH;
    				len = total_len - ((iph_len + tcph_len) * 4);
    				cerr << "This is the length: " << len;

			    	cerr << "\n\n\n" << p.GetPayload() << "\n\n\n";

	    			cerr << "\nExpected: " << state.GetLastSent();
	    			cerr << "\nLength of response: " << len;

    				//if this packet has data, send an ack
    				if (len > 0){
	    				SET_ACK(flags);

			    		//ack this packet if we expected it

			    		cerr << "\nINCOMING SEQ NUM: " << ack_num << ", EXPECTED: " << state.GetLastRecvd() << "\n";
			    		if (ack_num == state.GetLastRecvd()){
			    			cerr << "\nRECEIVED IN ORDER PACKET\n";

			    			ack_num += len;

			    			formatAndSendPacket(c, mux, flags, seq_num, ack_num, win_size, 5, 0, empty);
			    			state.SetLastSent(seq_num);
			    			state.SetLastRecvd(ack_num);

			    			Buffer &data = p.GetPayload().ExtractFront(len);

			    			SockRequestResponse write(WRITE,
					    		c,
					    		data,
					    		len,
					    		EOK);

			    			MinetSend(sock,write);
			    			cerr << "\nWRITING DATA TO SOCKET\n";

			    		}else{
			    			cerr << "\nRECEIVED OUT OF ORDER PACKET, RESEND LAST PACKET ACKED\n";

			    			formatAndSendPacket(c, mux, flags, state.GetLastSent(), state.GetLastRecvd(), win_size, 5, 0, empty);
			    		}
    				}
    				//this packet has no data so it has is an ack
    				else{
    					cerr << "\nRECEIVED ACK\n";

    					//erase all bytes between last ack and new ack
    					cerr << "\n" << seq_num << " " << state.GetLastAcked() << " bytes removed from buffer" << "\n";
    					state.SendBuffer.Erase(0, seq_num - state.GetLastAcked());
    					state.SetLastAcked(seq_num+1);
    				}

		    		

		    	}
		    	else{
		    		cerr << "\nNEITHER ACK NOR FIN\n";
		    	}
		    	break;
		    }
		    case LAST_ACK:{
		    	if (seq_num == state.GetLastSent()){
		    		cerr << "\nConnection Done!!\n";
		    		state.SetState(LISTEN);
		    	}
		    	else{
		    		cerr << "\nGot the wrong ack num, expected : " << state.GetLastSent() << ", but got: " << seq_num << "\n";
		    	}
		    	break;
		    }
		    case CLOSE_WAIT:{
		    	cerr << "\nSENDING FIN TO REMOTE\n";   
    			formatAndSendPacket(c, mux, flags, seq_num, 0, win_size, 5, 0, empty);
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

        		SockRequestResponse repl;
	   			repl.type=STATUS;
	    		// buffer is zero bytes
	    		repl.bytes=0;
	    		repl.error=EOK;
	    		MinetSend(sock,repl);

	    		cerr << "\nSENDING CONNECTION OK STATUS\n";
        		break;
        	}

        	case CONNECT:{
        		unsigned char flags = 0;
       	 		SET_SYN(flags);
       	 		seq_num = rand() % 1000;
       	 		for (int i = 0; i < 7; i++){
        			formatAndSendPacket(s.connection, mux, flags, seq_num, 0, win_size, 5, 0, empty);
        			state.SetLastSent(seq_num + 1);
       	 		}

       		 	state.SetState(SYN_SENT);

       		 	SockRequestResponse repl;
	   			repl.type=STATUS;
	    		// buffer is zero bytes
	    		repl.bytes=0;
	    		repl.error=EOK;
	    		MinetSend(sock,repl);

                cerr << "\nSENDING SOCKET CONNECTION STATUS\n";        

        		break;
        	}
        	case WRITE:{
        		cerr << "\nGot Write Request\n";
        		cerr << state.GetState();

        		if (state.GetState() == ESTABLISHED){

        			unsigned data_len = s.data.GetSize();

        			unsigned bytesinFlight = (state.GetLastSent() + data_len) - state.GetLastAcked();
        			unsigned bytesSent = data_len;

        			//if sending all the data will put us over receive window, only send the number of bytes to completely fill the window
        			if (bytesinFlight > state.rwnd){
        				bytesSent -= bytesinFlight - state.rwnd;
        			}

        			// create the payload of the packet
	   				state.SendBuffer.AddBack(s.data.ExtractFront(bytesSent));

        			unsigned char flags = 0;
       	 			SET_ACK(flags);
       	 			SET_PSH(flags);

        			formatAndSendPacket(s.connection, mux, flags, state.GetLastSent(), state.GetLastRecvd(), win_size, 5, bytesSent, state.SendBuffer);
        			state.SetLastSent(state.GetLastSent() + data_len);
        			cerr << "\nSending Data\n";

        			SockRequestResponse repl;
	   				repl.type=STATUS;
	    			// buffer is zero bytes
	    			repl.bytes=bytesSent;
	    			repl.error=EOK;
	    			MinetSend(sock,repl);
        		}
        		break;
        	}

        	case CLOSE:{
        		cerr << "\nSOCKET CLOSE REQUEST\n";
        		switch(state.GetState()){
        			case CLOSE_WAIT: {
        				unsigned char flags = 0;
        				seq_num = rand() % 1000;
        				SET_FIN(flags);

        				cerr << "\nSENDING FIN TO REMOTE\n";   
    					formatAndSendPacket(s.connection, mux, flags, seq_num, 0, win_size, 5, 0, empty);
    					state.SetState(LAST_ACK);
    					state.SetLastSent(seq_num + 1);
        			}

        			case ESTABLISHED:{
        				unsigned char flags = 0;
        				seq_num = rand() % 1000;
        				SET_FIN(flags);

        				cerr << "\nSENDING FIN TO REMOTE\n";   
    					formatAndSendPacket(s.connection, mux, flags, seq_num, 0, win_size, 5, 0, empty);
    					state.SetState(FIN_WAIT1);
    					state.SetLastSent(seq_num + 1);
        			}
        		}
        		break;
        	}
        }

      }
    }
  }
  return 0;
}
