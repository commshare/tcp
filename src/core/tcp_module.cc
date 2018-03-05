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

    cerr << "\nSENDING TCP Packet: IP Header is "<< iph <<" and ";
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
  //state.rwnd = 1000;
  double timeout = -1;

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

  while (MinetGetNextEvent(event,timeout)==0) {
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

        ConnectionList<TCPState>::iterator connIter = clist.FindMatching(c);

        if (connIter == clist.end()) {
            cerr << "\nNo matching connection found\n";

        }

        cerr << "STATE is: " << connIter->state.GetState();
        unsigned char flags = 0;
        switch(connIter->state.GetState()){

      		case LISTEN: {
      			cerr << "Is Syn: " << IS_SYN(client_flags);

      			if (IS_SYN(client_flags)){
      				cerr << "\nSYN RECEIVED\n";
   					SET_SYN(flags);
    				SET_ACK(flags);

	      			formatAndSendPacket(c, mux, flags, connIter->state.GetLastSent(), ack_num + 1, win_size, 5, 0, empty);
			        connIter->state.SetState(SYN_RCVD);
			        connIter->state.SetLastRecvd(ack_num + 1);
			        connIter->state.rwnd = win_size;
			    }

			    //this is so that incorrectly handled fins from earlier are ignored
			    if (IS_FIN(client_flags)){
			    	SET_ACK(flags);
    				formatAndSendPacket(c, mux, flags, rand() % 1000, ack_num+1, win_size, 5, 0, empty);
			    }
		    	break;
		    }

		    case SYN_RCVD: {
		    	//wait for an ack after revieving syn, if we get something else resend the syn
		    	if (IS_ACK(client_flags)){
		    		connIter->state.SetState(ESTABLISHED);

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
		    		formatAndSendPacket(c, mux, flags, connIter->state.GetLastSent(), connIter->state.GetLastRecvd(), win_size, 5, 0, empty);
		    	}

		    	break;
		    }

		    case SYN_SENT:{
		    	if (IS_ACK(client_flags) && IS_SYN(client_flags)){
		    		cerr << "Expecting: " << connIter->state.GetLastSent() << ", but got: " << seq_num;

		    		//if we get the correct syn ack, then we send an ack and establish the connection
		    		if (connIter->state.GetLastSent() == seq_num){
		    			SET_ACK(flags);
		    			formatAndSendPacket(c, mux, flags, seq_num, ack_num + 1, win_size, 5, 0, empty);
		    			connIter->state.SetLastSent(seq_num);
		    			connIter->state.SetLastRecvd(ack_num + 1);
		    			connIter->state.SetLastAcked(seq_num + 1);

		    			connIter->state.SetState(ESTABLISHED);

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
		    		formatAndSendPacket(c, mux, flags, connIter->state.GetLastSent() - 1, 0, win_size, 5, 0, empty);
		    	}
		    	
		    	break;
		    }

		    case ESTABLISHED: {
		    	//resend our ack if we get a syn ack

		    	//handle fin segment
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
	    			closeNotify.bytes= 0;
	    			closeNotify.error=EOK;

	    			cerr << "\nACKING AND NOTIFYING SOCKET\n";

	    			MinetSend(sock, closeNotify);
	    			connIter->state.SetState(CLOSE_WAIT);
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

	    			cerr << "\nExpected: " << connIter->state.GetLastSent();
	    			cerr << "\nLength of response: " << len;

    				//if this packet has data, send an ack
    				if (len > 0){
	    				SET_ACK(flags);

			    		//ack this packet if we expected it

			    		cerr << "\nINCOMING SEQ NUM: " << ack_num << ", EXPECTED: " << connIter->state.GetLastRecvd() << "\n";
			    		if (ack_num == connIter->state.GetLastRecvd()){
			    			cerr << "\nRECEIVED IN ORDER PACKET\n";

			    			ack_num += len;

			    			formatAndSendPacket(c, mux, flags, seq_num, ack_num, win_size, 5, 0, empty);
			    			connIter->state.SetLastSent(seq_num);
			    			connIter->state.SetLastRecvd(ack_num);

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

			    			formatAndSendPacket(c, mux, flags, connIter->state.GetLastSent(), connIter->state.GetLastRecvd(), win_size, 5, 0, empty);
			    		}
    				}

    				//this packet has no data so it has is an ack
    				else{
    					cerr << "\nRECEIVED ACK\n";

    					//erase all bytes between last ack and new ack
    					cerr << "\n" << seq_num << " " << connIter->state.GetLastAcked() << " bytes removed from buffer" << "\n";
    					connIter->state.SendBuffer.Erase(0, seq_num - connIter->state.GetLastAcked());
    					connIter->state.SetLastAcked(seq_num+1);
    				}

		    		

		    	}
		    	else{
		    		cerr << "\nNEITHER ACK NOR FIN\n";
		    	}
		    	break;
		    }
		    case LAST_ACK:{
		    	if (seq_num == connIter->state.GetLastSent()){
		    		cerr << "\nConnection Done!!\n";
		    		connIter->state.SetState(LISTEN);
		    	}
		    	else{
		    		cerr << "\nGot the wrong ack num, expected : " << connIter->state.GetLastSent() << ", but got: " << seq_num << "\n";
		    	}
		    	break;
		    }
		    case CLOSE_WAIT:{
		    	cerr << "\nSENDING FIN TO REMOTE\n";
		    	unsigned char flags;
		    	SET_FIN(flags);
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

        		SockRequestResponse repl;
	   			repl.type=STATUS;
	    		// buffer is zero bytes
	    		repl.bytes=0;
	    		repl.error=EOK;
	    		MinetSend(sock,repl);

	    		TCPState listenState(rand() % 1000, LISTEN, 3);
                ConnectionToStateMapping<TCPState> listenMapping(s.connection, 0, listenState, false);
                clist.push_back(listenMapping);   

	    		cerr << "\nSENDING CONNECTION OK STATUS\n";
        		break;
        	}

        	case CONNECT:{
        		unsigned char flags = 0;
       	 		SET_SYN(flags);
       	 		seq_num = rand() % 1000;
       	 		for (int i = 0; i < 2; i++){
       	 			sleep(2);
        			formatAndSendPacket(s.connection, mux, flags, seq_num, 0, win_size, 5, 0, empty);
       	 		}

       		 	SockRequestResponse repl;
	   			repl.type=STATUS;
	    		// buffer is zero bytes
	    		repl.bytes=0;
	    		repl.error=EOK;
	    		MinetSend(sock,repl);

	    		TCPState newState(seq_num + 1, SYN_SENT, 3);
	    		newState.rwnd = 1000;
                ConnectionToStateMapping<TCPState> newMapping(s.connection, 0, newState, false);

                clist.push_back(newMapping);   
                cerr << "\nSent syn and added new connection\n";     
        		break;
        	}
        	case WRITE:{
        		cerr << "\nGot Write Request\n";

        		ConnectionList<TCPState>::iterator connIter = clist.FindMatching(s.connection);


        		cerr << connIter->state.GetState();

        		if (connIter->state.GetState() == ESTABLISHED){

        			unsigned data_len = s.data.GetSize();

        			unsigned bytesinFlight = (connIter->state.GetLastSent() + data_len) - connIter->state.GetLastAcked();
        			unsigned bytesSent = data_len;

        			//if sending all the data will put us over receive window, only send the number of bytes to completely fill the window
        			if (bytesinFlight > connIter->state.rwnd){
        				bytesSent -= bytesinFlight - connIter->state.rwnd;
        			}

      				cerr << "\nBytes Sent: " << bytesSent;

        			// create the payload of the packet using the first n bytes of write request
	   				connIter->state.SendBuffer.AddBack(s.data.ExtractFront(bytesSent));

        			unsigned char flags = 0;
       	 			SET_ACK(flags);
       	 			SET_PSH(flags);

        			formatAndSendPacket(s.connection, mux, flags, connIter->state.GetLastSent(), connIter->state.GetLastRecvd(), win_size, 5, bytesSent, connIter->state.SendBuffer);
        			connIter->state.SetLastSent(connIter->state.GetLastSent() + data_len);
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

        		ConnectionList<TCPState>::iterator connIter = clist.FindMatching(s.connection);

        		switch(connIter->state.GetState()){
        			case CLOSE_WAIT: {
        				unsigned char flags = 0;
        				seq_num = rand() % 1000;
        				SET_FIN(flags);

        				cerr << "\nSENDING FIN TO REMOTE\n";   
    					formatAndSendPacket(s.connection, mux, flags, seq_num, 0, win_size, 5, 0, empty);
    					connIter->state.SetState(LAST_ACK);
    					connIter->state.SetLastSent(seq_num + 1);
    					break;
        			}

    				case ESTABLISHED:{
    					unsigned char flags = 0;
    					seq_num = rand() % 1000;
    					SET_FIN(flags);

    					cerr << "\nSENDING FIN TO REMOTE\n";   
						formatAndSendPacket(s.connection, mux, flags, seq_num, 0, win_size, 5, 0, empty);
						connIter->state.SetState(FIN_WAIT1);
						connIter->state.SetLastSent(seq_num + 1);
						break;
    				}
    			}
    		}
    		case FORWARD:{
    			SockRequestResponse repl;
   				repl.type=STATUS;
    			// buffer is zero bytes
    			repl.bytes=0;
    			repl.error=EOK;
    			MinetSend(sock,repl);
    			break;
    		}
        }

      }
    }
  }
  return 0;
}
