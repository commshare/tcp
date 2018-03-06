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
  double TIMEOUT_LEN = 2;
  unsigned char recv_flags = 0;
  unsigned int ack_num;
  unsigned int seq_num;
  short unsigned int win_size;
  Buffer& empty = *(new Buffer());

  MinetHandle mux, sock;
  ConnectionList<TCPState> c_list;

  double min_timeout = -1;

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

  Time prevTime;
  prevTime.SetToCurrentTime();

  while (MinetGetNextEvent(event, min_timeout)==0) {
    printf("\nReceived\n");

     //update timeouts for each connection after minet event
      Time newTime;
      newTime.SetToCurrentTime();

      double elapsedTime = double(newTime) - double(prevTime);
      prevTime = newTime;

      cerr << "\nElapse Time: " << elapsedTime;

      ConnectionList<TCPState>::iterator cMapping = c_list.begin();

      while (cMapping != c_list.end()){
      	if (cMapping->bTmrActive){
      		cerr << "\nActive Timer\n";
			if ((double(cMapping->timeout) - elapsedTime) <= 0){
				//we have timed out
				cerr << "\nConnection Timed out\n";
				cMapping->bTmrActive = false;
				unsigned char flags = 0;
				if (cMapping->state.GetState() == ESTABLISHED){
					//send entire buffer
					SET_ACK(flags);
					SET_PSH(flags);
					formatAndSendPacket(cMapping->connection, mux, flags, cMapping->state.GetLastAcked(), cMapping->state.GetLastRecvd(), cMapping->state.rwnd, 5, cMapping->state.SendBuffer.GetSize(), cMapping->state.SendBuffer);
					break;
				}
			}
			else{
				//decrement timeout remaining
				cMapping->timeout = Time(double(cMapping->timeout) - elapsedTime);
			}
      	}
      	cMapping++;
      }

      //make minet timeout equal to the smallest timeout of our connections
      if (c_list.FindEarliest() == c_list.end()){
      	min_timeout = -1;
      }
      else{
      	min_timeout = c_list.FindEarliest()->timeout;
      }

      cerr << "\nTimeout: " << min_timeout << "\n";

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
        tcph.GetFlags(recv_flags);
        tcph.GetSeqNum(ack_num);
        tcph.GetAckNum(seq_num);
        tcph.GetWinSize(win_size);

        ConnectionList<TCPState>::iterator connIter = c_list.FindMatching(c);

        if (connIter == c_list.end()) {
            cerr << "\nNo matching connection found\n";
            if (IS_FIN(recv_flags)){
            	unsigned char flags = 0;
			    SET_ACK(flags);
    			formatAndSendPacket(c, mux, flags, rand() % 1000, ack_num+1, win_size, 5, 0, empty);
			}
        }

        cerr << "STATE is: " << connIter->state.GetState();
        unsigned char flags = 0;
        switch(connIter->state.GetState()){

      		case LISTEN: {
      			cerr << "Is Syn: " << IS_SYN(recv_flags);

      			if (IS_SYN(recv_flags)){
      				cerr << "\nSYN RECEIVED\n";
   					SET_SYN(flags);
    				SET_ACK(flags);

	      			formatAndSendPacket(c, mux, flags, connIter->state.GetLastSent(), ack_num + 1, win_size, 5, 0, empty);
			        connIter->state.SetState(SYN_RCVD);
			        connIter->state.SetLastRecvd(ack_num + 1);
			        connIter->state.rwnd = win_size;
			    }

			    //this is so that incorrectly handled fins from earlier are ignored
			    if (IS_FIN(recv_flags)){
			    	SET_ACK(flags);
    				formatAndSendPacket(c, mux, flags, rand() % 1000, ack_num+1, win_size, 5, 0, empty);
			    }
		    	break;
		    }

		    case SYN_RCVD: {
		    	//wait for an ack after revieving syn, if we get something else resend the syn
		    	if (IS_ACK(recv_flags)){
		    		connIter->state.SetState(ESTABLISHED);

		    		Buffer empty_data;

		 			//notify socket of new connection

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
		    		formatAndSendPacket(c, mux, flags, connIter->state.GetLastSent(), connIter->state.GetLastRecvd(), connIter->state.rwnd, 5, 0, empty);
		    	}

		    	break;
		    }

		    case SYN_SENT:{
		    	if (IS_ACK(recv_flags) && IS_SYN(recv_flags)){
		    		cerr << "Expecting: " << connIter->state.GetLastSent() << ", but got: " << seq_num;

		    		//if we get the correct syn ack, then we send an ack and establish the connection
		    		if (connIter->state.GetLastSent() == seq_num){
		    			SET_ACK(flags);
		    			formatAndSendPacket(c, mux, flags, seq_num, ack_num + 1, connIter->state.rwnd, 5, 0, empty);
		    			connIter->state.SetLastSent(seq_num);
		    			connIter->state.SetLastRecvd(ack_num + 1);
		    			connIter->state.SetLastAcked(seq_num + 1);

		    			connIter->state.SetState(ESTABLISHED);

		    			//notify socket of new connection
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
		    	else if (IS_FIN(recv_flags)){
		    		unsigned char flags = 0;
			    	SET_ACK(flags);
    				formatAndSendPacket(c, mux, flags, rand() % 1000, ack_num+1, connIter->state.rwnd, 5, 0, empty);
			    }
		    	else{
		    		//resent SYN
		    		cerr << "\nSomething Wrong, Resending SYN\n";
		    		unsigned char flags = 0;
       	 			SET_SYN(flags);
		    		formatAndSendPacket(c, mux, flags, connIter->state.GetLastSent() - 1, 0, connIter->state.rwnd, 5, 0, empty);
		    	}
		    	
		    	break;
		    }

		    case ESTABLISHED: {
		    	//handle fin segment
		    	if (IS_FIN(recv_flags)){
		    		cerr << "\nFIN RECEIVED, going to close wait state\n";

		    		//send ack and notify socket that we are closing connection
    				SET_ACK(flags);
    				formatAndSendPacket(c, mux, flags, rand() % 1000, ack_num+1, win_size, 5, 0, empty);

    				Buffer empty_data;

    				SockRequestResponse closeNotify;
	   				closeNotify.type = WRITE;
	   				closeNotify.connection = c;
	    			// buffer is zero bytes
	    			closeNotify.data = empty_data;
	    			closeNotify.bytes= 0;
	    			closeNotify.error=EOK;

	    			MinetSend(sock, closeNotify);
	    			connIter->state.SetState(CLOSE_WAIT);
		    	}
		    	else if(IS_ACK(recv_flags)){
		    		cerr << "\nDATA RECEIVED\n";

		    		unsigned short total_len;
		    		ipl.GetTotalLength(total_len);

    				unsigned char iph_len;
    				ipl.GetHeaderLength(iph_len);

    				unsigned char tcph_len;
    				tcph.GetHeaderLen(tcph_len);

    				unsigned short len = total_len - ((iph_len + tcph_len) * 4);
    				//cerr << "This is the length: " << len;

			    	//cerr << "\n\n\n" << p.GetPayload() << "\n\n\n";

	    			//cerr << "\nExpected: " << connIter->state.GetLastSent();
	    			//cerr << "\nLength of response: " << len;

    				//if this packet has data, send an ack
    				if (len > 0){
	    				SET_ACK(flags);

			    		//ack this packet if we expected it
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
    					
    					//reset timer
    					if (connIter->state.GetLastAcked() == connIter->state.GetLastSent()){
    						cerr << "\nTimeout off until we send another packet\n";
    						connIter->bTmrActive = false;
    					}else{
    						cerr << "\nReset timeout\n";
    						connIter->bTmrActive = true;
    						connIter->timeout = TIMEOUT_LEN;
    					}
    				}
		    	}
		    	break;
		    }
			case FIN_WAIT1:{
                cerr << "\n\nSTATE SHOULD BE 8 FIN_WAIT1 ENTERED\n\n";
                if(IS_ACK(client_flags))  {
                    cerr << "\nRECEIVED FIN IN FINWAIT1...GOING TO FIN_WAIT2\n";
                    state.SetState(FIN_WAIT2);
                }
                else if(IS_FIN(client_flags)){
                    cerr << "\nRECEIVED ACK IN FINWAIT1...SENDING ACK\n";
                    state.SetState(TIME_WAIT);
                    SET_ACK(flags);
                    formatAndSendPacket(c, mux, flags, seq_num, ack_num, win_size, 5, 0, empty);
                }

            }
            case FIN_WAIT2:{
                cerr << "\n\nSTATE SHOULD BE 11 FIN_WAIT2 ENTERED\n\n"; 
                if(IS_FIN(client_flags)){
                    cerr << "\nRECEIVED FIN IN FIN_WAIT2...SENDING ACK\n";
                    SET_ACK(flags);
                    formatAndSendPacket(c, mux, flags, seq_num, ack_num+1, win_size, 5, 0, empty);
                    state.SetState(TIME_WAIT);
                }

            }
		    case LAST_ACK:{
		    	if (seq_num == connIter->state.GetLastSent()){
		    		cerr << "\nConnection Done!!\n";
		    		connIter->state.SetState(LISTEN);
		    	}
		    	else{
		    		cerr << "\nGot the wrong ack num, expected : " << connIter->state.GetLastSent() << ", but got: " << seq_num << "\n";
		    		cerr << "Closing connection anyway\n";
		    		connIter->state.SetState(CLOSE);
		    	}
		    	break;
		    }
			case TIME_WAIT:{
		    	cerr << "\n\nTIME WAIT\n\n";   
    			//2 MSL wait
                Time t = Time(2*MSL_TIME_SECS);
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
                c_list.push_back(listenMapping);   

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
	    		newState.rwnd = 500;
                ConnectionToStateMapping<TCPState> newMapping(s.connection, 0, newState, false);

                c_list.push_back(newMapping);   
                cerr << "\nSent syn and added new connection\n";     
        		break;
        	}
        	case WRITE:{
        		cerr << "\nGot Write Request\n";

        		ConnectionList<TCPState>::iterator connIter = c_list.FindMatching(s.connection);


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

      				//respond to socket with number of bytes that we sent
      				SockRequestResponse repl;
	   				repl.type=STATUS;
	    			// buffer is zero bytes
	    			repl.bytes=bytesSent;
	    			repl.error=EOK;
	    			MinetSend(sock,repl);

      				if (bytesSent <= 0){
      					//if we can't send any data than no reason to send mesage
      					break;
      				}

        			// create the payload of the packet using the first n bytes of write request
	   				connIter->state.SendBuffer.AddBack(s.data.ExtractFront(bytesSent));

        			unsigned char flags = 0;
       	 			SET_ACK(flags);
       	 			SET_PSH(flags);

        			formatAndSendPacket(s.connection, mux, flags, connIter->state.GetLastSent(), connIter->state.GetLastRecvd(), win_size, 5, bytesSent, connIter->state.SendBuffer);
        			connIter->state.SetLastSent(connIter->state.GetLastSent() + data_len);

        			//start timer if we haven't already
        			if (!(connIter->bTmrActive)){
        				connIter->bTmrActive = true;
        				connIter->timeout = TIMEOUT_LEN;

        				//update minimum timeout value
      					min_timeout = c_list.FindEarliest()->timeout;
        			}

        			cerr << "\nSending Data\n";
        		}
        		break;
        	}

        	case CLOSE:{
        		cerr << "\nSOCKET CLOSE REQUEST\n";

        		ConnectionList<TCPState>::iterator connIter = c_list.FindMatching(s.connection);

        		switch(connIter->state.GetState()){
        			case CLOSE_WAIT: {
        				unsigned char flags = 0;
        				seq_num = rand() % 1000;
        				SET_FIN(flags);
        				SET_ACK(flags);

        				cerr << "\nSENDING FIN TO REMOTE, moving to last ack state\n";   
    					formatAndSendPacket(s.connection, mux, flags, seq_num, 0, win_size, 5, 0, empty);
    					connIter->state.SetState(LAST_ACK);
    					connIter->state.SetLastSent(seq_num + 1);
    					break;
        			}

    				case ESTABLISHED:{
    					unsigned char flags = 0;
    					seq_num = rand() % 1000;
    					SET_FIN(flags);
    					SET_ACK(flags);
    					cerr << "\nSENDING FIN TO REMOTE\n";   
						formatAndSendPacket(s.connection, mux, flags, seq_num, 0, win_size, 5, 0, empty);
						connIter->state.SetState(FIN_WAIT1);
						connIter->state.SetLastSent(seq_num + 1);
						break;
    				}

    				case SYN_SENT:{
    					//closing connection
    					cerr << "\nClosing Connection\n";  
    					connIter->state.SetState(CLOSED);
    				}
    			}
    		}
        }

      }
    }
  }
  return 0;
}
