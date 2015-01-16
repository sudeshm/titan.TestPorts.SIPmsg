/******************************************************************************
* Copyright (c) 2005, 2014  Ericsson AB
* All rights reserved. This program and the accompanying materials
* are made available under the terms of the Eclipse Public License v1.0
* which accompanies this distribution, and is available at
* http://www.eclipse.org/legal/epl-v10.html
*
* Contributors:
*   Gabor Szalai - initial implementation and initial documentation
*   Gergely Futo
*   Laszlo Skumat
*   Pinter Norbert
*   Oliver Ferenc Czerman
*   Peter Balazs
*   Koppány Csaba Béla
*   Kulcsár Endre
*   Szalai Zsolt
******************************************************************************/
//
//  File:               SIPmsg_PT.hh
//  Rev:                R12D
//  Prodnr:             CNL 113 319
//  Reference:          RFC3261, RFC2806, RFC2976, RFC3262, RFC3311, RFC3323, 
//                      RFC3325, RFC3326, RFC3265, RFC3455, RFC4244
//                      IETF Draft draft-ietf-dip-session-timer-15.txt,
//                      IETF Draft draft-levy-sip-diversion-08.txt
//                      

#ifndef SIPmsg__PTType_HH
#define SIPmsg__PTType_HH

#include "SIPmsg_PortType.hh"

#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>


#define MAX_IN_BUFFER 65536

extern int SIP_parse_parse();

namespace SIPmsg__PortType{

class SIPmsg__PT : public SIPmsg__PT_BASE {

public:
  SIPmsg__PT(const char *SIPmsg__PT_name = NULL);
  ~SIPmsg__PT();

  void set_parameter(const char *parameter_name,
          const char *parameter_value);
  void Event_Handler(const fd_set *read_fds,
          const fd_set *write_fds, const fd_set *error_fds,
          double time_since_last_call);

  SIPmsg__Types::PDU__SIP__Response *respmsg;
  SIPmsg__Types::PDU__SIP__Request *reqmsg;
  CHARSTRING raw_msg;

  void static encode_headers(char *&, int &, int &,int ,int,int, bool, const SIPmsg__Types::MessageHeader *header);
  void static write_to_buff(char *&, int &, int &,const char *mit);
  void static write_to_buff(char *&, int &, int &,const CHARSTRING &mit);
  void static write_to_buff(char *&, int &, int &,const OCTETSTRING &mit);
  void static print_url(char *&, int &, int &,const SIPmsg__Types::SipUrl *cim, int brallowed, bool = true);
  void static print_host(char *&, int &, int &, const CHARSTRING &, bool);

protected:
  void user_start();
  void user_stop();

  void outgoing_send(const SIPmsg__Types::PDU__SIP__Request& send_par, const ADDRESS *destination_address);
  void outgoing_send(const SIPmsg__Types::PDU__SIP__Response& send_par, const ADDRESS *destination_address);
  void outgoing_send(const SIPmsg__Types::PDU__SIP__Raw& send_par, const ADDRESS *destination_address);

  void outgoing_send(const SIPmsg__Types::ASP__SIP__Request& send_par, const ADDRESS *destination_address);
  void outgoing_send(const SIPmsg__Types::ASP__SIP__Response& send_par, const ADDRESS *destination_address);
  void outgoing_send(const SIPmsg__Types::ASP__SIP__Raw& send_par, const ADDRESS *destination_address);
  void outgoing_send(const SIPmsg__Types::ASP__SIP__open& send_par, const ADDRESS *destination_address);
  void outgoing_send(const SIPmsg__Types::ASP__SIP__close& send_par, const ADDRESS *destination_address);
  void user_map(const char *system_port);
  void user_unmap(const char *system_port);

private:
  bool debug;
  bool asp;
  bool random_udp;
  bool ipv6enabled;
  bool close_soc;
  bool auto_length;
  bool report_error;
  int port_mode;  // 0- basic
                  // 1- advanced
  int mtu_size;
  int raw_mode;
  int decoding_enabled;
  int multiple_headers;
  int header_mode;// 0- long
                  // 1- short
  int error_mode; // 0- error
                  // 1- warning
                  // 2- ignore
  int status;   // test port status
                  // 0- CREATED - Sip test port created
                  // 1- STARTED - Sip test port started
                  // 2- LISTENING - Listening socket open
                  // 3- CONNECTED - Live connection
                  // 4- STOPPED - Sip test port stopped
  int udportcp;        // Sip via UDP or TCP   UDP -> 0; TCP -> 1
  int listen_soc;      // listening socket file descriptor
  int listen_soc_tcp;
  int comm_soc;        // communication socket file descriptor

  int local_port;      // locat port number
  char *local_addr;    // target address
  int target_port;     // target port
  char *target_addr;   // target address
  int listen_enabled;  // Open listening socket enabled?
                       // 0- Not enabled
                       // non zero- Enabled
                       // In advanced mode
                       // 1- listening on UDP enabled
                       // 2- listening on TCP enabled
                       // 3- enabled for TCP and UDP

  struct sockaddr_in listen_addr;     // listening address struct
  struct sockaddr_in remote_addr;     // communitaion address struct
  int wildcarded_enabled_port;

  int wait_msg_body;
  int body_length;
  int errorind;

  int msgsize;
  char msg_in_buffer[MAX_IN_BUFFER];
  char *msg_encode_buff;
  int msg_encode_buff_size;
  fd_set connections_read_fds;
  ADDRESS dest_addr;

  struct connection_data{
    char *addr;
    int  port;
    int  fp;
    char *buff;
    int msgsize;
    int buffsize;
    int wait_msg_body;
    int errorind;
    SIPmsg__Types::PDU__SIP__Response *respmsg;
    SIPmsg__Types::PDU__SIP__Request *reqmsg;
    CHARSTRING *raw_msg;
  };

  connection_data *conn_list;
  int size_conn_list;
  int active_connections;
  int last_conn;

  void static print_list(char *&, int &, int &,const SIPmsg__Types::GenericParam__List *lista, const char* separator[]);
  void static print_addr_union(char *&, int &, int &,const SIPmsg__Types::Addr__Union *addr, bool);

  bool static isIPv6address(const CHARSTRING &);
  void set_addr_struct(struct sockaddr_in *addr_st, int port_num, const char* host_name);
  int open_comm_socket(struct sockaddr_in addr_st);
  int open_comm_socket(struct sockaddr_in addr_st, struct sockaddr_in listen_st, int uort);
  inline void send_msg(const char *buff);
  void check_address(const ADDRESS *destination_address);
  void check_address(const SIPmsg__Types::SIP__comm__adress *destination_address);
  inline void reduce_buff(int lenght,char *buff,int bufflen);
  int get_conn_fp(const SIPmsg__Types::SIP__comm__adress *);
  int get_conn_id(const char*,int);
  int get_conn_id(int);
  int add_conn(const char*,int, int fd=-1);
  void remove_conn(int);
  void close_conn(int);
  int get_content_length(char *, int);
  void decode_messages(
    int udportcp_loc,
    int &wait_msg_body_loc,
    int &msg_in_len_loc,
    char *msg_in_buffer_loc,
    int &errorind_l,
    CHARSTRING &raw_msg_loc,
    SIPmsg__Types::PDU__SIP__Response *&respmsg_loc,
    SIPmsg__Types::PDU__SIP__Request *&reqmsg_loc,
    ADDRESS &dest_addr_loc
  );
  void log(const char *fmt, ...)
    __attribute__((format(printf, 2, 3)));

};
}
#endif
