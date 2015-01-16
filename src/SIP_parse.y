%{

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
//  File:               SIP_parse.y
//  Rev:                R12D
//  Prodnr:             CNL 113 319
//  Reference:          RFC3261, RFC2806, RFC2976, RFC3262, RFC3311, RFC3323, 
//                      RFC3325, RFC3326, RFC3265, RFC3455, RFC4244, RFC4538,
//                      RFC6442, RFC6086, RFC6050
//                      IETF Draft draft-ietf-dip-session-timer-15.txt,
//                      IETF Draft draft-levy-sip-diversion-08.txt, RFC5009
//                      IETF draft-ott-sip-serv-indication-notification-00
//                      IETF draft-holmberg-sipcore-proxy-feature-04,
//                      

/* C declarations */
#include <stdlib.h>
#include <ctype.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include "memory.h"

#include "SIPmsg_Types.hh"

#define YYDEBUG 1
using namespace SIPmsg__Types;
extern const char *myinputptr;
extern const char *myinputlim;
  extern void init_SIP_parse_lex();
  struct yy_buffer_state;
  extern yy_buffer_state *SIP_parse__scan_bytes(const char*, int);
  extern void SIP_parse__delete_buffer(yy_buffer_state*);
extern int SIP_parse_error(const char *);
extern int SIP_parse_lex();
extern int SIP_parse_parse();
extern void initcounters();
extern int SIP_parse_lex_destroy();
//Response *msgptr;

RequestLine *rqlineptr;
StatusLine *stlineptr;
MessageHeader *headerptr;
int wildcarded_enabled_parser;

// header part pointers
extern SipUrl *uriptr;
extern GenericParam__List *paramptr;
extern OptionTag__List *optptr;
extern RouteBody__List *routeptr;


// parameter counters
extern int paramcount;
extern int urlparamcount;
extern int headercount;
extern int optioncount;
extern int rcount;

// header counters
extern int acceptcount;
extern int aceptenccount;
extern int acceptlangcount;
extern int alertinfcount;
extern int allowcount;
extern int callinfocount;
extern int contactcount;
extern int contentenccount;
extern int contentlangcount;
extern int errorinfocount;
extern int featureCapscount;
extern int inreplytocount;
extern int passertedidcount;
extern int ppreferredidcount;
extern int privacycount;
extern int proxyreqcount;
extern int reasoncount;
extern int recroutecount;
extern int recvinfocount;
extern int routecount;
extern int reqcount;
extern int suppcount;
extern int unsuppcount;
extern int servercount;
extern int useragentcount;
extern int viacount;
extern int warncount;
extern int undefcount;
extern int aos_count;

char comment_buf[1500];
int errorind_loc;

char *trim(char *string);

bool ipv6enabled;
char *trimOnIPv6(char *string);
void resetptr();

extern char * stream_buffer; // EPTEBAL
%}

/* Bison declarations */

/*%expect 0*/

%union {
  unsigned int iv;
  char cv  ;
  char *sv ;
  SIPmsg__Types::Event__type *e_type;
  SIPmsg__Types::Event__template__list *e_template_list;
  SIPmsg__Types::Event__type__list *e_list;
  SIPmsg__Types::NameAddr *naddr;
  SIPmsg__Types::P__Assoc__uri__spec__list *u_spec_list;
  SIPmsg__Types::P__Assoc__uri__spec *u_spec;
  SIPmsg__Types::Network__spec *n_spec;
  SIPmsg__Types::Network__spec__list *n_spec_list;
  SIPmsg__Types::Access__net__spec *an_spec;
  SIPmsg__Types::Access__net__spec__list *an_spec_list;
  SIPmsg__Types::GenericParam__List *p_list;
  SIPmsg__Types::Contact__list *c_list;
  SIPmsg__Types::Request__disp__directive__list *d_list;
  SIPmsg__Types::Media__auth__token__list *a_t_list;
  SIPmsg__Types::RouteBody *route_val;
  SIPmsg__Types::RouteBody__List *route_list;
  SIPmsg__Types::Security__mechanism *sec_mech;
  SIPmsg__Types::Security__mechanism__list *sec_mech_list;
  SIPmsg__Types::HostPort *host_p;
  SIPmsg__Types::Diversion__params *divparam;
  SIPmsg__Types::Diversion__params__list *divparam_list;
  SIPmsg__Types::Hi__Entry *history_entry;
  SIPmsg__Types::Hi__Entry__list *history_entry_list;
  SIPmsg__Types::Em__param__List *em_bdy_list;
  SIPmsg__Types::Service__ID__List *service_1toN;
  SIPmsg__Types::Rvalue__List *r_val_list;
  SIPmsg__Types::Rvalue *rval;
  SIPmsg__Types::Location__value__list *g_val_list;
  SIPmsg__Types::Location__value *g_val;
}

%type <g_val_list> geoloaction_list1toN
%type <g_val> geoloaction_value
%token <cv> _SP
%token <sv> LONE_CRLF

%token <iv> EXTENSION_CODE

%token <sv> REASON_PHRASE SIP_VERSION SIP_SPHT_VERSION
%token <sv> _METHOD CONTENT_WITHOUTENDINGCRLF _CALLID

%token WWW_AUTHENTICATELWSCOLON _CRLF
%token PROXY_AUTHENTICATELWSCOLON
%token TOLWSCOLON
%token CONTACTLWSCOLON
%token ACCEPTRESPRIOLWSCOLON RESPRIOLWSCOLON
%token <sv> FROMLWSCOLON _TYPEID
%type <r_val_list> rvalue_list1toN
%type <rval> rvalue_value
%type <sv> From display_name
%token <sv> TOKENS QUOTED_STRING EPARENT SPARENT OTHERLWSCOLON
%type <sv> equals_token_host_qtdstr equals_token_host_qtdstr_withoutlws 
%type <sv> token_or_host_or_quotedstring product_comment
%type <e_type> event_event
%type <e_template_list> event_event_template1toN
%type <e_list> event_list1toN
%type <naddr> p_nameaddr
%type <u_spec> p_urispec
%type <u_spec_list> p_urispec_1toN
%type <history_entry> h_urispec
%type <history_entry_list> h_urispec_1toN
%type <n_spec> vnetspec
%type <n_spec_list> vnetspec_1toN
%type <an_spec> anetspec
%type <an_spec_list> anetspec_1toN
%type <p_list> conatact_value
%type <c_list> conatact_1toN
%type <d_list> directive_1toN
%type <a_t_list> auth_token_1toN
%type <route_val> routeadr
%type <route_list> routebdy1toN
%type <sec_mech> Secmechanism
%type <sec_mech_list> Secmechanism_1toN
%type <host_p> host_and_port
%type <divparam> p_divspec
%type <divparam_list> p_divspec_1toN
%type <em_bdy_list> embody1toN
%type <service_1toN> service1toN
%token CALL_IDLWSCOLON SOMELWS _LAES_CONTENT
%token <sv> _TOKEN _STOKEN _DIGEST _COMMENT USERINFO_AT _STAR

%token GEOLOCERRORLWSCOLON
%token GEOLOCATIONLWSCOLON
%token SUPPORTEDLWSCOLON 
%token VIALWSCOLON
%token SUBJECTLWSCOLON
%token CONTENT_ENCODINGLWSCOLON

%token CONTENT_LENGTHLWSCOLON
%token <sv> SOMEDIGITS

%token CONTENT_TYPELWSCOLON

%token ACCEPTLWSCOLON
%token ACCEPT_ENCODINGLWSCOLON
%token ACCEPT_LANGUAGELWSCOLON
%token AUTHINFOLWSCOLON
%token CALL_INFOLWSCOLON
%token MINEXPIRESLWSCOLON

%token CSEQLWSCOLON
%token EVENTLWSCOLON
%token ALLOWEVENTLWSCOLON
%token SUBSTATEWSCOLON
%token DATELWSCOLON
%token MIME_VERSIONLWSCOLON
%token ORGANIZATIONLWSCOLON
%token RECORD_ROUTELWSCOLON
%token PCALLEPPTYLWSCOLON
%token PVISITEDNETLWSCOLON
%token REQUIRELWSCOLON
%token HISTORYLWSCOLON
%token TIMESTAMPLWSCOLON
%token USER_AGENTLWSCOLON
%token PASSOCURILWSCOLON
%token DIVERSIONWSCOLON
%token ERROR_INFOLWSCOLON
%token RETRY_AFTERLWSCOLON
%token SERVERLWSCOLON
%token UNSUPPORTEDLWSCOLON
%token WARNINGLWSCOLON
%token PASSERTEDLWSCOLON
%token REASONLWSCOLON
%token PPREFERREDLWSCOLON
%token PRIVACYLWSCOLON
%token RACKLWSCOLON
%token RSEQLWSCOLON
%token ALERT_INFOLWSCOLON
%token AUTHORIZATIONLWSCOLON
%token IN_REPLY_TOLWSCOLON
%token REPLY_TOLWSCOLON
%token MAX_FORWARDSLWSCOLON
%token REFER_TOLWSCOLON
%token PRIORITYLWSCOLON
%token PROXY_AUTHORIZATIONLWSCOLON
%token PROXY_REQUIRELWSCOLON
%token ROUTELWSCOLON
%token ALLOWLWSCOLON
%token PEARLYMEDIALWSCOLON
%token CONTENT_DISPOSITIONLWSCOLON
%token CONTENT_LANGUAGELWSCOLON
%token EXPIRESLWSCOLON
%token SESSIONEXPWSCOLON
%token SESSIONIDLWSCOLON
%token MINSELWSCOLON
%token SOMELWSCOMMA
%token PACCESSNETLWSCOLON
%token REQDISPLWSCOLON
%token PCHARGEADDRLWSCOLON
%token PCHARGEVECTORLWSCOLON
%token ANSWERMODELWSCOLON
%token PRIVANSWERMODELWSCOLON
%token ALERTMODELWSCOLON
%token REFERSUBLWSCOLON
%token PALERTINGMODELWSCOLON
%token PANSWERSTATELWSCOLON
%token ACCEPTCONTACTLWSCOLON
%token REJECTCONTACTLWSCOLON
%token PMEDIAAUTHLWSCOLON
%token PATHLWSCOLON
%token SECCLIENTLWSCOLON
%token SECSERVERLWSCOLON
%token SECVERIFYLWSCOLON
%token PTARCEPTYIDLWSCOLON
%token POSPSLWSCOLON
%token PBILLINGINFOLWSCOLON
%token PLAESLWSCOLON
%token PDCSREDIRLWSCOLON
%token PUSERDBASELWSCOLON
%token SERVICEROUTELWSCOLON
%token REFERREDBYTOLWSCOLON
%token REPLACESLWSCOLON
%token IFMATCHLWSCOLON
%token ETAGLWSCOLON
%token JOINLWSCOLON
%token PSERVEDUSERLWSCOLON
%token PPROFILEKEYLWSCOLON
%token PSERVICEINDICATIONLWSCOLON
%token PSERVICENOTIFICATIONLWSCOLON
%token GEOROUTINGLWSCOLON
%token TARGETDIALOGLWSCOLON
%token INFOPACKAGELWSCOLON
%token FEATURECAPSLWSCOLON
%token RECVINFOLWSCOLON
%token <sv> _TOKEN_NO_DOT _HEXTOKEN
%token <cv> _DOT
%token <cv> _SLASH

%token <cv> SEMICOLON EQUALSIGN _ABO _ABC _COLON QUESTMARK AMPERSANT
%token SOMELWS_SEMICOLON _AT
%token <sv> _HOST SCHEME _HNAME _HVALUE
%token <iv> _PORT

%token <cv> SOMELWS_COMMA_SOMELWS SOMELWS_SLASH_SOMELWS
%token <sv> PROTOCOL_NAME PROTOCOL_VERSION TRANSPORT _URLTOKEN

%token PASSERTEDSERVICELWSCOLON
%token PPREFERREDSERVICELWSCOLON
%token XAUTLWSCOLON
%token XCARRIERINFOLWSCOLON
%token XCHGDELAYLWSCOLON
%token PAREAINFOLWSCOLON
%token XFCILWSCOLON
%token XCHGINFOLWSCOLON
%destructor {delete $$;}
event_event
event_event_template1toN
event_list1toN
p_nameaddr
p_urispec
p_urispec_1toN
h_urispec
h_urispec_1toN
vnetspec
vnetspec_1toN
anetspec
anetspec_1toN
conatact_1toN
conatact_value
routebdy1toN
routeadr
Secmechanism
Secmechanism_1toN
host_and_port
%%

SIP_Message:
    Request { 
        delete uriptr;
        uriptr=NULL;
        delete paramptr;
        paramptr=NULL;
        YYACCEPT;
      }
    | Response {
        delete uriptr;
        uriptr=NULL;
        delete paramptr;
        paramptr=NULL;
         YYACCEPT;
      };

Request:
    Request_Line
    gen_req_ent_header_0toN
    LONE_CRLF;
//      message_body_0to1 ;

Request_Line:
    _METHOD _SP SIP_URL _SP SIP_VERSION _CRLF {
        // rqlineptr->method()=Method::str_to_enum($<char1024>1); EPTEBAL
        rqlineptr->method()=Method::str_to_enum($1);
        rqlineptr->sipVersion()=$5;
        rqlineptr->requestUri()= *uriptr;
        delete uriptr;
        uriptr= new SipUrl;
        urlparamcount=headercount=0;
        /*Free($1);*/
        /*Free($5);*/
      }
    | error _CRLF {yyerrok; errorind_loc=255;};

gen_req_ent_header_0toN:
    /* empty */{}
    | gen_req_ent_header_1toN {};
gen_req_ent_header_1toN:
    gen_req_ent_header
    | gen_req_ent_header_1toN gen_req_ent_header ;
gen_req_ent_header:
    general_header {}
    | request_header {}
    | response_header {}
    | entity_header {}
    | error _CRLF { resetptr();  errorind_loc=255; yyerrok;};

/*------------------------[ Entity HDR section ]------------------------*/
entity_header:
    Allow _CRLF { headerptr->allow()().fieldName()=FieldName::ALLOW__E;}
    | Content_Disposition _CRLF
      { headerptr->contentDisposition()().fieldName()=FieldName::CONTENT__DISPOSITION__E;}
    | Content_Encoding _CRLF
      { headerptr->contentEncoding()().fieldName()=FieldName::CONTENT__ENCODING__E;}
    | Content_Language _CRLF
      { headerptr->contentLanguage()().fieldName()=FieldName::CONTENT__LANGUAGE__E;}
    | Content_Length _CRLF
      { headerptr->contentLength()().fieldName()=FieldName::CONTENT__LENGTH__E;}
    | Content_Type _CRLF
      { headerptr->contentType()().fieldName()=FieldName::CONTENT__TYPE__E;}
    | Expires _CRLF { headerptr->expires()().fieldName()=FieldName::EXPIRES__E;};

Allow:
    ALLOWLWSCOLON { headerptr->allow()().methods()=OMIT_VALUE;}
    |ALLOWLWSCOLON allowcontent_1toN {};
allowcontent_1toN:
    LWS_0toN _TOKEN {
        headerptr->allow()().methods()()[allowcount] = $2;
        allowcount++;
        /*Free($2);*/
      }
    | allowcontent_1toN SOMELWSCOMMA LWS_0toN _TOKEN {
        headerptr->allow()().methods()()[allowcount] = $4;
        allowcount++;
        /*Free($4);*/
      };


Content_Disposition:
    CONTENT_DISPOSITIONLWSCOLON LWS_0toN _TOKEN {
        headerptr->contentDisposition()().dispositionType()= $3;
        headerptr->contentDisposition()().dispositionParams()=OMIT_VALUE;
        /*Free($3);*/
      } 
    | CONTENT_DISPOSITIONLWSCOLON LWS_0toN _TOKEN semicolon_dispparam_1toN {
        headerptr->contentDisposition()().dispositionType()= $3;
        headerptr->contentDisposition()().dispositionParams()()=*paramptr;
        delete paramptr;
        paramptr=new GenericParam__List;
        paramcount=0;
//        Free($3);
      };

semicolon_dispparam_1toN:
      SOMELWS_SEMICOLON from_param {}
    | semicolon_dispparam_1toN SOMELWS_SEMICOLON from_param {};

Content_Encoding:
    CONTENT_ENCODINGLWSCOLON conctencoding1_N {} ;

conctencoding1_N:
    LWS_0toN _STOKEN {
       headerptr->contentEncoding()().contentCoding()[contentenccount]=trim($2);
       contentenccount++;
//       Free($2);
     }
    | conctencoding1_N SOMELWSCOMMA LWS_0toN _STOKEN {
       headerptr->contentEncoding()().contentCoding()[contentenccount]=trim($4);
       contentenccount++;
//       Free($4);
     };

Content_Language:
    CONTENT_LANGUAGELWSCOLON clangencoding1_N {};

clangencoding1_N:
    LWS_0toN _STOKEN {
        headerptr->contentLanguage()().languageTag()[contentlangcount]=trim($2);
        contentlangcount++;
//        Free($2);
      }
    | clangencoding1_N SOMELWSCOMMA LWS_0toN _STOKEN {
        headerptr->contentLanguage()().languageTag()[contentlangcount]=trim($4);
        contentlangcount++;
//        Free($4);
      };

Content_Length:
    CONTENT_LENGTHLWSCOLON LWS_0toN SOMEDIGITS
        { headerptr->contentLength()().len() = str2int($3); /*Free($3)*/};

Content_Type:
    CONTENT_TYPELWSCOLON LWS_0toN _TYPEID {
        headerptr->contentType()().mediaType() = trim($3);
//        Free($3);
      };

Expires:
    EXPIRESLWSCOLON LWS_0toN _TOKEN {
        headerptr->expires()().deltaSec() = $3;
//        Free($3);
      };
            
X_AUT:
    XAUTLWSCOLON LWS_0toN _TOKEN {
        headerptr->x__AUT()().x__AUT__Value() = $3;
      };
            
X_Carrier_Info:
    XCARRIERINFOLWSCOLON LWS_0toN _TOKEN {
        headerptr->x__Carrier__Info()().x__Carrier__Info__Value() = $3;
      };
            
X_CHGDelay:
    XCHGDELAYLWSCOLON LWS_0toN _TOKEN {
        headerptr->x__CHGDelay()().x__CHGDelay__Value() = $3;
      };
      
      
X_CHGInfo:      
    XCHGINFOLWSCOLON LWS_0toN _TOKEN {    
        headerptr->x__CHGInfo()().x__ci__kind__data()= $3; 
        headerptr->x__CHGInfo()().cDR__Record()=OMIT_VALUE; 
      }              
    | XCHGINFOLWSCOLON LWS_0toN _TOKEN SOMELWS_SEMICOLON _TOKEN {
        headerptr->x__CHGInfo()().x__ci__kind__data()= $3; 
        headerptr->x__CHGInfo()().cDR__Record()()=$5;        
      };

X_FCI:
    XFCILWSCOLON LWS_0toN _HEXTOKEN {
      headerptr->x__FCI()().x__FCI__Value() = str2hex($3);
    };
    
     
                  
/*------------------------[ Request HD section ]------------------------*/
request_header:
      Alert_Info _CRLF {headerptr->alertInfo()().fieldName()=FieldName::ALERT__INFO__E;}
    | Authorization _CRLF
        {headerptr->authorization()().fieldName()=FieldName::AUTHORIZATION__E;}
    | In_Reply_To _CRLF {headerptr->inReplyTo()().fieldName()=FieldName::IN__REPLY__TO__E;}
    | Max_Forwards _CRLF 
        {headerptr->maxForwards()().fieldName()=FieldName::MAX__FORWARDS__E;}
    | Priority _CRLF {headerptr->priority()().fieldName()=FieldName::PRIORITY__E;}
    | Proxy_Authorization _CRLF 
        {headerptr->proxyAuthorization()().fieldName()=FieldName::PROXY__AUTHORIZATION__E;}
    | Proxy_Require _CRLF
        {headerptr->proxyRequire()().fieldName()=FieldName::PROXY__REQUIRE__E;}
    | Route _CRLF {headerptr->route()().fieldName()=FieldName::ROUTE__E;}
    | Subject _CRLF {headerptr->subject()().fieldName()=FieldName::SUBJECT__E;}
    | ReferTo _CRLF {headerptr->refer__to()().fieldName()=FieldName::REFER__TO__E;}
    | PservedUser _CRLF {headerptr->p__served__user()().fieldName()=FieldName::P__SERVED__USER__E;}
    | PprofileKey _CRLF {headerptr->p__profile__key()().fieldName()=FieldName::P__PROFILE__KEY__E;}
    | Referedby _CRLF {headerptr->referred__by()().fieldName()=FieldName::REFERRED__BY__E;}
    | P_Asserted_Service _CRLF {headerptr->p__asserted__service()().fieldName()=FieldName::P__ASSERTED__SERVICE__E;}
    | P_Preferred_Service _CRLF {headerptr->p__preferred__service()().fieldName()=FieldName::P__PREFERRED__SERVICE__E;};
Referedby:
    REFERREDBYTOLWSCOLON LWS_0toN display_name _ABO addr_spec _ABC 
                    semicolon_fromparam_1toN {
        headerptr->referred__by()().referer__uri().nameAddr().displayName() = $3;
        headerptr->referred__by()().referer__uri().nameAddr().addrSpec()= *uriptr;
        headerptr->referred__by()().refererParams()=*paramptr;

        delete uriptr;
        uriptr= new SipUrl;
        urlparamcount=headercount=0;
        delete paramptr;
        paramptr= new GenericParam__List;
        paramcount=0;

//        Free($3);
      }
    | REFERREDBYTOLWSCOLON LWS_0toN _ABO addr_spec _ABC semicolon_fromparam_1toN {
        headerptr->referred__by()().referer__uri().nameAddr().displayName() 
                    = OMIT_VALUE;
        headerptr->referred__by()().referer__uri().nameAddr().addrSpec()= *uriptr;
        headerptr->referred__by()().refererParams()=*paramptr;
        delete uriptr;
        uriptr= new SipUrl;
        urlparamcount=headercount=0;
        delete paramptr;
        paramptr= new GenericParam__List;
        paramcount=0;
      }
    | REFERREDBYTOLWSCOLON LWS_0toN addr_spec_withnoparam semicolon_fromparam_1toN {
        headerptr->referred__by()().referer__uri().addrSpecUnion()= *uriptr;
        headerptr->referred__by()().refererParams()=*paramptr;
        delete uriptr;
        uriptr= new SipUrl;
        urlparamcount=headercount=0;
        delete paramptr;
        paramptr= new GenericParam__List;
        paramcount=0;
      }
    | REFERREDBYTOLWSCOLON LWS_0toN display_name _ABO addr_spec _ABC {
        headerptr->referred__by()().referer__uri().nameAddr().displayName() = $3;
        headerptr->referred__by()().referer__uri().nameAddr().addrSpec()= *uriptr;
        headerptr->referred__by()().refererParams()=OMIT_VALUE;
        delete uriptr;
        uriptr= new SipUrl;
        urlparamcount=headercount=0;
//        Free($3);
      }
    | REFERREDBYTOLWSCOLON LWS_0toN _ABO addr_spec _ABC {
        headerptr->referred__by()().referer__uri().nameAddr().displayName()
                    = OMIT_VALUE;
        headerptr->referred__by()().referer__uri().nameAddr().addrSpec()= *uriptr;
        headerptr->referred__by()().refererParams()=OMIT_VALUE;
        delete uriptr;
        uriptr= new SipUrl;
        urlparamcount=headercount=0;
      }
    | REFERREDBYTOLWSCOLON LWS_0toN addr_spec_withnoparam {
        headerptr->referred__by()().referer__uri().addrSpecUnion()= *uriptr;
        headerptr->referred__by()().refererParams()=OMIT_VALUE;
        delete uriptr;
        uriptr= new SipUrl;
        urlparamcount=headercount=0;
      };


PprofileKey:
    PPROFILEKEYLWSCOLON LWS_0toN display_name _ABO addr_spec _ABC 
                    semicolon_fromparam_1toN {
        headerptr->p__profile__key()().profile__key().nameAddr().displayName() = $3;
        headerptr->p__profile__key()().profile__key().nameAddr().addrSpec()= *uriptr;
        headerptr->p__profile__key()().profile__key__params()=*paramptr;

        delete uriptr;
        uriptr= new SipUrl;
        urlparamcount=headercount=0;
        delete paramptr;
        paramptr= new GenericParam__List;
        paramcount=0;

//        Free($3);
      }
    | PPROFILEKEYLWSCOLON LWS_0toN _ABO addr_spec _ABC semicolon_fromparam_1toN {
        headerptr->p__profile__key()().profile__key().nameAddr().displayName() 
                    = OMIT_VALUE;
        headerptr->p__profile__key()().profile__key().nameAddr().addrSpec()= *uriptr;
        headerptr->p__profile__key()().profile__key__params()=*paramptr;
        delete uriptr;
        uriptr= new SipUrl;
        urlparamcount=headercount=0;
        delete paramptr;
        paramptr= new GenericParam__List;
        paramcount=0;
      }
    | PPROFILEKEYLWSCOLON LWS_0toN addr_spec_withnoparam semicolon_fromparam_1toN {
        headerptr->p__profile__key()().profile__key().addrSpecUnion()= *uriptr;
        headerptr->p__profile__key()().profile__key__params()=*paramptr;
        delete uriptr;
        uriptr= new SipUrl;
        urlparamcount=headercount=0;
        delete paramptr;
        paramptr= new GenericParam__List;
        paramcount=0;
      }
    | PPROFILEKEYLWSCOLON LWS_0toN display_name _ABO addr_spec _ABC {
        headerptr->p__profile__key()().profile__key().nameAddr().displayName() = $3;
        headerptr->p__profile__key()().profile__key().nameAddr().addrSpec()= *uriptr;
        headerptr->p__profile__key()().profile__key__params()=OMIT_VALUE;
        delete uriptr;
        uriptr= new SipUrl;
        urlparamcount=headercount=0;
//        Free($3);
      }
    | PPROFILEKEYLWSCOLON LWS_0toN _ABO addr_spec _ABC {
        headerptr->p__profile__key()().profile__key().nameAddr().displayName()
                    = OMIT_VALUE;
        headerptr->p__profile__key()().profile__key().nameAddr().addrSpec()= *uriptr;
        headerptr->p__profile__key()().profile__key__params()=OMIT_VALUE;
        delete uriptr;
        uriptr= new SipUrl;
        urlparamcount=headercount=0;
      }
    | PPROFILEKEYLWSCOLON LWS_0toN addr_spec_withnoparam {
        headerptr->p__profile__key()().profile__key().addrSpecUnion()= *uriptr;
        headerptr->p__profile__key()().profile__key__params()=OMIT_VALUE;
        delete uriptr;
        uriptr= new SipUrl;
        urlparamcount=headercount=0;
      };

PservedUser:
    PSERVEDUSERLWSCOLON LWS_0toN display_name _ABO addr_spec _ABC 
                    semicolon_fromparam_1toN {
        headerptr->p__served__user()().served__user().nameAddr().displayName() = $3;
        headerptr->p__served__user()().served__user().nameAddr().addrSpec()= *uriptr;
        headerptr->p__served__user()().served__user__params()=*paramptr;

        delete uriptr;
        uriptr= new SipUrl;
        urlparamcount=headercount=0;
        delete paramptr;
        paramptr= new GenericParam__List;
        paramcount=0;

//        Free($3);
      }
    | PSERVEDUSERLWSCOLON LWS_0toN _ABO addr_spec _ABC semicolon_fromparam_1toN {
        headerptr->p__served__user()().served__user().nameAddr().displayName() 
                    = OMIT_VALUE;
        headerptr->p__served__user()().served__user().nameAddr().addrSpec()= *uriptr;
        headerptr->p__served__user()().served__user__params()=*paramptr;
        delete uriptr;
        uriptr= new SipUrl;
        urlparamcount=headercount=0;
        delete paramptr;
        paramptr= new GenericParam__List;
        paramcount=0;
      }
    | PSERVEDUSERLWSCOLON LWS_0toN addr_spec_withnoparam semicolon_fromparam_1toN {
        headerptr->p__served__user()().served__user().addrSpecUnion()= *uriptr;
        headerptr->p__served__user()().served__user__params()=*paramptr;
        delete uriptr;
        uriptr= new SipUrl;
        urlparamcount=headercount=0;
        delete paramptr;
        paramptr= new GenericParam__List;
        paramcount=0;
      }
    | PSERVEDUSERLWSCOLON LWS_0toN display_name _ABO addr_spec _ABC {
        headerptr->p__served__user()().served__user().nameAddr().displayName() = $3;
        headerptr->p__served__user()().served__user().nameAddr().addrSpec()= *uriptr;
        headerptr->p__served__user()().served__user__params()=OMIT_VALUE;
        delete uriptr;
        uriptr= new SipUrl;
        urlparamcount=headercount=0;
//        Free($3);
      }
    | PSERVEDUSERLWSCOLON LWS_0toN _ABO addr_spec _ABC {
        headerptr->p__served__user()().served__user().nameAddr().displayName()
                    = OMIT_VALUE;
        headerptr->p__served__user()().served__user().nameAddr().addrSpec()= *uriptr;
        headerptr->p__served__user()().served__user__params()=OMIT_VALUE;
        delete uriptr;
        uriptr= new SipUrl;
        urlparamcount=headercount=0;
      }
    | PSERVEDUSERLWSCOLON LWS_0toN addr_spec_withnoparam {
        headerptr->p__served__user()().served__user().addrSpecUnion()= *uriptr;
        headerptr->p__served__user()().served__user__params()=OMIT_VALUE;
        delete uriptr;
        uriptr= new SipUrl;
        urlparamcount=headercount=0;
      };

P_Service_Indication: 
    PSERVICEINDICATIONLWSCOLON LWS_0toN _TOKEN {
        headerptr->p__Service__Indication()().service__indication() = trim($3);
//        Free($3);
      };

P_Service_Notification: 
    PSERVICENOTIFICATIONLWSCOLON LWS_0toN _TOKEN {
        headerptr->p__Service__Notification()().service__notification() = trim($3);
//        Free($3);
      };

ReferTo:
    REFER_TOLWSCOLON LWS_0toN display_name _ABO addr_spec _ABC 
                    semicolon_fromparam_1toN {
        headerptr->refer__to()().addr().nameAddr().displayName() = $3;
        headerptr->refer__to()().addr().nameAddr().addrSpec()= *uriptr;
        headerptr->refer__to()().referToParams()=*paramptr;

        delete uriptr;
        uriptr= new SipUrl;
        urlparamcount=headercount=0;
        delete paramptr;
        paramptr= new GenericParam__List;
        paramcount=0;

//        Free($3);
      }
    | REFER_TOLWSCOLON LWS_0toN _ABO addr_spec _ABC semicolon_fromparam_1toN {
        headerptr->refer__to()().addr().nameAddr().displayName() 
                    = OMIT_VALUE;
        headerptr->refer__to()().addr().nameAddr().addrSpec()= *uriptr;
        headerptr->refer__to()().referToParams()=*paramptr;
        delete uriptr;
        uriptr= new SipUrl;
        urlparamcount=headercount=0;
        delete paramptr;
        paramptr= new GenericParam__List;
        paramcount=0;
      }
    | REFER_TOLWSCOLON LWS_0toN addr_spec_withnoparam semicolon_fromparam_1toN {
        headerptr->refer__to()().addr().addrSpecUnion()= *uriptr;
        headerptr->refer__to()().referToParams()=*paramptr;
        delete uriptr;
        uriptr= new SipUrl;
        urlparamcount=headercount=0;
        delete paramptr;
        paramptr= new GenericParam__List;
        paramcount=0;
      }
    | REFER_TOLWSCOLON LWS_0toN display_name _ABO addr_spec _ABC {
        headerptr->refer__to()().addr().nameAddr().displayName() = $3;
        headerptr->refer__to()().addr().nameAddr().addrSpec()= *uriptr;
        headerptr->refer__to()().referToParams()=OMIT_VALUE;
        delete uriptr;
        uriptr= new SipUrl;
        urlparamcount=headercount=0;
//        Free($3);
      }
    | REFER_TOLWSCOLON LWS_0toN _ABO addr_spec _ABC {
        headerptr->refer__to()().addr().nameAddr().displayName()
                    = OMIT_VALUE;
        headerptr->refer__to()().addr().nameAddr().addrSpec()= *uriptr;
        headerptr->refer__to()().referToParams()=OMIT_VALUE;
        delete uriptr;
        uriptr= new SipUrl;
        urlparamcount=headercount=0;
      }
    | REFER_TOLWSCOLON LWS_0toN addr_spec_withnoparam {
        headerptr->refer__to()().addr().addrSpecUnion()= *uriptr;
        headerptr->refer__to()().referToParams()=OMIT_VALUE;
        delete uriptr;
        uriptr= new SipUrl;
        urlparamcount=headercount=0;
      };

Alert_Info:
    ALERT_INFOLWSCOLON alert_info_body1toN {};

alert_info_body1toN:
    alert_info_body
    | alert_info_body SOMELWSCOMMA alert_info_body1toN;
    
alert_info_body:
    LWS_0toN _ABO _URLTOKEN _ABC {
        headerptr->alertInfo()().alertInfoBody()()[alertinfcount].url()=$3;
        headerptr->alertInfo()().alertInfoBody()()[alertinfcount].
                            genericParams()=OMIT_VALUE;
        alertinfcount++;
//        Free($3);
      }
    | LWS_0toN _ABO _URLTOKEN _ABC semicolon_fromparam_1toN {
        headerptr->alertInfo()().alertInfoBody()()[alertinfcount].url()=$3;
        headerptr->alertInfo()().alertInfoBody()()[alertinfcount].
                            genericParams()()=*paramptr;
        paramcount=0;
        alertinfcount++;
        delete paramptr;
        paramptr=new GenericParam__List;
//        Free($3);
      };

Authorization:    
    AUTHORIZATIONLWSCOLON authbody {};
    
authbody:
    LWS_0toN _DIGEST coma_authparam1_N {
        headerptr->authorization()().body().digestResponse()=*paramptr;
        paramcount=0;
        delete paramptr;
        paramptr=new GenericParam__List;
      }
    | LWS_0toN _TOKEN coma_authparam1_N {
         headerptr->authorization()().body().otherResponse().authScheme()=$2;
         headerptr->authorization()().body().otherResponse().authParams()=
                            *paramptr;
         paramcount=0;
         delete paramptr;
         paramptr=new GenericParam__List;
//         Free($2);
      };

In_Reply_To:
    IN_REPLY_TOLWSCOLON LWS_0toN callid1toN {};

callid1toN:
    _CALLID {
        headerptr->inReplyTo()().callids()[inreplytocount] = $1;
        inreplytocount++;
//        Free($1);
      }
    | callid1toN SOMELWSCOMMA LWS_0toN _CALLID {
        headerptr->inReplyTo()().callids()[inreplytocount] = $4;
        inreplytocount++;
//        Free($4);
      };
    
Max_Forwards:
    MAX_FORWARDSLWSCOLON LWS_0toN SOMEDIGITS
      { headerptr->maxForwards()().forwards()=str2int($3);/*Free($3)*/};

Priority:
    PRIORITYLWSCOLON CONTENT_WITHOUTENDINGCRLF {
        headerptr->priority()().priorityValue() = trim($2);
//        Free($2);
      };

Proxy_Authorization:
    PROXY_AUTHORIZATIONLWSCOLON pauthbody {};

pauthbody:
    LWS_0toN _DIGEST coma_authparam1_N {
        headerptr->proxyAuthorization()().credentials().digestResponse()=
                              *paramptr;
        paramcount=0;
        delete paramptr;
        paramptr=new GenericParam__List;
      }
    | LWS_0toN _TOKEN coma_authparam1_N {
        headerptr->proxyAuthorization()().credentials().otherResponse().
                              authScheme()=$2;
        headerptr->proxyAuthorization()().credentials().otherResponse().
                              authParams()=*paramptr;
        paramcount=0;
        delete paramptr;
        paramptr=new GenericParam__List;
//        Free($2);
      };

Proxy_Require:
    PROXY_REQUIRELWSCOLON optioncontent_1toN {
        if(!proxyreqcount){
          headerptr->proxyRequire()().optionsTags()= *optptr;
          delete optptr;
        }
        proxyreqcount=optioncount;
      };

optioncontent_1toN:
    LWS_0toN _TOKEN {
        (*optptr)[optioncount]=$2;
        optioncount++;
//        Free($2);
      }
    | optioncontent_1toN SOMELWSCOMMA LWS_0toN _TOKEN {
        (*optptr)[optioncount]=$4;
        optioncount++;
//        Free($4);
      };

Route:
    ROUTELWSCOLON routebody1toN {
        if(!routecount){
          headerptr->route()().routeBody()= *routeptr;
          delete routeptr;
        }
        routecount=rcount;
      };

routebody1toN:
    routeadress {}
    | routebody1toN SOMELWSCOMMA routeadress{};

routeadress:
    LWS_0toN display_name _ABO addr_spec _ABC semicolon_toparam_1toN {
        (*routeptr)[rcount].nameAddr().displayName()=$2;
        (*routeptr)[rcount].nameAddr().addrSpec()= *uriptr;
        (*routeptr)[rcount].rrParam()()= *paramptr;
        rcount++;

        delete uriptr;
        uriptr= new SipUrl;
        urlparamcount=headercount=0;
        delete paramptr;
        paramptr= new GenericParam__List;
        paramcount=0;
//        Free($2);
      } 
    | LWS_0toN _ABO addr_spec _ABC semicolon_toparam_1toN {
        (*routeptr)[rcount].nameAddr().displayName()=OMIT_VALUE;
        (*routeptr)[rcount].nameAddr().addrSpec()= *uriptr;
        (*routeptr)[rcount].rrParam()()= *paramptr;
        rcount++;

        delete uriptr;
        uriptr= new SipUrl;
        urlparamcount=headercount=0;
        delete paramptr;
        paramptr= new GenericParam__List;
        paramcount=0;
      }
    | LWS_0toN display_name _ABO addr_spec _ABC {
        (*routeptr)[rcount].nameAddr().displayName()=$2;
        (*routeptr)[rcount].nameAddr().addrSpec()= *uriptr;
        (*routeptr)[rcount].rrParam()= OMIT_VALUE;
        rcount++;

        delete uriptr;
        uriptr= new SipUrl;
        urlparamcount=headercount=0;
//        Free($2);
      }
    | LWS_0toN _ABO addr_spec _ABC {
        (*routeptr)[rcount].nameAddr().displayName()=OMIT_VALUE;
        (*routeptr)[rcount].nameAddr().addrSpec()= *uriptr;
        (*routeptr)[rcount].rrParam()= OMIT_VALUE;
        rcount++;

        delete uriptr;
        uriptr= new SipUrl;
        urlparamcount=headercount=0;
      };

Subject:
    SUBJECTLWSCOLON CONTENT_WITHOUTENDINGCRLF {
        headerptr->subject()().summary()=trim($2);
//        Free($2);
      };

/*-------------------------[ Response Section ]-------------------------*/

Response:
    Status_Line gen_res_ent_header_0toN LONE_CRLF;
//          message_body_0to1

Status_Line:
    SIP_SPHT_VERSION _SP EXTENSION_CODE _SP REASON_PHRASE _CRLF {

/*	EPTEBAL */
//	int offset = $<sip_sv>1.offset;
//	int len = $<sip_sv>1.length;
//      stlineptr->sipVersion() = CHARSTRING(len, stream_buffer+offset);
//      stlineptr->sipVersion() = stream_buffer+offset;

        stlineptr->sipVersion() = $1; /* EPTEBAL */
        stlineptr->statusCode() = $3;
        stlineptr->reasonPhrase() = $5;
        /*Free($1);*/
//	Free($5);
      }
    | error REASON_PHRASE _CRLF { yyerrok; errorind_loc=255;};

gen_res_ent_header_0toN:
    /* empty */ {}
    | gen_res_ent_header_1toN {};
gen_res_ent_header_1toN:
    gen_res_ent_header
    | gen_res_ent_header_1toN gen_res_ent_header ;
gen_res_ent_header:
    general_header    {}
    | request_header  {}
    | response_header {}
    | entity_header   {}
    | error _CRLF     { resetptr(); yyerrok; errorind_loc=255;} ;

response_header:
    Error_Info _CRLF {headerptr->errorInfo()().fieldName()=FieldName::ERROR__INFO__E;}
    | Proxy_Authenticate _CRLF 
       {headerptr->proxyAuthenticate()().fieldName()=FieldName::PROXY__AUTHENTICATE__E;}
    | Retry_After _CRLF {headerptr->retryAfter()().fieldName()=FieldName::RETRY__AFTER__E;}
    | Server _CRLF      {headerptr->server()().fieldName()=FieldName::SERVER__E;}
    | Unsupported _CRLF {headerptr->unsupported()().fieldName()=FieldName::UNSUPPORTED__E;}
    | Auth_info _CRLF   
       {headerptr->authenticationInfo()().fieldName()=FieldName::AUTHENTICATION__INFO__E;}
    | Warning _CRLF     {headerptr->warning()().fieldName()=FieldName::WARNING__E;}
    | WWW_Authenticate _CRLF
       {headerptr->wwwAuthenticate()().fieldName()=FieldName::WWW__AUTHENTICATE__E;};

Auth_info:
    AUTHINFOLWSCOLON coma_authparam1_N {
        headerptr->authenticationInfo()().ainfo()=*paramptr;
        delete paramptr;
        paramptr= new GenericParam__List;
        paramcount=0;
      };

P_Asserted_Service:
    PASSERTEDSERVICELWSCOLON service1toN{ 
      if(headerptr->p__asserted__service().ispresent()){
        int a=headerptr->p__asserted__service()().p__as().size_of();
        for(int b=0;b<$2->size_of();b++){
          headerptr->p__asserted__service()().p__as()[a]=(*$2)[b];
          a++;
          }
      }
      else {
        headerptr->p__asserted__service()().p__as()=*$2;
      }
      delete $2;    
      };

P_Preferred_Service:
    PPREFERREDSERVICELWSCOLON service1toN{ 
      if(headerptr->p__preferred__service().ispresent()){
        int a=headerptr->p__preferred__service()().p__ps().size_of();
        for(int b=0;b<$2->size_of();b++){
          headerptr->p__preferred__service()().p__ps()[a]=(*$2)[b];
          a++;
          }
      }
      else {
        headerptr->p__preferred__service()().p__ps()=*$2;
      }
      delete $2;    
      };

service1toN:
    LWS_0toN _TOKEN{
        $$ = new Service__ID__List;
        (*$$)[0] = $2;
      //  delete $2;
      }
    | service1toN SOMELWSCOMMA LWS_0toN _TOKEN{
        int a=$1->size_of();
        $$=$1;
        (*$$)[a] = $4;
     //   delete $4;
      };

coma_authparam1_N:
    from_param {}
    | from_param SOMELWSCOMMA coma_authparam1_N {};

Error_Info:
    ERROR_INFOLWSCOLON error_info_body1toN {};

error_info_body1toN:
    error_info_body
    |error_info_body SOMELWSCOMMA error_info_body1toN;
    
error_info_body:
    LWS_0toN _ABO _URLTOKEN _ABC {
        headerptr->errorInfo()().errorInfo()()[errorinfocount].uri()=$3;
        headerptr->errorInfo()().errorInfo()()[errorinfocount].genericParams()
                   =OMIT_VALUE;
        errorinfocount++;
//        Free($3);
      }
    |LWS_0toN _ABO _URLTOKEN _ABC semicolon_fromparam_1toN {
        headerptr->errorInfo()().errorInfo()()[errorinfocount].uri()=$3;
        headerptr->errorInfo()().errorInfo()()[errorinfocount].
                  genericParams()()=*paramptr;
        paramcount=0;
        errorinfocount++;
        delete paramptr;
        paramptr=new GenericParam__List;
//        Free($3);
      };

Retry_After:
    RETRY_AFTERLWSCOLON LWS_0toN _TOKEN {
        headerptr->retryAfter()().deltaSec() = $3;
        headerptr->retryAfter()().comment() = OMIT_VALUE;
        headerptr->retryAfter()().retryParams() = OMIT_VALUE;
//        Free($3);
      }
    | RETRY_AFTERLWSCOLON LWS_0toN _TOKEN LWS_0toN SPARENT comment EPARENT {
        headerptr->retryAfter()().deltaSec() = $3;
        headerptr->retryAfter()().comment()() = comment_buf+1;
        headerptr->retryAfter()().retryParams() = OMIT_VALUE;
//        Free($3);
        comment_buf[1]='\0';
      }
    | RETRY_AFTERLWSCOLON LWS_0toN _TOKEN LWS_0toN 
            SPARENT comment EPARENT semicolon_fromparam_1toN {
        headerptr->retryAfter()().deltaSec() = $3;
        headerptr->retryAfter()().comment()() = comment_buf+1;
        headerptr->retryAfter()().retryParams()() = *paramptr;
//        Free($3);
        delete paramptr;
        paramptr=new GenericParam__List;
        paramcount=0;
        comment_buf[1]='\0';
      }
    | RETRY_AFTERLWSCOLON LWS_0toN _TOKEN semicolon_fromparam_1toN {
        headerptr->retryAfter()().deltaSec() = $3;
        headerptr->retryAfter()().comment() = OMIT_VALUE;
        headerptr->retryAfter()().retryParams()() = *paramptr;
//        Free($3);
        delete paramptr;
        paramptr=new GenericParam__List;
        paramcount=0;
      };
                
comment:
    _COMMENT {
      strcat(comment_buf+1,$1);
//      Free($1);
    }
    |comment _COMMENT {
      strcat(comment_buf+1,$2);
//      Free($2);
    };

Server:
    SERVERLWSCOLON LWS_0toN product_comment_s1toN {};
product_comment_s1toN:
    product_comment {
        headerptr->server()().serverBody()[servercount]= $1;
        servercount++;
        Free($1);
      }
    |product_comment_s1toN SOMELWS product_comment {
        headerptr->server()().serverBody()[servercount]= $3;
        servercount++;
        Free($3);
      };

product_comment:
    SPARENT comment EPARENT {
        size_t comment_buflen = strlen(comment_buf+1);
        char *atm=(char *)Malloc(comment_buflen+3);
        atm[0]='(';
        strcpy(atm+1,comment_buf+1);
        atm[comment_buflen+1] = ')';
        atm[comment_buflen+2] = '\0';
        $$=atm;
        comment_buf[1]='\0';
      }
    | _TOKEN {
        char *atm=(char *)Malloc(strlen($1)+1);
        strcpy(atm,$1);
        $$=atm;
    };

Unsupported:
    UNSUPPORTEDLWSCOLON optioncontent_1toN {
        if(!unsuppcount){
            headerptr->unsupported()().optionsTags()= *optptr;
            delete optptr;
        }
        unsuppcount=optioncount;
      };

Warning:
    WARNINGLWSCOLON LWS_0toN warncontent_1toN {} 
    |WARNINGLWSCOLON _SP warncontent_1toN {};

warncontent_1toN:
    warncontent    {}
    | warncontent_1toN SOMELWSCOMMA _SP warncontent        {}
    | warncontent_1toN SOMELWSCOMMA LWS_0toN warncontent    {};
    
warncontent:
    _PORT _SP host_port _SP QUOTED_STRING {
        headerptr->warning()().warningValue()[warncount].warnCode()=$1;
        $5[strlen($5)-1]='\0';
        headerptr->warning()().warningValue()[warncount].WarnText()=$5+1;

        warncount++;
//        Free($5);
      };

host_port:
     _TOKEN _COLON _PORT{
        headerptr->warning()().warningValue()[warncount].warnAgent().
                hostPort().host()=trimOnIPv6($1);
        headerptr->warning()().warningValue()[warncount].warnAgent().
                hostPort().portField() = $3;
//        Free($1);
      }
    | _TOKEN {
        if(strchr($1,'.') || strchr($1,':')){
          headerptr->warning()().warningValue()[warncount].warnAgent().
                hostPort().host()=trimOnIPv6($1);
          headerptr->warning()().warningValue()[warncount].warnAgent().
                hostPort().portField() = OMIT_VALUE;
        }
        else{
          headerptr->warning()().warningValue()[warncount].warnAgent().
                pseudonym()=$1;
        }
//        Free($1);
      };
    | _HOST _COLON _PORT{
        headerptr->warning()().warningValue()[warncount].warnAgent().
                hostPort().host()=trimOnIPv6($1);
        headerptr->warning()().warningValue()[warncount].warnAgent().
                hostPort().portField() = $3;
//        Free($1);
      }
    | _HOST {
        if(strchr($1,'.') || strchr($1,':')){
          headerptr->warning()().warningValue()[warncount].warnAgent().
                hostPort().host()=trimOnIPv6($1);
          headerptr->warning()().warningValue()[warncount].warnAgent().
                hostPort().portField() = OMIT_VALUE;
        }
        else{
          headerptr->warning()().warningValue()[warncount].warnAgent().
                pseudonym()=$1;
        }
//        Free($1);
      };

/*------------------[ End of Response Header section ]------------------*/

general_header:  
    Accept _CRLF            {headerptr->accept()().fieldName()=FieldName::ACCEPT__E;}
    | Accept_Encoding _CRLF 
        {headerptr->acceptEncoding()().fieldName()=FieldName::ACCEPT__ENCODING__E;}
    | Accept_Language _CRLF 
        {headerptr->acceptLanguage()().fieldName()=FieldName::ACCEPT__LANGUAGE__E;}
    | Call_ID _CRLF         {headerptr->callId()().fieldName()=FieldName::CALL__ID__E;}
    | Call_Info _CRLF       {headerptr->callInfo()().fieldName()=FieldName::CALL__INFO__E;}
    | Contact _CRLF         {headerptr->contact()().fieldName()=FieldName::CONTACT__E;}
    | Cseq _CRLF            {headerptr->cSeq()().fieldName()=FieldName:: CSEQ__E;}
    | Date _CRLF            {headerptr->date()().fieldName()=FieldName::DATE__E;}      
    | MinExpires _CRLF  {headerptr->minExpires()().fieldName()=FieldName::MIN__EXPIRES__E;}
    | Eventheader _CRLF    {headerptr->event()().fieldName()=FieldName::EVENT__E;}
    | AllowEventheader _CRLF    {headerptr->allow__events()().fieldName()=FieldName::ALLOW__EVENTS__E;}
    | AcceptResPrioheader _CRLF    {headerptr->acceptResourcePriority()().fieldName()=FieldName::ACCEPT__RESOURCE__PRIORITY__E;}
    | ResPrioheader _CRLF    {headerptr->resourcePriority()().fieldName()=FieldName::RESOURCE__PRIORITY__E;}
    | From _CRLF            {headerptr->fromField()().fieldName()=FieldName::FROM__E;errorind_loc&=254;}  // 1111 1110
    | HistoryInfo_header _CRLF 
        {headerptr->historyInfo()().fieldName()=FieldName::HISTORY__INFO__E;}
    | MIME_Version _CRLF
        {headerptr->mimeVersion()().fieldName()=FieldName::MIME__VERSION__E;}
    | Organization _CRLF
        {headerptr->organization()().fieldName()=FieldName::ORGANIZATION__E;}
    | Privacyheader _CRLF   {headerptr->privacy()().fieldName()=FieldName::PRIVACY__E;}
    | P_assoc_uri_header _CRLF 
        {headerptr->p__associated__uri()().fieldName()=FieldName::P__ASSOCIATED__URI;}
    | P_diversion_header _CRLF 
        {headerptr->diversion()().fieldName()=FieldName::DIVERSION__E;}
    | P_called_party_id_header _CRLF 
        {headerptr->p__called__party__id()().fieldName()=FieldName::P__CALLED__PARTY__ID;}
    | P_Asserted_header _CRLF 
        {headerptr->passertedID()().fieldName()=FieldName::P__ASSERTED__ID__E;}
    | p_visited_net_id_header _CRLF 
        {headerptr->p__visited__network__id()().fieldName()=FieldName::P__VISITED__NETWORK__ID;}
    | P_Preferred_header _CRLF 
        {headerptr->ppreferredID()().fieldName()=FieldName::P__PREFERRED__ID__E;}
    | p_access_net_header _CRLF
        {headerptr->p__access__network__info()().fieldName()=FieldName::P__ACCESS__NETWORK__INFO;}
    | p_charge_addr _CRLF 
        {headerptr->p__charging__function__address()().fieldName()=FieldName::P__CHARGING__FUNCTION__ADDRESS;}
    | p_charge_vector _CRLF 
        {headerptr->p__charging__vector()().fieldName()=FieldName::P__CHARGING__VECTOR;}
    | Rackheader _CRLF      {headerptr->rack()().fieldName()=FieldName::RACK__E;}
    | Reasonheader _CRLF    {headerptr->reason()().fieldName()=FieldName::REASON__E;}
    | Rseqheader _CRLF      {headerptr->rseq()().fieldName()=FieldName::RSEQ__E;}
    | Record_Route _CRLF
        {headerptr->recordRoute()().fieldName()=FieldName::RECORD__ROUTE__E;}
    | ReplyTo _CRLF         {headerptr->replyTo()().fieldName()=FieldName::REPLY__TO__E;}
    | Require _CRLF         {headerptr->require()().fieldName()=FieldName::REQUIRE__E;}
    | Supported _CRLF       {headerptr->supported()().fieldName()=FieldName::SUPPORTED__E;}
    | min_se_header _CRLF       {headerptr->min__SE()().fieldName()=FieldName::MIN__SE__E;}
    | session_exp_header _CRLF       {headerptr->session__expires()().fieldName()=FieldName::SESSION__EXPIRES__E;}
    | session_id_header _CRLF       {headerptr->session__id()().fieldName()=FieldName::SESSION__ID__E;}
    | Subscription_stateheader _CRLF   {headerptr->subscription__state()().fieldName()=FieldName::SUBSCRIPTION__STATE__E;}
    | Timestamp _CRLF       {headerptr->timestamp()().fieldName()=FieldName::TIMESTAMP__E;}
    | Toheader _CRLF        {headerptr->toField()().fieldName()=FieldName::TO__E;errorind_loc&=253;} // 1111 1101
    | User_Agent _CRLF  {headerptr->userAgent()().fieldName()=FieldName::USER__AGENT__E;}
    | Via _CRLF             {headerptr->via()().fieldName()=FieldName::VIA__E;errorind_loc&=251;}  // 1111 1011
    | Accept_cont _CRLF     {headerptr->accept__contact()().fieldName()=FieldName::ACCEPT__CONTACT__E;}
    | Reject_cont _CRLF     {headerptr->reject__contact()().fieldName()=FieldName::REJECT__CONTACT__E;}
    | Req_disp_cont _CRLF   {headerptr->request__disp()().fieldName()=FieldName::REQUEST__DISP__E;}
    | P_media_auth _CRLF    {headerptr->p__media__auth()().fieldName()=FieldName::P__MEDIA__AUTH__E;}
    | Pathheader _CRLF      {headerptr->path()().fieldName()=FieldName::PATH__E;}
    | Sec_client _CRLF      {headerptr->security__client()().fieldName()=FieldName::SECURITY__CLIENT__E;}
    | Sec_server _CRLF      {headerptr->security__server()().fieldName()=FieldName::SECURITY__SERVER__E;}
    | Sec_verify _CRLF      {headerptr->security__verify()().fieldName()=FieldName::SECURITY__VERIFY__E;}
    | P_trace_pty _CRLF     {headerptr->p__DCS__trace__pty__id()().fieldName()=FieldName::P__DCS__TRACE__PTY__ID__E;}
    | P_osps _CRLF          {headerptr->p__DCS__OSPS()().fieldName()=FieldName::P__DCS__OSPS__E;}
    | P_early_media _CRLF          {headerptr->p__Early__Media()().fieldName()=FieldName::P__EARLY__MEDIA__E;}
    | P_billing_info _CRLF          {headerptr->p__DCS__billing__info()().fieldName()=FieldName::P__DCS__BILLING__INFO__E;}
    | P_laes _CRLF          {headerptr->p__DCS__LAES()().fieldName()=FieldName::P__DCS__LAES__E;}
    | P_dcsredir _CRLF          {headerptr->p__DCS__redirect()().fieldName()=FieldName::P__DCS__REDIRECT__E;}
    | P_userdbase _CRLF          {headerptr->p__user__database()().fieldName()=FieldName::P__USER__DATABASE__E;}
    | service_route_header _CRLF          {headerptr->service__route()().fieldName()=FieldName::SERVICE__ROUTE__E;}
    | replacesheader _CRLF          {headerptr->replaces()().fieldName()=FieldName::REPLACES__E;}
    | SIPetag _CRLF          {headerptr->sip__ETag()().fieldName()=FieldName::SIP__ETAG__E;}
    | SIPifmatch _CRLF          {headerptr->sip__If__Match()().fieldName()=FieldName::SIP__IF__MATCH__E;}
    | joinheader _CRLF          {headerptr->join()().fieldName()=FieldName::JOIN__E;}
    | P_Service_Indication _CRLF  {headerptr->p__Service__Indication()().fieldName()=FieldName::P__SERVICE__INDICATION__E;}    
    | P_Service_Notification _CRLF  {headerptr->p__Service__Notification()().fieldName()=FieldName::P__SERVICE__NOTIFICATION__E;}     
    | answer_mode_header _CRLF 
        {headerptr->answer__mode()().fieldName()=FieldName::ANSWER__MODE__E;}
    | priv_answer_mode_header _CRLF 
        {headerptr->priv__answer__mode()().fieldName()=FieldName::PRIV__ANSWER__MODE__E;}
    | alert_mode_header _CRLF 
        {headerptr->alert__mode()().fieldName()=FieldName::ALERT__MODE__E;}
    | refer_sub_header _CRLF 
        {headerptr->refer__sub()().fieldName()=FieldName::REFER__SUB__E;}
    | p_alerting_mode_header _CRLF 
        {headerptr->p__alerting__mode()().fieldName()=FieldName::P__ALERTING__MODE__E;}
    | p_answer_sate_header _CRLF 
        {headerptr->p__answer__state()().fieldName()=FieldName::P__ANSWER__STATE__E;}
    | geolocation_header _CRLF {headerptr->geolocation()().fieldName()=FieldName::GEOLOCATION__E;}
    | georouting_header _CRLF {headerptr->geolocation__routing()().fieldName()=FieldName::GEOLOCATION__ROUTING__E;}
    | geolocerr_header _CRLF {headerptr->geolocation__error()().fieldName()=FieldName::GEOLOCATION__ERROR__E;}
    | target_dialogheader _CRLF {headerptr->target__dialog()().fieldName()=FieldName::TARGET__DIALOG__E;}   
    | featureCapsHeader _CRLF {headerptr->feature__caps()().fieldName()=FieldName::FEATURE__CAPS__E;} 
    | info_package_header _CRLF {headerptr->info__Package()().fieldName()=FieldName::INFO__PACKAGE__E;}   
    | recv_info_header _CRLF {headerptr->recv__Info()().fieldName()=FieldName::RECV__INFO__E;}  
    | X_AUT _CRLF {headerptr->x__AUT()().fieldName()=FieldName::X__AUT__E;}      
    | X_Carrier_Info _CRLF {headerptr->x__Carrier__Info()().fieldName()=FieldName::X__CARRIER__INFO__E;}     
    | X_CHGDelay _CRLF {headerptr->x__CHGDelay()().fieldName()=FieldName::X__CHGDELAY__E;} 
    | p_area_info _CRLF {headerptr->p__Area__Info()().fieldName()=FieldName::P__AREA__INFO__E;}  
    | X_CHGInfo _CRLF {headerptr->x__CHGInfo()().fieldName()=FieldName::X__CHGINFO__E;}
    | X_FCI _CRLF     {headerptr->x__FCI()().fieldName()=FieldName::X__FCI__E;}               
    | Other _CRLF;



recv_info_header:
    RECVINFOLWSCOLON {
        headerptr->recv__Info()().info__Package__List()=OMIT_VALUE;
      }
    |RECVINFOLWSCOLON info_package_range1toN {} ;

info_package_range1toN:
    info_package_type   
   |info_package_type SOMELWSCOMMA info_package_range1toN;

info_package_type:
    LWS_0toN _TOKEN {
        headerptr->recv__Info()().info__Package__List()()[recvinfocount].
                                  info__package__name()=$2;	
	headerptr->recv__Info()().info__Package__List()()[recvinfocount].
                                  info__package__params()=OMIT_VALUE;
				  
	recvinfocount++;
//        Free($2);				  
   }
   | LWS_0toN _TOKEN semicolon_fromparam_1toN {
        headerptr->recv__Info()().info__Package__List()()[recvinfocount].
                                  info__package__name()=$2;	
        headerptr->recv__Info()().info__Package__List()()[recvinfocount].
                                  info__package__params()=*paramptr;
        paramcount=0;
        recvinfocount++;
        delete paramptr;
        paramptr=new GenericParam__List;
//        Free($2);
      };
      
info_package_header:
    INFOPACKAGELWSCOLON LWS_0toN _TOKEN {
        headerptr->info__Package()().info__Package__Type().info__package__name() = $3;
        headerptr->info__Package()().info__Package__Type().info__package__params() = OMIT_VALUE;
//        Free($3);
      }
    | INFOPACKAGELWSCOLON LWS_0toN _TOKEN semicolon_fromparam_1toN {
        headerptr->info__Package()().info__Package__Type().info__package__name() = $3;
        headerptr->info__Package()().info__Package__Type().info__package__params() = *paramptr;
//        Free($3);
        delete paramptr;
        paramptr=new GenericParam__List;
        paramcount=0;
      };
    
target_dialogheader:
   TARGETDIALOGLWSCOLON LWS_0toN _CALLID{
      headerptr->target__dialog()().callid() =$3;
      headerptr->target__dialog()().td__params()= OMIT_VALUE;
//      Free($3);
    }
   | TARGETDIALOGLWSCOLON LWS_0toN _CALLID semicolon_fromparam_1toN{
      headerptr->target__dialog()().callid() =$3;
      headerptr->target__dialog()().td__params()= *paramptr;
      paramcount=0;
      delete paramptr;
      paramptr=new GenericParam__List;

//      Free($3);
    };
    
    
featureCapsHeader:
   FEATURECAPSLWSCOLON fc_values1toN {}; 
     
fc_values1toN:
    fc_value
    |fc_value SOMELWSCOMMA fc_values1toN;
  
fc_value:
    LWS_0toN _TOKEN {
        headerptr->feature__caps()().fc__values()[featureCapscount].fc__string()=$2;
        headerptr->feature__caps()().fc__values()[featureCapscount].feature__param()=
                                                                     OMIT_VALUE;
        featureCapscount++;
//        Free($3);
      }
    | LWS_0toN _TOKEN semicolon_fromparam_1toN {
        headerptr->feature__caps()().fc__values()[featureCapscount].fc__string()=$2;
        headerptr->feature__caps()().fc__values()[featureCapscount].feature__param()=
                                                                      *paramptr;
        paramcount=0;
        featureCapscount++;
        delete paramptr;
        paramptr=new GenericParam__List;
//        Free($3);
      };

geolocerr_header:
    GEOLOCERRORLWSCOLON LWS_0toN SOMEDIGITS{
      headerptr->geolocation__error()().location__error__code()=str2int($3);
      headerptr->geolocation__error()().location__error__params()=OMIT_VALUE;
    }
    | GEOLOCERRORLWSCOLON LWS_0toN SOMEDIGITS semicolon_fromparam_1toN{
      headerptr->geolocation__error()().location__error__code()=str2int($3);
      headerptr->geolocation__error()().location__error__params()=*paramptr;
        delete paramptr;
        paramptr= new GenericParam__List;
        paramcount=0;
    }

georouting_header:
   GEOROUTINGLWSCOLON LWS_0toN _TOKEN {
     headerptr->geolocation__routing()().georouting__param()=$3;
     headerptr->geolocation__routing()().georouting__value()=OMIT_VALUE;
   }
   | GEOROUTINGLWSCOLON LWS_0toN _TOKEN LWS_0toN equals_token_host_qtdstr{
     headerptr->geolocation__routing()().georouting__param()=$3;
     headerptr->geolocation__routing()().georouting__value()=$5;
   };


geolocation_header:
   GEOLOCATIONLWSCOLON geoloaction_list1toN {
      if(headerptr->geolocation().ispresent()){
        int a=headerptr->geolocation()().location__values().size_of();
        for(int b=0;b<$2->size_of();b++){
          headerptr->geolocation()().location__values()[a]=(*$2)[b];
          a++;
          }
      }
      else {
        headerptr->geolocation()().location__values()=*$2;
      }
      delete $2;
    };

geoloaction_list1toN:
   geoloaction_value {
        $$= new Location__value__list;
        (*$$)[0]=*$1;
        delete $1;
      }

   | geoloaction_list1toN SOMELWSCOMMA geoloaction_value{
        int a=$1->size_of();
        $$=$1;
        (*$$)[a] = *$3;
        delete $3;
      };
      
geoloaction_value:
   LWS_0toN _ABO addr_spec _ABC {
     $$ = new Location__value;
     $$->location__uri() = *uriptr;
     $$->location__params() = OMIT_VALUE;
     
        delete uriptr;
        uriptr= new SipUrl;
        urlparamcount=headercount=0;
   }
   | LWS_0toN _ABO addr_spec _ABC semicolon_fromparam_1toN {
     $$ = new Location__value;
     $$->location__uri() = *uriptr;
     $$->location__params() = *paramptr;
     
        delete uriptr;
        uriptr= new SipUrl;
        urlparamcount=headercount=0;
        delete paramptr;
        paramptr= new GenericParam__List;
        paramcount=0;
   }



AcceptResPrioheader:
   ACCEPTRESPRIOLWSCOLON rvalue_list1toN{
      if(headerptr->acceptResourcePriority().ispresent()){
        int a=headerptr->acceptResourcePriority()().rvalues()().size_of();
        for(int b=0;b<$2->size_of();b++){
          headerptr->acceptResourcePriority()().rvalues()()[a]=(*$2)[b];
          a++;
          }
      }
      else {
        headerptr->acceptResourcePriority()().rvalues()()=*$2;
      }
      delete $2;
   };

ResPrioheader:
   RESPRIOLWSCOLON rvalue_list1toN{
      if(headerptr->resourcePriority().ispresent()){
        int a=headerptr->resourcePriority()().rvalues()().size_of();
        for(int b=0;b<$2->size_of();b++){
          headerptr->resourcePriority()().rvalues()()[a]=(*$2)[b];
          a++;
          }
      }
      else {
        headerptr->resourcePriority()().rvalues()()=*$2;
      }
      delete $2;
   };

rvalue_list1toN:
    LWS_0toN rvalue_value{
        $$ = new Rvalue__List;
        (*$$)[0] = *$2;
        delete $2;
      }
    | rvalue_list1toN SOMELWSCOMMA LWS_0toN rvalue_value{
        int a=$1->size_of();
        $$=$1;
        (*$$)[a] = *$4;
        delete $4;
      };

rvalue_value:
      _TOKEN_NO_DOT _DOT _TOKEN_NO_DOT{
      $$ = new Rvalue;
      $$->namespace_()= $1;
      $$->r__priority()=$3;
//      delete $3;
//      Free($1);
      };


P_early_media: 
    PEARLYMEDIALWSCOLON /* empty */ {
      if(!headerptr->p__Early__Media().ispresent()){
        headerptr->p__Early__Media()().em__param__list()= OMIT_VALUE;
      }
    }
    | PEARLYMEDIALWSCOLON embody1toN{
      if(headerptr->p__Early__Media().ispresent()){
        int a=headerptr->p__Early__Media()().em__param__list().ispresent()?
                 headerptr->p__Early__Media()().em__param__list()().size_of():0;
        for(int b=0;b<$2->size_of();b++){
          headerptr->p__Early__Media()().em__param__list()()[a]=(*$2)[b];
          a++;
          }
      }
      else {
        headerptr->p__Early__Media()().em__param__list()()=*$2;
      }
      delete $2;
   };

embody1toN:
    LWS_0toN _TOKEN {
        $$= new Em__param__List;
        (*$$)[0]=$2;
//        Free($2);
      }
    | embody1toN SOMELWSCOMMA LWS_0toN _TOKEN{
        int a=$1->size_of();
        $$=$1;
        (*$$)[a] = $4;
//        Free($4);
      };

joinheader:
    JOINLWSCOLON LWS_0toN _CALLID {
        headerptr->join()().callid()=$3;
        headerptr->join()().joinParams()=OMIT_VALUE;
//        Free($3);
      }
    | JOINLWSCOLON LWS_0toN _CALLID semicolon_fromparam_1toN{
        headerptr->join()().callid()=$3;
        headerptr->join()().joinParams()=*paramptr;
        delete paramptr;
        paramptr= new GenericParam__List;
        paramcount=0;
//        Free($3);
      };

SIPetag:
    ETAGLWSCOLON LWS_0toN _TOKEN {
        headerptr->sip__ETag()().entity__tag()=$3;
//        Free($3);
      };

SIPifmatch:
    IFMATCHLWSCOLON LWS_0toN _TOKEN {
        headerptr->sip__If__Match()().entity__tag()=$3;
//        Free($3);
      };

replacesheader:
    REPLACESLWSCOLON LWS_0toN _CALLID {
        headerptr->replaces()().callid()=$3;
        headerptr->replaces()().replacesParams()=OMIT_VALUE;
//        Free($3);
      }
    | REPLACESLWSCOLON LWS_0toN _CALLID semicolon_fromparam_1toN{
        headerptr->replaces()().callid()=$3;
        headerptr->replaces()().replacesParams()=*paramptr;
        delete paramptr;
        paramptr= new GenericParam__List;
        paramcount=0;
//        Free($3);
      };

service_route_header: 
    SERVICEROUTELWSCOLON routebdy1toN{
      if(headerptr->service__route().ispresent()){
        int a=headerptr->service__route()().routeBody().size_of();
        for(int b=0;b<$2->size_of();b++){
          headerptr->service__route()().routeBody()[a]=(*$2)[b];
          a++;
          }
      }
      else {
        headerptr->service__route()().routeBody()=*$2;
      }
      delete $2;
   };

P_userdbase:
    PUSERDBASELWSCOLON LWS_0toN _ABO addr_spec _ABC {
        headerptr->p__user__database()().database()=*uriptr;
        headerptr->p__user__database()().params()=OMIT_VALUE;
        delete uriptr;
        uriptr= new SipUrl;
        urlparamcount=headercount=0;

      }
    | PUSERDBASELWSCOLON LWS_0toN _ABO addr_spec _ABC semicolon_fromparam_1toN {
        headerptr->p__user__database()().database()=*uriptr;
          headerptr->p__user__database()().params()=*paramptr;
          delete paramptr;
          paramptr= new GenericParam__List;
          paramcount=0;
        delete uriptr;
        uriptr= new SipUrl;
        urlparamcount=headercount=0;
      };

P_dcsredir:
    PDCSREDIRLWSCOLON addr_spec _ABC {
        headerptr->p__DCS__redirect()().caller__ID()=*uriptr;
        headerptr->p__DCS__redirect()().redir__params()=OMIT_VALUE;
        delete uriptr;
        uriptr= new SipUrl;
        urlparamcount=headercount=0;

      }
    | PDCSREDIRLWSCOLON addr_spec _ABC semicolon_fromparam_1toN {
        headerptr->p__DCS__redirect()().caller__ID()=*uriptr;
          headerptr->p__DCS__redirect()().redir__params()=*paramptr;
          delete paramptr;
          paramptr= new GenericParam__List;
          paramcount=0;
        delete uriptr;
        uriptr= new SipUrl;
        urlparamcount=headercount=0;
      };

P_laes:
    PLAESLWSCOLON LWS_0toN host_and_port {
        headerptr->p__DCS__LAES()().laes__sig()=*$3;
        headerptr->p__DCS__LAES()().laes__params()=OMIT_VALUE;
        delete $3;
      }
    | PLAESLWSCOLON LWS_0toN host_and_port SOMELWS_SEMICOLON laes_params {
        headerptr->p__DCS__LAES()().laes__sig()=*$3;
          headerptr->p__DCS__LAES()().laes__params()=*paramptr;
          delete paramptr;
          paramptr= new GenericParam__List;
          paramcount=0;
        delete $3;
      };

laes_params:
    laes_param
    | laes_param SOMELWS_SEMICOLON laes_params;
    

laes_param:
    laes_content 
    | from_param
    ;

laes_content:
    LWS_0toN _LAES_CONTENT LWS_0toN host_and_port {
        (*paramptr)[paramcount].id()="content";
        if($4->portField().ispresent()){
          (*paramptr)[paramcount].paramValue()=$4->host()() + ":" + int2str($4->portField()());
        } else {
          (*paramptr)[paramcount].paramValue()=$4->host()();
        }
        paramcount++;
        delete $4;
    };

host_and_port:
     _HOST _COLON _PORT{
        $$= new HostPort;
        $$->host()=$1;
        $$->portField() = $3;
//        Free($1);
      }
    | _HOST {
        $$= new HostPort;
        $$->host()=$1;
        $$->portField() = OMIT_VALUE;
//        Free($1);
      };

P_billing_info:
    PBILLINGINFOLWSCOLON LWS_0toN _HEXTOKEN SOMELWS_SLASH_SOMELWS _HEXTOKEN _AT _HOST{
        headerptr->p__DCS__billing__info()().billing__correlation__ID()=str2hex($3);
        headerptr->p__DCS__billing__info()().FEID__ID()=str2hex($4);
        headerptr->p__DCS__billing__info()().FEID__host()=trimOnIPv6($7);
        headerptr->p__DCS__billing__info()().billing__info__params()=OMIT_VALUE;
        
//        Free($3);
//        Free($5);
//        Free($7);
      }
    | PBILLINGINFOLWSCOLON LWS_0toN _HEXTOKEN SOMELWS_SLASH_SOMELWS _HEXTOKEN _AT _HOST semicolon_fromparam_1toN{
        headerptr->p__DCS__billing__info()().billing__correlation__ID()=str2hex($3);
        headerptr->p__DCS__billing__info()().FEID__ID()=str2hex($5);
        headerptr->p__DCS__billing__info()().FEID__host()=trimOnIPv6($7);
        headerptr->p__DCS__billing__info()().billing__info__params()=*paramptr;
        delete paramptr;
        paramptr= new GenericParam__List;
        paramcount=0;        
//        Free($3);
//        Free($5);
//        Free($7);
      };

P_osps:
    POSPSLWSCOLON LWS_0toN _TOKEN {
        headerptr->p__DCS__OSPS()().OSPS__tag()=$3;
//        Free($3);
      };

P_trace_pty:
    PTARCEPTYIDLWSCOLON p_nameaddr {
        headerptr->p__DCS__trace__pty__id()().name__addr()=*$2;
        delete $2;
      };


Sec_client:
    SECCLIENTLWSCOLON Secmechanism_1toN{
      if(headerptr->security__client().ispresent()){
        int a=headerptr->security__client()().sec__mechanism__list().size_of();
        for(int b=0;b<$2->size_of();b++){
          headerptr->security__client()().sec__mechanism__list()[a]=(*$2)[b];
          a++;
          }
      }
      else {
        headerptr->security__client()().sec__mechanism__list()=*$2;
      }
      delete $2;
    };

Sec_server:
    SECSERVERLWSCOLON Secmechanism_1toN{
      if(headerptr->security__server().ispresent()){
        int a=headerptr->security__server()().sec__mechanism__list().size_of();
        for(int b=0;b<$2->size_of();b++){
          headerptr->security__server()().sec__mechanism__list()[a]=(*$2)[b];
          a++;
          }
      }
      else {
        headerptr->security__server()().sec__mechanism__list()=*$2;
      }
      delete $2;
    };

Sec_verify:
    SECVERIFYLWSCOLON Secmechanism_1toN{
      if(headerptr->security__verify().ispresent()){
        int a=headerptr->security__verify()().sec__mechanism__list().size_of();
        for(int b=0;b<$2->size_of();b++){
          headerptr->security__verify()().sec__mechanism__list()[a]=(*$2)[b];
          a++;
          }
      }
      else {
        headerptr->security__verify()().sec__mechanism__list()=*$2;
      }
      delete $2;
    };

Secmechanism_1toN:
    Secmechanism{
        $$= new Security__mechanism__list;
        (*$$)[0]=*$1;
        delete $1;
      }
    | Secmechanism_1toN SOMELWSCOMMA Secmechanism{
        int a=$1->size_of();
        $$=$1;
        (*$$)[a] = *$3;
        delete $3;
      };

Secmechanism:
    LWS_0toN _TOKEN {
        $$ = new Security__mechanism;
        $$->mechanism__name()= $2;
        $$->mechanism__params()=OMIT_VALUE;
//        Free($2);
      }
    | LWS_0toN _TOKEN semicolon_fromparam_1toN{
        $$ = new Security__mechanism;
        $$->mechanism__name()= $2;
        $$->mechanism__params()=*paramptr;
        delete paramptr;
        paramptr= new GenericParam__List;
        paramcount=0;
//        Free($2);
      };

Pathheader: PATHLWSCOLON routebdy1toN{
      if(headerptr->path().ispresent()){
        int a=headerptr->path()().routeBody().size_of();
        for(int b=0;b<$2->size_of();b++){
          headerptr->path()().routeBody()[a]=(*$2)[b];
          a++;
          }
      }
      else {
        headerptr->path()().routeBody()=*$2;
      }
      delete $2;
   };

routebdy1toN:
    routeadr {
        $$= new RouteBody__List;
        (*$$)[0]=*$1;
        delete $1;
      }
    | routebdy1toN SOMELWSCOMMA routeadr{
        int a=$1->size_of();
        $$=$1;
        (*$$)[a] = *$3;
        delete $3;
      };

routeadr:
    LWS_0toN display_name _ABO addr_spec _ABC semicolon_toparam_1toN {
        $$ = new RouteBody;
        $$->nameAddr().displayName()=$2;
        $$->nameAddr().addrSpec()= *uriptr;
        $$->rrParam()()= *paramptr;

        delete uriptr;
        uriptr= new SipUrl;
        urlparamcount=headercount=0;
        delete paramptr;
        paramptr= new GenericParam__List;
        paramcount=0;
//        Free($2);
      } 
    | LWS_0toN _ABO addr_spec _ABC semicolon_toparam_1toN {
        $$ = new RouteBody;
        $$->nameAddr().displayName()=OMIT_VALUE;
        $$->nameAddr().addrSpec()= *uriptr;
        $$->rrParam()()= *paramptr;

        delete uriptr;
        uriptr= new SipUrl;
        urlparamcount=headercount=0;
        delete paramptr;
        paramptr= new GenericParam__List;
        paramcount=0;
      }
    | LWS_0toN display_name _ABO addr_spec _ABC {
        $$ = new RouteBody;
        $$->nameAddr().displayName()=$2;
        $$->nameAddr().addrSpec()= *uriptr;
        $$->rrParam()= OMIT_VALUE;

        delete uriptr;
        uriptr= new SipUrl;
        urlparamcount=headercount=0;
//        Free($2);
      }
    | LWS_0toN _ABO addr_spec _ABC {
        $$ = new RouteBody;
        $$->nameAddr().displayName()=OMIT_VALUE;
        $$->nameAddr().addrSpec()= *uriptr;
        $$->rrParam()= OMIT_VALUE;

        delete uriptr;
        uriptr= new SipUrl;
        urlparamcount=headercount=0;
      };


P_media_auth:
    PMEDIAAUTHLWSCOLON auth_token_1toN {
      if(headerptr->p__media__auth().ispresent()){
        int a=headerptr->p__media__auth()().token__list().size_of();
        for(int b=0;b<$2->size_of();b++){
          headerptr->p__media__auth()().token__list()[a]=(*$2)[b];
          a++;
          }
      }
      else {
        headerptr->p__media__auth()().token__list()=*$2;
      }
      delete $2;
   };

auth_token_1toN:
    LWS_0toN _TOKEN{
        $$= new Media__auth__token__list;
        (*$$)[0]=str2hex($2);
        //Free $2;
      }
    | auth_token_1toN SOMELWSCOMMA LWS_0toN _TOKEN{
        int a=$1->size_of();
        $$=$1;
        (*$$)[a] = str2hex($4);
        //Free $4;
      };

Req_disp_cont:
    REQDISPLWSCOLON directive_1toN {
      if(headerptr->request__disp().ispresent()){
        int a=headerptr->request__disp()().directive__list().size_of();
        for(int b=0;b<$2->size_of();b++){
          headerptr->request__disp()().directive__list()[a]=(*$2)[b];
          a++;
          }
      }
      else {
        headerptr->request__disp()().directive__list()=*$2;
      }
      delete $2;
   };

directive_1toN:
    LWS_0toN _TOKEN{
        $$= new Request__disp__directive__list;
        (*$$)[0]=$2;
//        Free($2);
      }
    | directive_1toN SOMELWSCOMMA LWS_0toN _TOKEN{
        int a=$1->size_of();
        $$=$1;
        (*$$)[a] = $4;
//        Free($4);
      };

Reject_cont:
    REJECTCONTACTLWSCOLON conatact_1toN {
      if(headerptr->reject__contact().ispresent()){
        int a=headerptr->reject__contact()().rc__values().size_of();
        for(int b=0;b<$2->size_of();b++){
          headerptr->reject__contact()().rc__values()[a]=(*$2)[b];
          a++;
          }
      }
      else {
        headerptr->reject__contact()().rc__values()=*$2;
      }
      delete $2;
   };

Accept_cont:
    ACCEPTCONTACTLWSCOLON conatact_1toN {
      if(headerptr->accept__contact().ispresent()){
        int a=headerptr->accept__contact()().ac__values().size_of();
        for(int b=0;b<$2->size_of();b++){
          headerptr->accept__contact()().ac__values()[a]=(*$2)[b];
          a++;
          }
      }
      else {
        headerptr->accept__contact()().ac__values()=*$2;
      }
      delete $2;
   };

conatact_1toN:
    conatact_value{
        $$= new Contact__list;
        (*$$)[0]=*$1;
        delete $1;
      }
    | conatact_1toN SOMELWSCOMMA conatact_value{
        int a=$1->size_of();
        $$=$1;
        (*$$)[a] = *$3;
        delete $3;
      };

conatact_value:
    LWS_0toN _STAR {
        $$= new GenericParam__List(NULL_VALUE);
//        Free($2);
      };
    | LWS_0toN _STAR semicolon_fromparam_1toN {
//        Free($2);
        $$=paramptr;
        paramptr=new GenericParam__List;
        paramcount=0;
      };

session_exp_header:
    SESSIONEXPWSCOLON LWS_0toN _TOKEN {
        headerptr->session__expires()().deltaSec() = $3;
        headerptr->session__expires()().se__params() = OMIT_VALUE;
//        Free($3);
      }
    | SESSIONEXPWSCOLON LWS_0toN _TOKEN semicolon_fromparam_1toN {
        headerptr->session__expires()().deltaSec() = $3;
        headerptr->session__expires()().se__params()() = *paramptr;
//        Free($3);
        delete paramptr;
        paramptr=new GenericParam__List;
        paramcount=0;
      };

session_id_header:
    SESSIONIDLWSCOLON LWS_0toN _TOKEN {
        headerptr->session__id()().sessionID() = $3;
        headerptr->session__id()().se__params() = OMIT_VALUE;
//        Free($3);
      }
    | SESSIONIDLWSCOLON LWS_0toN _TOKEN semicolon_fromparam_1toN {
        headerptr->session__id()().sessionID() = $3;
        headerptr->session__id()().se__params()() = *paramptr;
//        Free($3);
        delete paramptr;
        paramptr=new GenericParam__List;
        paramcount=0;
      };

min_se_header:
    MINSELWSCOLON LWS_0toN _TOKEN {
        headerptr->min__SE()().deltaSec() = $3;
        headerptr->min__SE()().params() = OMIT_VALUE;
//        Free($3);
      }
    | MINSELWSCOLON LWS_0toN _TOKEN semicolon_fromparam_1toN {
        headerptr->min__SE()().deltaSec() = $3;
        headerptr->min__SE()().params()() = *paramptr;
//        Free($3);
        delete paramptr;
        paramptr=new GenericParam__List;
        paramcount=0;
      };

HistoryInfo_header:
    HISTORYLWSCOLON h_urispec_1toN{
      if(headerptr->historyInfo().ispresent()){
        int a=headerptr->historyInfo()().hi__entries().size_of();
        for(int b=0;b<$2->size_of();b++){
          headerptr->historyInfo()().hi__entries()[a]=(*$2)[b];
          a++;
          }
      }
      else {
        headerptr->historyInfo()().hi__entries()=*$2;
      }
      delete $2;
   };

h_urispec_1toN:
    h_urispec {
        $$ = new Hi__Entry__list;
        (*$$)[0] = *$1;
        delete $1;
      }
    | h_urispec_1toN SOMELWSCOMMA h_urispec{
        int a=$1->size_of();
        $$=$1;
        (*$$)[a] = *$3;
        delete $3;
      };
    
h_urispec:
    p_nameaddr {
        $$= new Hi__Entry;
        $$->nameAddr()=*$1;
        $$->hi__params()=OMIT_VALUE;
        delete $1;
      }
    | p_nameaddr semicolon_fromparam_1toN {
        $$= new Hi__Entry;
        $$->nameAddr()=*$1;
        $$->hi__params()=*paramptr;
        paramcount=0;
        delete paramptr;
        paramptr=new GenericParam__List;
        delete $1;
      };

p_charge_vector:
    PCHARGEVECTORLWSCOLON semicolon_param_1toN{
        int b=0;
        int a;
        for(a=0;a<paramptr->size_of();a++){
          if(strcasecmp((const char*)(*paramptr)[a].id(),"icid-value")){
            headerptr->p__charging__vector()().charge__params()()[b].id()=(*paramptr)[a].id();
            headerptr->p__charging__vector()().charge__params()()[b].paramValue()=(*paramptr)[a].paramValue();
            b++;
          }
          else {
            headerptr->p__charging__vector()().icid__value()=(*paramptr)[a].paramValue();
          }
        }
        if(b==0) headerptr->p__charging__vector()().charge__params()=OMIT_VALUE;
        if(a==b) headerptr->p__charging__vector()().icid__value()="";
        paramcount=0;
        delete paramptr;
        paramptr=new GenericParam__List;

      };


p_charge_addr:
    PCHARGEADDRLWSCOLON semicolon_param_1toN{
        headerptr->p__charging__function__address()().charge__addr__params()=*paramptr;
        paramcount=0;
        delete paramptr;
        paramptr=new GenericParam__List;

      };

semicolon_param_1toN:
    from_param {}
    | semicolon_param_1toN SOMELWS_SEMICOLON from_param {};


p_access_net_header:
    PACCESSNETLWSCOLON anetspec_1toN{
      if(headerptr->p__access__network__info().ispresent()){
        int a=headerptr->p__access__network__info()().access__net__specs().size_of();
        for(int b=0;b<$2->size_of();b++){
          headerptr->p__access__network__info()().access__net__specs()[a]=(*$2)[b];
          a++;
          }
      }
      else {
        headerptr->p__access__network__info()().access__net__specs()=*$2;
      }
      delete $2;
   };
   
anetspec_1toN:
    anetspec{
        $$= new Access__net__spec__list;
        (*$$)[0]=*$1;
        delete $1;
      }
    | anetspec_1toN SOMELWSCOMMA anetspec{
        int a=$1->size_of();
        $$=$1;
        (*$$)[a] = *$3;
        delete $3;
      };
      
anetspec:
    LWS_0toN display_name{
        $$= new Access__net__spec;
        $$->access__type()=$2;
        $$->access__info()=OMIT_VALUE;
//        Free($2);
      }
    | LWS_0toN display_name semicolon_fromparam_1toN{
        $$= new Access__net__spec;
        $$->access__type()=$2;
        $$->access__info()=*paramptr;
        paramcount=0;
        delete paramptr;
        paramptr=new GenericParam__List;
//        Free($2);
      };
      
      
answer_mode_header:
    ANSWERMODELWSCOLON LWS_0toN _TOKEN{
        headerptr->answer__mode()().answer__mode()=$3;
        headerptr->answer__mode()().answer__mode__param()=OMIT_VALUE;
//        Free($3);
      }
    | ANSWERMODELWSCOLON LWS_0toN _TOKEN semicolon_fromparam_1toN{
        headerptr->answer__mode()().answer__mode()=$3;
        headerptr->answer__mode()().answer__mode__param()=*paramptr;
        paramcount=0;
        delete paramptr;
        paramptr=new GenericParam__List;
//        Free($3);
      };

priv_answer_mode_header:
    PRIVANSWERMODELWSCOLON LWS_0toN _TOKEN{
        headerptr->priv__answer__mode()().answer__mode()=$3;
        headerptr->priv__answer__mode()().answer__mode__param()=OMIT_VALUE;
//        Free($3);
      }
    | PRIVANSWERMODELWSCOLON LWS_0toN _TOKEN semicolon_fromparam_1toN{
        headerptr->priv__answer__mode()().answer__mode()=$3;
        headerptr->priv__answer__mode()().answer__mode__param()=*paramptr;
        paramcount=0;
        delete paramptr;
        paramptr=new GenericParam__List;
//        Free($3);
      };

alert_mode_header:
    ALERTMODELWSCOLON LWS_0toN _TOKEN{
        headerptr->alert__mode()().alert__mode()=$3;
        headerptr->alert__mode()().alert__mode__param()=OMIT_VALUE;
//        Free($3);
      }
    | ALERTMODELWSCOLON LWS_0toN _TOKEN semicolon_fromparam_1toN{
        headerptr->alert__mode()().alert__mode()=$3;
        headerptr->alert__mode()().alert__mode__param()=*paramptr;
        paramcount=0;
        delete paramptr;
        paramptr=new GenericParam__List;
//        Free($3);
      };

refer_sub_header:
    REFERSUBLWSCOLON LWS_0toN _TOKEN{
        headerptr->refer__sub()().refer__sub__value()=$3;
        headerptr->refer__sub()().refer__sub__param()=OMIT_VALUE;
//        Free($3);
      }
    | REFERSUBLWSCOLON LWS_0toN _TOKEN semicolon_fromparam_1toN{
        headerptr->refer__sub()().refer__sub__value()=$3;
        headerptr->refer__sub()().refer__sub__param()=*paramptr;
        paramcount=0;
        delete paramptr;
        paramptr=new GenericParam__List;
//        Free($3);
      };

p_alerting_mode_header:
    PALERTINGMODELWSCOLON LWS_0toN _TOKEN{
        headerptr->p__alerting__mode()().alerting__type()=$3;
        headerptr->p__alerting__mode()().alerting__info()=OMIT_VALUE;
//        Free($3);
      }
    | PALERTINGMODELWSCOLON LWS_0toN _TOKEN semicolon_fromparam_1toN{
        headerptr->p__alerting__mode()().alerting__type()=$3;
        headerptr->p__alerting__mode()().alerting__info()=*paramptr;
        paramcount=0;
        delete paramptr;
        paramptr=new GenericParam__List;
//        Free($3);
      };

p_answer_sate_header:
    PANSWERSTATELWSCOLON LWS_0toN _TOKEN{
        headerptr->p__answer__state()().answer__type()=$3;
        headerptr->p__answer__state()().answer__info()=OMIT_VALUE;
//        Free($3);
      }
    | PANSWERSTATELWSCOLON LWS_0toN _TOKEN semicolon_fromparam_1toN{
        headerptr->p__answer__state()().answer__type()=$3;
        headerptr->p__answer__state()().answer__info()=*paramptr;
        paramcount=0;
        delete paramptr;
        paramptr=new GenericParam__List;
//        Free($3);
      };

p_area_info:
    PAREAINFOLWSCOLON semicolon_param_1toN{
        headerptr->p__Area__Info()().p__Area__Info__Value()=*paramptr;
        paramcount=0;
        delete paramptr;
        paramptr=new GenericParam__List;
      };

p_visited_net_id_header:
    PVISITEDNETLWSCOLON vnetspec_1toN{
      if(headerptr->p__visited__network__id().ispresent()){
        int a=headerptr->p__visited__network__id()().vnetworks().size_of();
        for(int b=0;b<$2->size_of();b++){
          headerptr->p__visited__network__id()().vnetworks()[a]=(*$2)[b];
          a++;
          }
      }
      else {
        headerptr->p__visited__network__id()().vnetworks()=*$2;
      }
      delete $2;
   };

vnetspec_1toN:
    vnetspec{
        $$= new Network__spec__list;
        (*$$)[0]=*$1;
        delete $1;
      }
    | vnetspec_1toN SOMELWSCOMMA vnetspec{
        int a=$1->size_of();
        $$=$1;
        (*$$)[a] = *$3;
        delete $3;
      };
vnetspec:
    LWS_0toN display_name{
        $$= new Network__spec;
        $$->network__id()=$2;
        $$->network__par()=OMIT_VALUE;
//        Free($2);
      }
    | LWS_0toN display_name semicolon_fromparam_1toN{
        $$= new Network__spec;
        $$->network__id()=$2;
        $$->network__par()=*paramptr;
        paramcount=0;
        delete paramptr;
        paramptr=new GenericParam__List;
//        Free($2);
      };


P_called_party_id_header:
    PCALLEPPTYLWSCOLON p_nameaddr {
        headerptr->p__called__party__id()().called__pty__id()=*$2;
        headerptr->p__called__party__id()().cpid__param()=OMIT_VALUE;
        delete $2;
      }
    | PCALLEPPTYLWSCOLON p_nameaddr semicolon_fromparam_1toN {
        headerptr->p__called__party__id()().called__pty__id()=*$2;
        headerptr->p__called__party__id()().cpid__param()=*paramptr;
        paramcount=0;
        delete paramptr;
        paramptr=new GenericParam__List;
        delete $2;
      };

P_assoc_uri_header:
    PASSOCURILWSCOLON p_urispec_1toN{
      if(headerptr->p__associated__uri().ispresent()){
        int a=headerptr->p__associated__uri()().p__assoc__uris().size_of();
        for(int b=0;b<$2->size_of();b++){
          headerptr->p__associated__uri()().p__assoc__uris()[a]=(*$2)[b];
          a++;
          }
      }
      else {
        headerptr->p__associated__uri()().p__assoc__uris()=*$2;
      }
      delete $2;
   };

p_urispec_1toN:
    p_urispec {
        $$ = new P__Assoc__uri__spec__list;
        (*$$)[0] = *$1;
        delete $1;
      }
    | p_urispec_1toN SOMELWSCOMMA p_urispec{
        int a=$1->size_of();
        $$=$1;
        (*$$)[a] = *$3;
        delete $3;
      };
    
p_urispec:
    p_nameaddr {
        $$= new P__Assoc__uri__spec;
        $$->p__asso__uri()=*$1;
        $$->ai__params()=OMIT_VALUE;
        delete $1;
      }
    | p_nameaddr semicolon_fromparam_1toN {
        $$= new P__Assoc__uri__spec;
        $$->p__asso__uri()=*$1;
        $$->ai__params()=*paramptr;
        paramcount=0;
        delete paramptr;
        paramptr=new GenericParam__List;
        delete $1;
      };

P_diversion_header:
    DIVERSIONWSCOLON p_divspec_1toN{
      if(headerptr->diversion().ispresent()){
        int a=headerptr->diversion()().divParams().size_of();
        for(int b=0;b<$2->size_of();b++){
          headerptr->diversion()().divParams()[a]=(*$2)[b];
          a++;
          }
      }
      else {
        headerptr->diversion()().divParams()=*$2;
      }
      delete $2;
   };

p_divspec_1toN:
    p_divspec {
        $$ = new Diversion__params__list;
        (*$$)[0] = *$1;
        delete $1;
      }
    | p_divspec_1toN SOMELWSCOMMA p_divspec{
        int a=$1->size_of();
        $$=$1;
        (*$$)[a] = *$3;
        delete $3;
      };
    
p_divspec:
    p_nameaddr {
        $$= new Diversion__params;
        $$->nameAddr()=*$1;
        $$->div__params()=OMIT_VALUE;
        delete $1;
      }
    | p_nameaddr semicolon_fromparam_1toN {
        $$= new Diversion__params;
        $$->nameAddr()=*$1;
        $$->div__params()=*paramptr;
        paramcount=0;
        delete paramptr;
        paramptr=new GenericParam__List;
        delete $1;
      };

p_nameaddr:
    LWS_0toN display_name _ABO addr_spec _ABC {
        $$= new NameAddr;
        $$->displayName() = $2;
        $$->addrSpec()= *uriptr;
        delete uriptr;
        uriptr= new SipUrl;
        urlparamcount=headercount=0;
//        Free($2);
      }
    | LWS_0toN _ABO addr_spec _ABC {
        $$= new NameAddr;
        $$->displayName() = OMIT_VALUE;
        $$->addrSpec()= *uriptr;
        delete uriptr;
        uriptr= new SipUrl;
        urlparamcount=headercount=0;
      };


Subscription_stateheader:
   SUBSTATEWSCOLON LWS_0toN _TOKEN{
      headerptr->subscription__state()().substate__value() =$3;
      headerptr->subscription__state()().subexp__params()= OMIT_VALUE;
//      Free($3);
    }
   | SUBSTATEWSCOLON LWS_0toN _TOKEN semicolon_fromparam_1toN{
      headerptr->subscription__state()().substate__value() =$3;
      headerptr->subscription__state()().subexp__params()= *paramptr;
      paramcount=0;
      delete paramptr;
      paramptr=new GenericParam__List;

//      Free($3);
    };

AllowEventheader:
   ALLOWEVENTLWSCOLON event_list1toN{
      if(headerptr->allow__events().ispresent()){
        int a=headerptr->allow__events()().events().size_of();
        for(int b=0;b<$2->size_of();b++){
          headerptr->allow__events()().events()[a]=(*$2)[b];
          a++;
          }
      }
      else {
        headerptr->allow__events()().events()=*$2;
      }
      delete $2;
   };

event_list1toN:
    LWS_0toN event_event{
        $$ = new Event__type__list;
        (*$$)[0] = *$2;
        delete $2;
      }
    | event_list1toN SOMELWSCOMMA LWS_0toN event_event{
        int a=$1->size_of();
        $$=$1;
        (*$$)[a] = *$4;
        delete $4;
      };


Eventheader:
    EVENTLWSCOLON LWS_0toN event_event {
        headerptr->event()().event__type()=*$3;
        headerptr->event()().event__params()=OMIT_VALUE;
        delete $3;
      }
    | EVENTLWSCOLON LWS_0toN event_event semicolon_fromparam_1toN{
        headerptr->event()().event__type()=*$3;
        headerptr->event()().event__params()=*paramptr;
        paramcount=0;
        delete paramptr;
        paramptr=new GenericParam__List;
        delete $3;
      };

event_event:
    _TOKEN_NO_DOT {
      $$ = new Event__type;
      $$->event__package()= $1;
      $$->event__templates()=OMIT_VALUE;
//      Free($1);
      }
    | _TOKEN_NO_DOT _DOT event_event_template1toN{
      $$ = new Event__type;
      $$->event__package()= $1;
      $$->event__templates()=*$3;
      delete $3;
//      Free($1);
      };

event_event_template1toN:
    LWS_0toN _TOKEN_NO_DOT{
        $$ = new Event__template__list;
        (*$$)[0] = $2;
//        Free($2);
      }
    | event_event_template1toN _DOT LWS_0toN _TOKEN_NO_DOT{
        int a=$1->size_of();
        $$=$1;
        (*$$)[a] = $4;
//        Free($4);
      };

Reasonheader:
    REASONLWSCOLON reason_1toN;

reason_1toN:
    reason_
    | reason_1toN SOMELWSCOMMA reason_ ;

reason_:
    LWS_0toN _TOKEN {
        headerptr->reason()().reasons()[reasoncount].protocol()= $2;
        headerptr->reason()().reasons()[reasoncount].reasonValues()=OMIT_VALUE;
        reasoncount++;
//        Free($2);
      } 
    | LWS_0toN _TOKEN semicolon_dispparam_1toN {
        headerptr->reason()().reasons()[reasoncount].protocol()= $2;
        headerptr->reason()().reasons()[reasoncount].reasonValues()()=*paramptr;
        reasoncount++;
        delete paramptr;
        paramptr=new GenericParam__List;
        paramcount=0;
//        Free($2);
      };

P_Asserted_header:
    PASSERTEDLWSCOLON asserted_id_1toN {};

asserted_id_1toN:
    asserted_id
    | asserted_id_1toN SOMELWSCOMMA asserted_id;

asserted_id:
    | LWS_0toN display_name _ABO addr_spec _ABC {
        headerptr->passertedID()().ids()[passertedidcount].
                    nameAddr().displayName()= $2;
        headerptr->passertedID()().ids()[passertedidcount].
                    nameAddr().addrSpec()= *uriptr;
        passertedidcount++;
//        Free($2);
        delete uriptr;
        uriptr= new SipUrl;
        urlparamcount=headercount=0;
      }
    | LWS_0toN _ABO addr_spec _ABC {
        headerptr->passertedID()().ids()[passertedidcount].
                    nameAddr().displayName()= OMIT_VALUE;
        headerptr->passertedID()().ids()[passertedidcount].
                    nameAddr().addrSpec()= *uriptr;
        passertedidcount++;
        delete uriptr;
        uriptr= new SipUrl;
        urlparamcount=headercount=0;
      }
    | LWS_0toN addr_spec {
        headerptr->passertedID()().ids()[passertedidcount].
                    addrSpecUnion()= *uriptr;
        passertedidcount++;
        delete uriptr;
        uriptr= new SipUrl;
        urlparamcount=headercount=0;
      };

P_Preferred_header:
    PPREFERREDLWSCOLON preferred_id_1toN {};

preferred_id_1toN:
    preferred_id
    | preferred_id_1toN SOMELWSCOMMA preferred_id;

preferred_id:
    | LWS_0toN display_name _ABO addr_spec _ABC {
        headerptr->ppreferredID()().ids()[ppreferredidcount].
                    nameAddr().displayName()= $2;
        headerptr->ppreferredID()().ids()[ppreferredidcount].
                    nameAddr().addrSpec()= *uriptr;
        ppreferredidcount++;
//        Free($2);
        delete uriptr;
        uriptr= new SipUrl;
        urlparamcount=headercount=0;
      }
    | LWS_0toN _ABO addr_spec _ABC {
        headerptr->ppreferredID()().ids()[ppreferredidcount].
                    nameAddr().displayName()= OMIT_VALUE;
        headerptr->ppreferredID()().ids()[ppreferredidcount].
                    nameAddr().addrSpec()= *uriptr;
        ppreferredidcount++;
        delete uriptr;
        uriptr= new SipUrl;
        urlparamcount=headercount=0;
      }
    | LWS_0toN addr_spec_withnoparam {
        headerptr->ppreferredID()().ids()[ppreferredidcount].
                    addrSpecUnion()= *uriptr;
        ppreferredidcount++;
        delete uriptr;
        uriptr= new SipUrl;
        urlparamcount=headercount=0;
      };

Privacyheader:
    PRIVACYLWSCOLON privacy_value1ton {};

privacy_value1ton:
    LWS_0toN privacy_value
    | privacy_value1ton SOMELWS_SEMICOLON LWS_0toN privacy_value;

privacy_value:
    _TOKEN {
      headerptr->privacy()().privacyValues()[privacycount]=$1;
      privacycount++;
//      Free($1);
    };

Rackheader:
    RACKLWSCOLON LWS_0toN SOMEDIGITS SOMELWS SOMEDIGITS SOMELWS _TOKEN {
        headerptr->rack()().response__num()= str2int($3); /*Free($3);*/
        headerptr->rack()().seqNumber()= str2int($5); /*Free($5);*/
        headerptr->rack()().method()= $7;
//        Free($7);
      };

Rseqheader:
    RSEQLWSCOLON LWS_0toN SOMEDIGITS {
        headerptr->rseq()().response__num() = str2int($3); /*Free($3);*/
      };

ReplyTo:
    REPLY_TOLWSCOLON replytobody {};

replytobody:
    LWS_0toN display_name _ABO addr_spec _ABC semicolon_toparam_1toN {
        headerptr->replyTo()().addressField().nameAddr().displayName() = $2;
        headerptr->replyTo()().addressField().nameAddr().addrSpec()= *uriptr;
        headerptr->replyTo()().replyToParams()=*paramptr;

        delete uriptr;
        uriptr= new SipUrl;
        urlparamcount=headercount=0;
        delete paramptr;
        paramptr= new GenericParam__List;
        paramcount=0;

//        Free($2);
      } 
    | LWS_0toN _ABO addr_spec _ABC semicolon_toparam_1toN {
        headerptr->replyTo()().addressField().nameAddr().displayName() = 
                                                                     OMIT_VALUE;
        headerptr->replyTo()().addressField().nameAddr().addrSpec()= *uriptr;
        headerptr->replyTo()().replyToParams()=*paramptr;
        delete uriptr;
        uriptr= new SipUrl;
        urlparamcount=headercount=0;
        delete paramptr;
        paramptr= new GenericParam__List;
        paramcount=0;
      }
    | LWS_0toN addr_spec_withnoparam semicolon_toparam_1toN {
        headerptr->replyTo()().addressField().addrSpecUnion()= *uriptr;
        headerptr->replyTo()().replyToParams()=*paramptr;
        delete uriptr;
        uriptr= new SipUrl;
        urlparamcount=headercount=0;
        delete paramptr;
        paramptr= new GenericParam__List;
        paramcount=0;
      }
    | LWS_0toN display_name _ABO addr_spec _ABC {
        headerptr->replyTo()().addressField().nameAddr().displayName() = $2;
        headerptr->replyTo()().addressField().nameAddr().addrSpec()= *uriptr;
        headerptr->replyTo()().replyToParams()=OMIT_VALUE;
        delete uriptr;
        uriptr= new SipUrl;
        urlparamcount=headercount=0;
//        Free($2);
      }
    | LWS_0toN _ABO addr_spec _ABC {
        headerptr->replyTo()().addressField().nameAddr().displayName() = 
                                                                    OMIT_VALUE;
        headerptr->replyTo()().addressField().nameAddr().addrSpec()= *uriptr;
        headerptr->replyTo()().replyToParams()=OMIT_VALUE;
        delete uriptr;
        uriptr= new SipUrl;
        urlparamcount=headercount=0;
      }
    | LWS_0toN addr_spec_withnoparam {
        headerptr->replyTo()().addressField().addrSpecUnion()= *uriptr;
        headerptr->replyTo()().replyToParams()=OMIT_VALUE;
        delete uriptr;
        uriptr= new SipUrl;
        urlparamcount=headercount=0;
      };

Other:
    OTHERLWSCOLON CONTENT_WITHOUTENDINGCRLF {
        headerptr->undefinedHeader__List()()[undefcount].headerName() = $1;
        headerptr->undefinedHeader__List()()[undefcount].headerValue()=trim($2);
        undefcount++;
//        Free($1);Free($2);
      };

Via:
    VIALWSCOLON sntp_sntb_scviap0N_cmt01_1cN {};

sntp_sntb_scviap0N_cmt01_1cN:
    LWS_0toN sntp_sntb_scviap0N_cmt01 LWS0N_c_LWS0N_spbscvpc_1toN
    |LWS_0toN sntp_sntb_scviap0N_cmt01;

LWS0N_c_LWS0N_spbscvpc_1toN:
      SOMELWS_COMMA_SOMELWS sntp_sntb_scviap0N_cmt01    {}
    | LWS0N_c_LWS0N_spbscvpc_1toN
        SOMELWS_COMMA_SOMELWS sntp_sntb_scviap0N_cmt01;

sntp_sntb_scviap0N_cmt01:
    sent_protocol LWS_0toN sent_by semicolon_viaparams_1toN {
        headerptr->via()().viaBody()[viacount].viaParams()=*paramptr;
        viacount++;
        delete paramptr;
        paramptr= new GenericParam__List;
        paramcount=0;
      }
    | sent_protocol LWS_0toN sent_by {
        headerptr->via()().viaBody()[viacount].viaParams()=OMIT_VALUE;
        viacount++;
      };
        
sent_protocol:
    PROTOCOL_NAME SOMELWS_SLASH_SOMELWS PROTOCOL_VERSION 
                                               SOMELWS_SLASH_SOMELWS TRANSPORT {
       headerptr->via()().viaBody()[viacount].sentProtocol().protocolName()=$1;
       headerptr->via()().viaBody()[viacount].sentProtocol().protocolVersion()=$3;
       headerptr->via()().viaBody()[viacount].sentProtocol().transport()=$5;
//       Free($1);Free($3);Free($5);
     };

sent_by:
    _HOST SOMELWS _COLON SOMELWS _PORT {
        headerptr->via()().viaBody()[viacount].sentBy().host()=trimOnIPv6($1);
        headerptr->via()().viaBody()[viacount].sentBy().portField()=$5;
//        Free($1);
      }
    |_HOST SOMELWS _COLON _PORT {
        headerptr->via()().viaBody()[viacount].sentBy().host()=trimOnIPv6($1);
        headerptr->via()().viaBody()[viacount].sentBy().portField()=$4;
//        Free($1);
      }
    |_HOST _COLON SOMELWS _PORT {
        headerptr->via()().viaBody()[viacount].sentBy().host()=trimOnIPv6($1);
        headerptr->via()().viaBody()[viacount].sentBy().portField()=$4;
//        Free($1);
      }
    |_HOST _COLON _PORT {
        headerptr->via()().viaBody()[viacount].sentBy().host()=trimOnIPv6($1);
        headerptr->via()().viaBody()[viacount].sentBy().portField()=$3;
//        Free($1);
      }
    |_HOST {
        headerptr->via()().viaBody()[viacount].sentBy().host()=trimOnIPv6($1);
        headerptr->via()().viaBody()[viacount].sentBy().portField()=OMIT_VALUE;
//        Free($1);
      };

semicolon_viaparams_1toN:
      SOMELWS_SEMICOLON from_param {}
    | semicolon_viaparams_1toN SOMELWS_SEMICOLON from_param {};

MinExpires:
    MINEXPIRESLWSCOLON LWS_0toN _TOKEN {
        headerptr->minExpires()().deltaSec()= $3;
//        Free($3);
      };

MIME_Version:
    MIME_VERSIONLWSCOLON LWS_0toN SOMEDIGITS _DOT SOMEDIGITS {
        headerptr->mimeVersion()().majorNumber()=str2int($3); /*Free($3);*/
        headerptr->mimeVersion()().minorNumber()=str2int($5); /*Free($5); */
      };

User_Agent:
    USER_AGENTLWSCOLON LWS_0toN product_comment_1toN {};

product_comment_1toN:
    product_comment {
        headerptr->userAgent()().userAgentBody()[useragentcount]= $1;
        useragentcount++;
        Free($1);
      }
    | product_comment_1toN SOMELWS product_comment {
        headerptr->userAgent()().userAgentBody()[useragentcount]= $3;
        useragentcount++;
        Free($3);
      };

Timestamp:
    TIMESTAMPLWSCOLON LWS_0toN SOMEDIGITS {
        headerptr->timestamp()().timeValue()().majorDigit()=str2int($3); /*Free($3);*/
        headerptr->timestamp()().timeValue()().minorDigit()=OMIT_VALUE;
        headerptr->timestamp()().delay() = OMIT_VALUE;
      } 
    | TIMESTAMPLWSCOLON LWS_0toN SOMEDIGITS _DOT SOMEDIGITS {
        headerptr->timestamp()().timeValue()().majorDigit()=str2int($3); /*Free($3);*/
        headerptr->timestamp()().timeValue()().minorDigit()=str2int($5); /*Free($5);*/
        headerptr->timestamp()().delay() = OMIT_VALUE;
      } 
    | TIMESTAMPLWSCOLON LWS_0toN SOMEDIGITS SOMELWS SOMEDIGITS {
        headerptr->timestamp()().timeValue()().majorDigit()=str2int($3); /*Free($3);*/
        headerptr->timestamp()().timeValue()().minorDigit()=OMIT_VALUE;
        headerptr->timestamp()().delay()().majorDigit()=str2int($5); /*Free($5);*/
        headerptr->timestamp()().delay()().minorDigit()=OMIT_VALUE;
      } 
    | TIMESTAMPLWSCOLON LWS_0toN SOMEDIGITS _DOT SOMEDIGITS SOMELWS SOMEDIGITS {
        headerptr->timestamp()().timeValue()().majorDigit()=str2int($3); //Free($3);
        headerptr->timestamp()().timeValue()().minorDigit()=str2int($5); //Free($5);
        headerptr->timestamp()().delay()().majorDigit()=str2int($7); //Free($7);
        headerptr->timestamp()().delay()().minorDigit()=OMIT_VALUE;
      } 
    | TIMESTAMPLWSCOLON LWS_0toN SOMEDIGITS SOMELWS SOMEDIGITS _DOT SOMEDIGITS {
        headerptr->timestamp()().timeValue()().majorDigit()=str2int($3); //Free($3);
        headerptr->timestamp()().timeValue()().minorDigit()=OMIT_VALUE;
        headerptr->timestamp()().delay()().majorDigit()=str2int($5); //Free($5);
        headerptr->timestamp()().delay()().minorDigit()=str2int($7); //Free($7);
      } 
    | TIMESTAMPLWSCOLON LWS_0toN SOMEDIGITS _DOT SOMEDIGITS 
                                            SOMELWS SOMEDIGITS _DOT SOMEDIGITS {
        headerptr->timestamp()().timeValue()().majorDigit()=str2int($3); //Free($3);
        headerptr->timestamp()().timeValue()().minorDigit()=str2int($5); //Free($5);
        headerptr->timestamp()().delay()().majorDigit()=str2int($7); //Free($7);
        headerptr->timestamp()().delay()().minorDigit()=str2int($9); //Free($9);
      };

Supported:
    SUPPORTEDLWSCOLON {
        headerptr->supported()().optionsTags()=OMIT_VALUE;
      }
    |SUPPORTEDLWSCOLON optioncontent_1toN {
        if(!suppcount){
          headerptr->supported()().optionsTags()= *optptr;
          delete optptr;
        }
        suppcount=optioncount;
      };

Require:
    REQUIRELWSCOLON optioncontent_1toN {
        if(!reqcount){
          headerptr->require()().optionsTags()= *optptr;
          delete optptr;
        }
        reqcount=optioncount;
      };

Record_Route:
    RECORD_ROUTELWSCOLON routebody1toN {
        if(!recroutecount){
          headerptr->recordRoute()().routeBody()= *routeptr;
          delete routeptr;
        }
        recroutecount=rcount;
      };

Organization:
    ORGANIZATIONLWSCOLON CONTENT_WITHOUTENDINGCRLF {
        headerptr->organization()().organization() = trim($2);
//        Free($2);
      };

Date:
    DATELWSCOLON LWS_0toN _TYPEID {
        headerptr->date()().sipDate() = trim($3);
//        Free($3);
      };

Cseq:
    CSEQLWSCOLON LWS_0toN SOMEDIGITS LWS_0toN _METHOD {
        headerptr->cSeq()().seqNumber() = str2int($3); //Free($3);
        headerptr->cSeq()().method()= $5;
//        Free($5);
      };

Call_Info:
    CALL_INFOLWSCOLON call_info_body1toN {};

call_info_body1toN:
    call_info_body
    |call_info_body SOMELWSCOMMA call_info_body1toN;
    
call_info_body:
    LWS_0toN _ABO _URLTOKEN _ABC {
        headerptr->callInfo()().callInfoBody()()[callinfocount].url()=$3;
        headerptr->callInfo()().callInfoBody()()[callinfocount].infoParams()=
                                                                     OMIT_VALUE;
        callinfocount++;
//        Free($3);
      }
    | LWS_0toN _ABO _URLTOKEN _ABC semicolon_fromparam_1toN {
        headerptr->callInfo()().callInfoBody()()[callinfocount].url()=$3;
        headerptr->callInfo()().callInfoBody()()[callinfocount].infoParams()=
                                                                      *paramptr;
        paramcount=0;
        callinfocount++;
        delete paramptr;
        paramptr=new GenericParam__List;
//        Free($3);
      };

Call_ID:
    CALL_IDLWSCOLON LWS_0toN _CALLID {
        headerptr->callId()().callid()=$3;
//        Free($3);
      };

LWS_0toN:
    /* empty */  {}
    | SOMELWS    {};

Accept:            
    ACCEPTLWSCOLON {
        if(!acceptcount){headerptr->accept()().acceptArgs()= OMIT_VALUE;};
      }
    | ACCEPTLWSCOLON acceptrange1toN {};
    
acceptrange1toN:
    acceptrange
    | acceptrange SOMELWSCOMMA acceptrange1toN;
    
acceptrange:
    LWS_0toN _TOKEN _SLASH _TOKEN {
        size_t len2 = strlen($2);
        size_t buflen = len2+strlen($4)+2;
        char *buff=(char *)Malloc(buflen);
        /*buff[0]='\0';
        strcat(buff,$2);
        strcat(buff,"/");
        strcat(buff,$4);*/
        // avoid strcat+strcat+...
        strcpy(buff, $2);
        buff[len2] = '/';
        strcpy(buff+len2+1, $4);
        buff[buflen-1] = '\0'; // safety
        headerptr->accept()().acceptArgs()()[acceptcount].mediaRange()=buff;
        headerptr->accept()().acceptArgs()()[acceptcount].acceptParam()
                      =OMIT_VALUE;
        acceptcount++;
        //Free($2);Free($4);
	Free(buff);
      }
    | LWS_0toN _TOKEN _SLASH _TOKEN semicolon_fromparam_1toN {
        size_t len2 = strlen($2);
        size_t buflen = len2+strlen($4)+2;
        char *buff=(char *)Malloc(buflen);
        /*buff[0]='\0';
        strcat(buff,$2);
        strcat(buff,"/");
        strcat(buff,$4);*/
        // avoid strcat+strcat+...
        strcpy(buff, $2);
        buff[len2] = '/';
        strcpy(buff+len2+1, $4);
        buff[buflen-1] = '\0'; // safety
        headerptr->accept()().acceptArgs()()[acceptcount].mediaRange()=buff;
        headerptr->accept()().acceptArgs()()[acceptcount].acceptParam()
                      =*paramptr;
        paramcount=0;
        acceptcount++;
        delete paramptr;
        paramptr=new GenericParam__List;
        //Free($2);Free($4);
	Free(buff);
      };


Accept_Encoding:
    ACCEPT_ENCODINGLWSCOLON {
        if(!aceptenccount){headerptr->acceptEncoding()().contentCoding()
                    = OMIT_VALUE;};
      }
    | ACCEPT_ENCODINGLWSCOLON encoding1_N {};

encoding1_N:
    LWS_0toN _STOKEN {
        headerptr->acceptEncoding()().contentCoding()()[aceptenccount]=trim($2);
        aceptenccount++;
//        Free($2);
      }
    | encoding1_N SOMELWSCOMMA LWS_0toN _STOKEN {
        headerptr->acceptEncoding()().contentCoding()()[aceptenccount]=trim($4);
        aceptenccount++;
//        Free($4);
      };

Accept_Language:
    ACCEPT_LANGUAGELWSCOLON {
        headerptr->acceptLanguage()().languageBody()=OMIT_VALUE;
      }
    |ACCEPT_LANGUAGELWSCOLON accept_lang_range1toN {} ;

accept_lang_range1toN:
    accept_lang_range
    |accept_lang_range SOMELWSCOMMA accept_lang_range1toN;
    
accept_lang_range:
    LWS_0toN _TOKEN {
        headerptr->acceptLanguage()().languageBody()()[acceptlangcount].
                      languageRange()=$2;
        headerptr->acceptLanguage()().languageBody()()[acceptlangcount].
                      acceptParam()=OMIT_VALUE;
        acceptlangcount++;
//        Free($2);
      }
    | LWS_0toN _TOKEN semicolon_fromparam_1toN {
        headerptr->acceptLanguage()().languageBody()()[acceptlangcount].
                      languageRange()=$2;
        headerptr->acceptLanguage()().languageBody()()[acceptlangcount].
                      acceptParam()=*paramptr;
        paramcount=0;
        acceptlangcount++;
        delete paramptr;
        paramptr=new GenericParam__List;
//        Free($2);
      };

/*------------------[ End of General  Header section ]------------------*/

WWW_Authenticate:
    WWW_AUTHENTICATELWSCOLON wwwauthbody {};

wwwauthbody:
    LWS_0toN _DIGEST coma_authparam1_N {
        int idx;
        if(headerptr->wwwAuthenticate().ispresent()) 
          idx=headerptr->wwwAuthenticate()().challenge().size_of();
        else idx=0;
        headerptr->wwwAuthenticate()().challenge()[idx].digestCln()=*paramptr;
        paramcount=0;
        delete paramptr;
        paramptr=new GenericParam__List;
      }
    | LWS_0toN _TOKEN coma_authparam1_N {
        int idx;
        if(headerptr->wwwAuthenticate().ispresent()) 
          idx=headerptr->wwwAuthenticate()().challenge().size_of();
        else idx=0;
        headerptr->wwwAuthenticate()().challenge()[idx].otherChallenge().
                      authScheme()=$2;
        headerptr->wwwAuthenticate()().challenge()[idx].otherChallenge().
                      authParams()=*paramptr;
        paramcount=0;
        delete paramptr;
        paramptr=new GenericParam__List;
//        Free($2);
      };

Proxy_Authenticate:
    PROXY_AUTHENTICATELWSCOLON proxyauthbody {};

proxyauthbody:
    LWS_0toN _DIGEST coma_authparam1_N {
        int idx;
        if(headerptr->proxyAuthenticate().ispresent()) 
          idx=headerptr->proxyAuthenticate()().challenge().size_of();
        else idx=0;
        headerptr->proxyAuthenticate()().challenge()[idx].digestCln()=*paramptr;
        paramcount=0;
        delete paramptr;
        paramptr=new GenericParam__List;
      }
    | LWS_0toN _TOKEN coma_authparam1_N {
        int idx;
        if(headerptr->proxyAuthenticate().ispresent()) 
          idx=headerptr->proxyAuthenticate()().challenge().size_of();
        else idx=0;
        headerptr->proxyAuthenticate()().challenge()[idx].otherChallenge().
                authScheme()=$2;
        headerptr->proxyAuthenticate()().challenge()[idx].otherChallenge().
                authParams()=*paramptr;
        paramcount=0;
        delete paramptr;
        paramptr=new GenericParam__List;
//        Free($2);
      };


Toheader:
    TOLWSCOLON LWS_0toN display_name _ABO addr_spec _ABC
                semicolon_fromparam_1toN {
        headerptr->toField()().addressField().nameAddr().displayName() = $3;
        headerptr->toField()().addressField().nameAddr().addrSpec()= *uriptr;
        headerptr->toField()().toParams()=*paramptr;
        delete uriptr;
        uriptr= new SipUrl;
        urlparamcount=headercount=0;
        delete paramptr;
        paramptr= new GenericParam__List;
        paramcount=0;
//        Free($3);
      }
    | TOLWSCOLON LWS_0toN _ABO addr_spec _ABC semicolon_fromparam_1toN {
        headerptr->toField()().addressField().nameAddr().displayName()=OMIT_VALUE;
        headerptr->toField()().addressField().nameAddr().addrSpec()= *uriptr;
        headerptr->toField()().toParams()=*paramptr;
        delete uriptr;
        uriptr= new SipUrl;
        urlparamcount=headercount=0;
        delete paramptr;
        paramptr= new GenericParam__List;
        paramcount=0;
      }
    | TOLWSCOLON LWS_0toN addr_spec_withnoparam semicolon_fromparam_1toN {
        headerptr->toField()().addressField().addrSpecUnion()= *uriptr;
        headerptr->toField()().toParams()=*paramptr;
        delete uriptr;
        uriptr= new SipUrl;
        urlparamcount=headercount=0;
        delete paramptr;
        paramptr= new GenericParam__List;
        paramcount=0;
      }
    | TOLWSCOLON LWS_0toN display_name _ABO addr_spec _ABC {
        headerptr->toField()().addressField().nameAddr().displayName() = $3;
        headerptr->toField()().addressField().nameAddr().addrSpec()= *uriptr;
        headerptr->toField()().toParams()=OMIT_VALUE;
        delete uriptr;
        uriptr= new SipUrl;
        urlparamcount=headercount=0;
//        Free($3);
      }
    | TOLWSCOLON LWS_0toN _ABO addr_spec _ABC {
        headerptr->toField()().addressField().nameAddr().displayName()=OMIT_VALUE;
        headerptr->toField()().addressField().nameAddr().addrSpec()= *uriptr;
        headerptr->toField()().toParams()=OMIT_VALUE;
        delete uriptr;
        uriptr= new SipUrl;
        urlparamcount=headercount=0;
      }
    | TOLWSCOLON LWS_0toN addr_spec_withnoparam {
        headerptr->toField()().addressField().addrSpecUnion()= *uriptr;
        headerptr->toField()().toParams()=OMIT_VALUE;
        delete uriptr;
        uriptr= new SipUrl;
        urlparamcount=headercount=0;
      };

semicolon_toparam_1toN:
    SOMELWS_SEMICOLON from_param {}
    | semicolon_toparam_1toN SOMELWS_SEMICOLON from_param {};

Contact:
    CONTACTLWSCOLON LWS_0toN _STAR {
        headerptr->contact()().contactBody().wildcard()=$3;
//        Free($3);
      } 
    | CONTACTLWSCOLON contactbody1toN {};

contactbody1toN:
    contactadress {}
    | contactbody1toN SOMELWSCOMMA contactadress{};

contactadress:
    LWS_0toN display_name _ABO addr_spec _ABC semicolon_toparam_1toN {
        headerptr->contact()().contactBody().contactAddresses()[contactcount].
                    addressField().nameAddr().displayName()= $2;
        headerptr->contact()().contactBody().contactAddresses()[contactcount].
                    addressField().nameAddr().addrSpec()= *uriptr;
        headerptr->contact()().contactBody().contactAddresses()[contactcount].
                    contactParams()= *paramptr;
        contactcount++;
        delete uriptr;
        uriptr= new SipUrl;
        urlparamcount=headercount=0;
        delete paramptr;
        paramptr= new GenericParam__List;
        paramcount=0;
//        Free($2);
      }
    | LWS_0toN _ABO addr_spec _ABC semicolon_toparam_1toN {
        headerptr->contact()().contactBody().contactAddresses()[contactcount].
                    addressField().nameAddr().displayName()= OMIT_VALUE;
        headerptr->contact()().contactBody().contactAddresses()[contactcount].
                    addressField().nameAddr().addrSpec()= *uriptr;
        headerptr->contact()().contactBody().contactAddresses()[contactcount].
                    contactParams()= *paramptr;
        contactcount++;
        delete uriptr;
        uriptr= new SipUrl;
        urlparamcount=headercount=0;
        delete paramptr;
        paramptr= new GenericParam__List;
        paramcount=0;
      }
    | LWS_0toN addr_spec_withnoparam semicolon_toparam_1toN {
        headerptr->contact()().contactBody().contactAddresses()[contactcount].
                    addressField().addrSpecUnion()= *uriptr;
        headerptr->contact()().contactBody().contactAddresses()[contactcount].
                    contactParams()= *paramptr;
        contactcount++;
        delete uriptr;
        uriptr= new SipUrl;
        urlparamcount=headercount=0;
        delete paramptr;
        paramptr= new GenericParam__List;
        paramcount=0;
      }
    | LWS_0toN display_name _ABO addr_spec _ABC {
        headerptr->contact()().contactBody().contactAddresses()[contactcount].
                    addressField().nameAddr().displayName()= $2;
        headerptr->contact()().contactBody().contactAddresses()[contactcount].
                    addressField().nameAddr().addrSpec()= *uriptr;
        headerptr->contact()().contactBody().contactAddresses()[contactcount].
                    contactParams()= OMIT_VALUE;
        contactcount++;
//        Free($2);
        delete uriptr;
        uriptr= new SipUrl;
        urlparamcount=headercount=0;
      }
    | LWS_0toN _ABO addr_spec _ABC {
        headerptr->contact()().contactBody().contactAddresses()[contactcount].
                    addressField().nameAddr().displayName()= OMIT_VALUE;
        headerptr->contact()().contactBody().contactAddresses()[contactcount].
                    addressField().nameAddr().addrSpec()= *uriptr;
        headerptr->contact()().contactBody().contactAddresses()[contactcount].
                    contactParams()= OMIT_VALUE;
        contactcount++;
        delete uriptr;
        uriptr= new SipUrl;
        urlparamcount=headercount=0;
      }
    | LWS_0toN addr_spec_withnoparam {
        headerptr->contact()().contactBody().contactAddresses()[contactcount].
                    addressField().addrSpecUnion()= *uriptr;
        headerptr->contact()().contactBody().contactAddresses()[contactcount].
                    contactParams()= OMIT_VALUE;
        contactcount++;
        delete uriptr;
        uriptr= new SipUrl;
        urlparamcount=headercount=0;
      };

From:
    FROMLWSCOLON LWS_0toN display_name _ABO addr_spec _ABC 
                    semicolon_fromparam_1toN {
        headerptr->fromField()().addressField().nameAddr().displayName() = $3;
        headerptr->fromField()().addressField().nameAddr().addrSpec()= *uriptr;
        headerptr->fromField()().fromParams()=*paramptr;

        delete uriptr;
        uriptr= new SipUrl;
        urlparamcount=headercount=0;
        delete paramptr;
        paramptr= new GenericParam__List;
        paramcount=0;

//        Free($3);
      }
    | FROMLWSCOLON LWS_0toN _ABO addr_spec _ABC semicolon_fromparam_1toN {
        headerptr->fromField()().addressField().nameAddr().displayName() 
                    = OMIT_VALUE;
        headerptr->fromField()().addressField().nameAddr().addrSpec()= *uriptr;
        headerptr->fromField()().fromParams()=*paramptr;
        delete uriptr;
        uriptr= new SipUrl;
        urlparamcount=headercount=0;
        delete paramptr;
        paramptr= new GenericParam__List;
        paramcount=0;
      }
    | FROMLWSCOLON LWS_0toN addr_spec_withnoparam semicolon_fromparam_1toN {
        headerptr->fromField()().addressField().addrSpecUnion()= *uriptr;
        headerptr->fromField()().fromParams()=*paramptr;
        delete uriptr;
        uriptr= new SipUrl;
        urlparamcount=headercount=0;
        delete paramptr;
        paramptr= new GenericParam__List;
        paramcount=0;
      }
    | FROMLWSCOLON LWS_0toN display_name _ABO addr_spec _ABC {
        headerptr->fromField()().addressField().nameAddr().displayName() = $3;
        headerptr->fromField()().addressField().nameAddr().addrSpec()= *uriptr;
        headerptr->fromField()().fromParams()=OMIT_VALUE;
        delete uriptr;
        uriptr= new SipUrl;
        urlparamcount=headercount=0;
//        Free($3);
      }
    | FROMLWSCOLON LWS_0toN _ABO addr_spec _ABC {
        headerptr->fromField()().addressField().nameAddr().displayName()
                    = OMIT_VALUE;
        headerptr->fromField()().addressField().nameAddr().addrSpec()= *uriptr;
        headerptr->fromField()().fromParams()=OMIT_VALUE;
        delete uriptr;
        uriptr= new SipUrl;
        urlparamcount=headercount=0;
      }
    | FROMLWSCOLON LWS_0toN addr_spec_withnoparam {
        headerptr->fromField()().addressField().addrSpecUnion()= *uriptr;
        headerptr->fromField()().fromParams()=OMIT_VALUE;
        delete uriptr;
        uriptr= new SipUrl;
        urlparamcount=headercount=0;
      };

semicolon_fromparam_1toN:
    SOMELWS_SEMICOLON from_param {}
    | semicolon_fromparam_1toN SOMELWS_SEMICOLON from_param {};

from_param:
    SOMELWS _TOKEN SOMELWS equals_token_host_qtdstr {
        (*paramptr)[paramcount].id()=$2;
        (*paramptr)[paramcount].paramValue()=$4;
        paramcount++;
//        Free($2);Free($4);
      }
    | _TOKEN SOMELWS equals_token_host_qtdstr {
        (*paramptr)[paramcount].id()=$1;
        (*paramptr)[paramcount].paramValue()=$3;
        paramcount++;
//        Free($1);Free($3);
      }
    | SOMELWS from_param_withoutlws {}
    | from_param_withoutlws {};
    /*/last two cases also handle params without equal signs..!;)*/
    
    
from_param_withoutlws:
     _TOKEN equals_token_host_qtdstr {
        (*paramptr)[paramcount].id()=$1;
        (*paramptr)[paramcount].paramValue()=$2;
        paramcount++;
//        Free($1);
//        Free($2);
      }
    | _TOKEN {
        (*paramptr)[paramcount].id()=$1;
        (*paramptr)[paramcount].paramValue()=OMIT_VALUE;
        paramcount++;
//        Free($1);
      };

equals_token_host_qtdstr:
    EQUALSIGN SOMELWS token_or_host_or_quotedstring {$$=$3;}
    | EQUALSIGN token_or_host_or_quotedstring         {$$=$2;};

token_or_host_or_quotedstring: /* removes parantheses above */
    _TOKEN                            /*/default act*/
    | _HOST                            /*/default act*/
    | QUOTED_STRING;                    /*/default act*/

generic_param_withoutlws:    // used by url_param!
    _TOKEN equals_token_host_qtdstr_withoutlws {
        uriptr->urlParameters()()[urlparamcount].id()=$1;
        uriptr->urlParameters()()[urlparamcount].paramValue()=$2;
        urlparamcount++;
//        Free($1);Free($2);
      }
    | _TOKEN {
        uriptr->urlParameters()()[urlparamcount].id()=$1;
        uriptr->urlParameters()()[urlparamcount].paramValue()=OMIT_VALUE;
        urlparamcount++;
//        Free($1);
    };

equals_token_host_qtdstr_withoutlws:
    EQUALSIGN token_or_host_or_quotedstring {$$=$2;};

addr_spec_withnoparam:
    SIP_URL_withnoparam ;

SIP_URL_withnoparam:
    SCHEME userinfo_at_0to1 hostport {
        uriptr->scheme() = $1;
        uriptr->urlParameters() = OMIT_VALUE;
        uriptr->headers() = OMIT_VALUE;
        if(!strcasecmp($1,"tel")){
          if(!uriptr->userInfo().ispresent()){
            uriptr->userInfo()().userOrTelephoneSubscriber()=uriptr->hostPort().host()();
            uriptr->userInfo()().password()=OMIT_VALUE;
            uriptr->hostPort().host()=OMIT_VALUE;
          }
        }
        /*Free($1);*/
      };

display_name:
    TOKENS LWS_0toN                        /*/default act*/
    | _TOKEN LWS_0toN                    /*/default act*/
    | QUOTED_STRING LWS_0toN            ;    /*/default act*/

addr_spec:
    SIP_URL {};
SIP_URL:
    SCHEME userinfo_at_0to1 hostport semicolon_urlparam_1toN headers {
        uriptr->scheme() = $1;
        if(!strcasecmp($1,"tel")){
          if(!uriptr->userInfo().ispresent()){
            uriptr->userInfo()().userOrTelephoneSubscriber()=uriptr->hostPort().host()();
            uriptr->userInfo()().password()=OMIT_VALUE;
            uriptr->hostPort().host()=OMIT_VALUE;
          }
        }
        /*Free($1);*/
      }
    | SCHEME userinfo_at_0to1 hostport semicolon_urlparam_1toN {
        uriptr->scheme() = $1;
        uriptr->headers() = OMIT_VALUE;
        if(!strcasecmp($1,"tel")){
          if(!uriptr->userInfo().ispresent()){
            uriptr->userInfo()().userOrTelephoneSubscriber()=uriptr->hostPort().host()();
            uriptr->userInfo()().password()=OMIT_VALUE;
            uriptr->hostPort().host()=OMIT_VALUE;
          }
        }
        /*Free($1);*/
      }
    | SCHEME userinfo_at_0to1 hostport headers {
        uriptr->scheme() = $1;
        uriptr->urlParameters() = OMIT_VALUE;
        if(!strcasecmp($1,"tel")){
          if(!uriptr->userInfo().ispresent()){
            uriptr->userInfo()().userOrTelephoneSubscriber()=uriptr->hostPort().host()();
            uriptr->userInfo()().password()=OMIT_VALUE;
            uriptr->hostPort().host()=OMIT_VALUE;
          }
        }
        /*Free($1);*/
      }
    |SCHEME userinfo_at_0to1 hostport {
        uriptr->scheme() = $1;
        uriptr->urlParameters() = OMIT_VALUE;
        uriptr->headers() = OMIT_VALUE;
        if(!strcasecmp($1,"tel")){
          if(!uriptr->userInfo().ispresent()){
            uriptr->userInfo()().userOrTelephoneSubscriber()=uriptr->hostPort().host()();
            uriptr->userInfo()().password()=OMIT_VALUE;
            uriptr->hostPort().host()=OMIT_VALUE;
          }
        }
        /*Free($1);*/
      };


userinfo_at_0to1:
        /* empty */ { uriptr->userInfo() = OMIT_VALUE;}
        | USERINFO_AT {
        char* s=strchr($1,':');
        if(s==NULL){
          uriptr->userInfo()().password() = OMIT_VALUE;
          uriptr->userInfo()().userOrTelephoneSubscriber() = $1;
        }
        else{
          *s='\0';
          s++;
          uriptr->userInfo()().password() = s;
          uriptr->userInfo()().userOrTelephoneSubscriber() = $1;
        }
//        Free($1);
      };

hostport:
    _HOST colon_port_0to1 {
        uriptr->hostPort().host() = trimOnIPv6($1);
//        Free($1);
      };

colon_port_0to1:     
        /* empty */    {uriptr->hostPort().portField() = OMIT_VALUE;}
        | _COLON _PORT {uriptr->hostPort().portField() = $2;};

semicolon_urlparam_1toN:
          semicolon_urlparam
        | semicolon_urlparam_1toN semicolon_urlparam ;

semicolon_urlparam:
        SEMICOLON url_parameter {}
        |SOMELWS_SEMICOLON url_parameter {};

url_parameter:
    generic_param_withoutlws ;    

headers:
    QUESTMARK header amp_header_0toN {};

amp_header_0toN:
    /* empty */
    | amp_header_1toN ;

amp_header_1toN:
    amp_header
    | amp_header_1toN amp_header ;

amp_header:
    AMPERSANT header {};

header:
    _HNAME EQUALSIGN _HVALUE {
        uriptr->headers()()[headercount].id()=$1;
        uriptr->headers()()[headercount].paramValue()=$3;
        headercount++;
//        Free($1);Free($3);
      };                /*/ HVALUE IS NEVER OMITTED..!!*/
/*
message_body_0to1:
        */ /* empty */ /*        {  }
    | OCTETS        {  } ;
*/
%%
                    
/* Additional C code */
char *trim(char *string){

    /* trims leading blanks and removes line breaks*/

    char *j;
    int a=0;
    int b=0;
    j = string+strlen(string);
    //leading blanks
    while ((string[0] <= ' ') && (string[0] > 0) && (string < j)) string++; 
    while (string[a]){                                       // line breaks
        if((string[a]=='\n') || (string[a]=='\r')){
            while ((string[a] <= ' ') && (string[a] > 0) && (string[a])) a++;
            string[b]=' ';
            b++;
        }
        if(string[a]){
            string[b]=string[a];
            b++;
            a++;
        }
    }
    string[b]='\0';
    b--;
    //ending blanks
    while ((string[b] <= ' ') && (string[b] > 0) && (b)){string[b]='\0';b--;}
    return(string);
}

char *trimOnIPv6(char *str){
  if(ipv6enabled){
    if(str[0]=='['){
      str++;
      str[strlen(str)-1]='\0';
    }
  }
  return str;
}

void resetptr(){
    if(paramcount){
      delete paramptr;
      paramptr= new GenericParam__List;
      paramcount=0;
    }
    if(urlparamcount+headercount){
      delete uriptr;
      uriptr= new SipUrl;
      urlparamcount=headercount=0;
    }
}

extern char * getstream();

void parsing(const char* buff, int len, bool p_ipv6enabled){
  SIP_parse_lex_destroy();
  yy_buffer_state * flex_buffer = SIP_parse__scan_bytes (buff, len);
//  stream_buffer = getstream(); // EPTEBAL
  stream_buffer = (char *)Malloc((len*2+2)*sizeof(char)); // EPTEBAL
  if (flex_buffer == NULL) {
    TTCN_error("Flex buffer creation failed.");
  }
  ipv6enabled = p_ipv6enabled;
      SIP_parse_debug=0;
//      void resetptr();
      initcounters();
      SIP_parse_parse();  // also sets appropriate fields of msg through pointers..
        delete uriptr;
        uriptr=NULL;
        delete paramptr;
        paramptr=NULL;
  SIP_parse__delete_buffer(flex_buffer);
  Free(stream_buffer);
}
