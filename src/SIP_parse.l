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
//  File:               SIP_parse.l
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

#include <string.h>
#include <strings.h>
#include <ctype.h>

#include "SIP_parse.h"                              //needed for re-definition of YY_INPUT !!
#include "SIPmsg_Types.hh"

#include "SIP_parse_.tab.h"
#include "memory.h"

using namespace SIPmsg__Types;
// Message pointers
extern RequestLine *rqlineptr;
extern StatusLine *stlineptr;
extern MessageHeader *headerptr;

extern int wildcarded_enabled_parser;

// header part pointers
SipUrl *uriptr=NULL;
GenericParam__List *paramptr=NULL;
OptionTag__List *optptr=NULL;
RouteBody__List *routeptr=NULL;

// parameter counters 
int paramcount;
int urlparamcount;
int headercount;
int optioncount;
int rcount;

// header counters
int acceptcount;
int aceptenccount;
int acceptlangcount;
int alertinfcount;
int allowcount;
int callinfocount;
int contactcount;
int contentenccount;
int contentlangcount;
int errorinfocount;
int featureCapscount;
int inreplytocount;
int passertedidcount;
int ppreferredidcount;
int privacycount;
int proxyreqcount;
int reasoncount;
int recroutecount;
int recvinfocount;
int routecount;
int reqcount;
int suppcount;
int unsuppcount;
int servercount;
int useragentcount;
int viacount;
int warncount;
int undefcount;
int erro_handling_sip_parser;
int aos_count;

extern char comment_buf[1500];

int num_chars = 0;
int pos_in_buf = 0;

int kovall =0;
int level=0;
int paramptrused=0;

void initcounters();
char* strupr(char* str);

char * stream_buffer; // EPTEBAL

void dump(char* buf, int len) {
  for (int i=0; i<len/8+1; i++) {
    int rowmax = 8;
    if (i == len/8) {
      rowmax = len%8;
    }
    for (int j=0; j<rowmax; j++) {
      if (j==4) printf(" ");
      printf("%2.2X ", buf[i*j]);
    }

    printf("    ");

    for (int k=0; k<rowmax; k++) {
      printf("%c", buf[i*k]);
    }
    printf("\n");
  }
}

%}

%option noyywrap
%option nounput
%x front 
%x generalcontent
%x requriversp

%x acceptst
%x acceptstencoding
%x acceptstlang
%x alertinfo
%x alertinfouri
%x allow
%x alloweventst
%x authinfo
%x authorization
%x callid
%x callinfo
%x callinfouri
%x contact
%x contactbeg
%x contentdisp
%x contentencoding
%x contentlang
%x contentlength
%x contenttype
%x cseq
%x datestate
%x errorinfo
%x errorinfouri
%x expires
%x eventst
%x eventparamst
%x fromfield
%x fromparam
%x inreplyto
%x maxforwards
%x minexpires
%x mimever
%x organization
%x pmeadiaauth
%x privacyst
%x proxyauthentication
%x proxyauthorization
%x proxyreq
%x rackst
%x rseqst
%x recroute
%x replyto
%x requirest
%x retryafter
%x routest
%x par
%x server
%x supportedst
%x timestamp
%x unsupportedst
%x useragent
%x warning
%x wauth
%x billinginfost
%x laesst
%x laessthost
%x laesst2
%x replacesst

%x tofield
%x uriwithparamscheme
%x uriwithparamusrtel
%x uriwithoutparamusrtel

%x uriwithparamcolpas
%x uriwithoutparamcolpas

%x uriwithparampasswd
%x uriwithoutparampasswd
%x uriwithparampassat
%x uriwithoutparampassat

%x uriwithparamhstprt
%x uriwithoutparamhstprt

%x uriwithparamcolprt
%x uriwithoutparamcolprt

%x uriwithparamport
%x uriwithoutparamport

%x uriparam
%x uriparamvalue

%x uriheadr
%x uriheadrhvalue

%x toparam

%x via1
%x via2
%x via3
%x via4
%x viaparam
%x viaport

%x requriver
%x statuscode

%x reasonsp
%x reason

%x pserviceindication
%x pservicenotification
%x geolocationerror
%x urn
%x urnwithparams
%x passertedservice
%x ppreferredservice
%x xaut
%x xcarrierinfo
%x xchgdelay
%x xfci

OCTET   [\000-\377]
CHAR    [\000-\177]
SP      [ ]
HT      [\t]
CR      [\r]
LF      [\n]
A       [Aa]
B       [Bb]
C       [Cc]
D       [Dd]
E       [Ee]
F       [Ff]
G       [Gg]
H       [Hh]
I       [Ii]
J       [Jj]
K       [Kk]
L       [Ll]
M       [Mm]
N       [Nn]
O       [Oo]
P       [Pp]
Q       [Qq]
R       [Rr]
S       [Ss]
T       [Tt]
U       [Uu]
V       [Vv]
W       [Ww]
X       [Xx]
Y       [Yy]
Z       [Zz]
DIGIT   [0-9]
COLON   [:]
BADID   [\000-\010\013-\014\016-\037\041-\071\073-\377]
ANLWS   (({SP}|{HT})*{CRLF}?({SP}|{HT})+)
NONLWS  [\000-\010\013-\014\016-\037\041-\377]
NONLWSA [\000-\010\013-\014\016-\037\041-\053\055-\377]
NONLWSB [\041-\075\077-\377]
NONLWSC [\041-\053\055-\377]
NONLWS_NONSC [\041-\053\055-\072\074-\377]
NONLWSD [\041-\047\052-\377]
NONLWSE [\041-\072\074-\377]
VER     {S}{I}{P}[/]{DIGIT}[.]{DIGIT}
SPHTVER {S}{I}{P}({SP}|{HT})*[/]({SP}|{HT})*{DIGIT}[.]{DIGIT}
TOKEN   ([[:alnum:]]|[-]|[.]|[!]|[%]|[\*]|[_]|[\+]|[`]|[']|[~])+
TOKEN_NO_DOT ([[:alnum:]]|[-]|[!]|[%]|[\*]|[_]|[\+]|[`]|[']|[~])+
TOKEN_ID ({NONLWSE})+
WTOKEN  ([A-Za-z])+

UTF8CON [\200-\277]
UTF8CO2 {UTF8CON}{UTF8CON}
UTF8CO3 {UTF8CO2}{UTF8CON}
UTF8CO4 {UTF8CO2}{UTF8CO2}
UTF8CO5 {UTF8CO3}{UTF8CO2}

XC0_DF  [\300-\337]
XE0_EF  [\340-\357]
XF0_F7  [\360-\367]
XF8_FB  [\370-\373]
XFC_FD  [\374\375]
U1      {XC0_DF}{UTF8CON}
U2      {XE0_EF}{UTF8CO2}
U3      {XF0_F7}{UTF8CO3}
U4      {XF8_FB}{UTF8CO4}
U5      {XFC_FD}{UTF8CO5}
UTF8NNA {U1}|{U2}|{U3}|{U4}|{U5}

UTF8WOE [\041-\176]|{UTF8NNA}|{SP}|{HT}

CRLF    {CR}{LF}
OLDCRLF {CR}|{LF}|({CR}{LF})
ANCRLF  {ANLWS}*{OLDCRLF}

QDTEXT  {ANLWS}|[\041]|[\043-\133]|[\135-\176]|{UTF8NNA}
QDPAIR  [\134][\000-\011\013-\014\016-\177]
QDSTR   [\042](({QDTEXT}|{QDPAIR})*)[\042]

HEX     [A-Fa-f]|{DIGIT}
AT      [@]

USERIN  ({USER}|[:])*{AT}

USER    ({UR}|{ESCAPED}|{USER_UR})*
USER_UR [&]|[=]|[\+]|[\$]|[,]|[;]|[\077]|[/]
UR      [[:alnum:]]|[-]|[_]|[.]|[!]|[~]]|[\*]|[']|[(]|[)]
ESCAPED [%]{HEX}{HEX}

HOST    ({HOSTNAM}|{IPVFOUR}|{IPVSIXR}|{TELURI})
TELURI  ([\+]?)(({TURICHR}|[(]{TURICHR})*)
TURICHR ({HEX}|[)]|[\*]|[-]|[.]|[#])

HOST2  ([\+]?)(({TURICHR2}|[(]{TURICHR2})*)
TURICHR2 ({HEX}|[)]|[\*]|[-]|[.]|[#]|[!]|[\]]|[\[])


USERIN2  ({USER2}|[:])*{AT}
USER2    {USER}|{USER_UR2}
USER_UR2  [\]]|[\[]

HOSTNAM (({DOMNLBL}[.])*){TOPLBL}([.]?)
DOMNLBL [[:alnum:]]|([[:alnum:]](([[:alnum:]]|[-])*)[[:alnum:]])
TOPLBL  [[:alpha:]]|([[:alnum:]](([[:alnum:]]|[-])*)[[:alnum:]])
IPVFOUR {DIGIT}{1,3}[.]{DIGIT}{1,3}[.]{DIGIT}{1,3}[.]{DIGIT}{1,3}
IPVSIXR [\133]{IPVSIXA}[\135]
IPVSIXA ({HEXPART}(({COLON}{IPVFOUR})?))|({COLON}{2}{IPVFOUR})
HEXPART {HEXSEQ}|{OTHRTWO}
OTHRTWO ({HEXSEQ}({COLON}{2})({HEXSEQ}?))|({COLON}{2}({HEXSEQ}?))
HEXSEQ  {HEXFOUR}(({COLON}{HEXFOUR})*)
HEXFOUR {HEX}{1,4}
URNDEF  ({URN_UR}|{UR}|{ESCAPED})({URN_R}|{UR}|{ESCAPED})*
URN_UR  [;]|[\077]|{COLON}|[@]|[&]|[=]|[\+]|[\$]|[,]
URN_R   [;]|[/]|[\077]|{COLON}|[@]|[&]|[=]|[\+]|[\$]|[,]
URNDEF2  ({URN_UR2}|{UR}|{ESCAPED})({URN_R2}|{UR}|{ESCAPED})*
URN_UR2  [\077]|{COLON}|[@]|[&]|[=]|[\+]|[\$]|[,]
URN_R2   [/]|[\077]|{COLON}|[@]|[&]|[=]|[\+]|[\$]|[,]

PORT    {DIGIT}*

PARAMCHAR ({P_UR}|{UR}|{ESCAPED})
P_UR    [\133]|[\135]|[/]|[&]|{COLON}|[\+]|[\$]

PNAME   {PARAMCHAR}*
PVALUE  {PARAMCHAR}*

HNAME   ({HNV_UR}|{UR}|{ESCAPED})+
HVALUE  ({HNV_UR}|{UR}|{ESCAPED})*
HNV_UR  [\133]|[\135]|[/]|[\077]|{COLON}|[\+]|[\$]

METHOD  ({I}{N}{V}{I}{T}{E})|({C}{A}{N}{C}{E}{L})|({O}{P}{T}{I}{O}{N}{S})|({R}{E}{G}{I}{S}{T}{E}{R})|({B}{Y}{E})|({A}{C}{K})|({I}{N}{F}{O})|({U}{P}{D}{A}{T}{E})|({P}{R}{A}{C}{K})|({P}{U}{B}{L}{I}{S}{H})|({S}{U}{B}{S}{C}{R}{I}{B}{E})|({N}{O}{T}{I}{F}{Y})|{EXT_MET}
EXT_MET {TOKEN}

PRTNAME ({S}{I}{P})|{TOKEN}
PRTVERS {TOKEN}
TRNSPRT ({U}{D}{P})|({T}{C}{P})|{TOKEN}

CTEXT   [\041-\047\052-\176]|{UTF8NNA}|{ANLWS}

%%

<INITIAL>{OLDCRLF}+                                                                     num_chars+=SIP_parse_leng;


<INITIAL>{METHOD}                                                                       {//{num_chars+=SIP_parse_leng;
                                                                                        //BEGIN(requriver); SIP_parse_lval.sv=(char*)Malloc((SIP_parse_leng+3)*sizeof(char)); strcpy(SIP_parse_lval.sv,strupr(SIP_parse_text));
                                                                                        //SIP_parse_lval.sv[SIP_parse_leng]='_';SIP_parse_lval.sv[SIP_parse_leng+1]='E';SIP_parse_lval.sv[SIP_parse_leng+2]='\0';
                                                                                        //rqlineptr = new RequestLine;
	  										///*initcounters();*/
                                                                                        //return _METHOD;}

											// New style
											num_chars+=SIP_parse_leng; 
											BEGIN(requriver);
											SIP_parse_lval.sv = stream_buffer; 
											pos_in_buf=SIP_parse_leng+3;
											strcpy(SIP_parse_lval.sv,strupr(SIP_parse_text));
											//dump(stream_buffer, 20);
											//printf("METHOD: %d, %p, %s, %s\n", pos_in_buf, stream_buffer, stream_buffer, SIP_parse_lval.sv);
                                                                                        SIP_parse_lval.sv[SIP_parse_leng]='_';SIP_parse_lval.sv[SIP_parse_leng+1]='E';SIP_parse_lval.sv[SIP_parse_leng+2]='\0';
                                                                                        rqlineptr = new RequestLine;
                                                                                        /*initcounters();*/
                                                                                        return _METHOD;}
<INITIAL>{SPHTVER}                                                                      {//num_chars+=SIP_parse_leng; BEGIN(statuscode); SIP_parse_lval.sv=(char *)Malloc(SIP_parse_leng+1); strcpy(SIP_parse_lval.sv,SIP_parse_text); stlineptr=new StatusLine; /*initcounters();*/return SIP_SPHT_VERSION;
											
											// New style
											num_chars+=SIP_parse_leng;
											BEGIN(statuscode);
											SIP_parse_lval.sv = stream_buffer;
											pos_in_buf=SIP_parse_leng+1;
                                                                                        strcpy(SIP_parse_lval.sv, SIP_parse_text); 
											//dump(stream_buffer, 20);
											//printf("SIP_SPHT_VERSION: %d, %p, %s, %s\n", pos_in_buf, stream_buffer, stream_buffer, SIP_parse_lval.sv);
											stlineptr=new StatusLine;
											/*initcounters();*/
											return SIP_SPHT_VERSION;}
<requriver>{VER}                                                                        {//num_chars+=SIP_parse_leng; SIP_parse_lval.sv=(char *)Malloc(SIP_parse_leng+1); strcpy(SIP_parse_lval.sv,SIP_parse_text);  return SIP_VERSION;

											// New style
											num_chars+=SIP_parse_leng;
											//SIP_parse_lval.sv=(char *)Malloc(SIP_parse_leng+1);
											SIP_parse_lval.sv=stream_buffer+pos_in_buf;
											pos_in_buf+=SIP_parse_leng+1;
											strcpy(SIP_parse_lval.sv,SIP_parse_text);
											//printf("SIP_VERSION: %d, %p, %s, %s\n", pos_in_buf, stream_buffer, stream_buffer, SIP_parse_lval.sv);
											return SIP_VERSION;}
<requriver>{TOKEN}{COLON}                                                               {//num_chars+=SIP_parse_leng; if(strcasecmp(SIP_parse_text,"tel:")){BEGIN(uriwithparamusrtel);} else {BEGIN(uriwithparamhstprt);} kovall=requriver; SIP_parse_lval.sv=(char *)Malloc(SIP_parse_leng+1); strcpy(SIP_parse_lval.sv,SIP_parse_text); SIP_parse_lval.sv[SIP_parse_leng-1]='\0'; return SCHEME;
											
											// New style
											num_chars+=SIP_parse_leng;
                      if(!strcasecmp(SIP_parse_text,"urn:")){
											  BEGIN(urn);
											} else if(strcasecmp(SIP_parse_text,"tel:")){
											  BEGIN(uriwithparamusrtel);
											} else {
											  BEGIN(uriwithparamhstprt);
											}


											kovall=requriver;
											
											SIP_parse_lval.sv=stream_buffer+pos_in_buf;
											pos_in_buf+=SIP_parse_leng+1;
											strcpy(SIP_parse_lval.sv,SIP_parse_text);
											SIP_parse_lval.sv[SIP_parse_leng-1]='\0';
											return SCHEME;}
<statuscode,requriver,warning>{SP}                                                      num_chars+=SIP_parse_leng; SIP_parse_lval.cv=SIP_parse_text[0]; return _SP;
<statuscode>{DIGIT}{3}                                                                  num_chars+=SIP_parse_leng; BEGIN(reasonsp); SIP_parse_lval.iv=atoi(SIP_parse_text); return EXTENSION_CODE;

<reasonsp>{SP}                                                                          num_chars+=SIP_parse_leng; BEGIN(reason); SIP_parse_lval.cv=SIP_parse_text[0]; return _SP;
<reason>{UTF8WOE}*                                                                      {//num_chars+=SIP_parse_leng; SIP_parse_lval.sv=(char *)Malloc(SIP_parse_leng+1); strcpy(SIP_parse_lval.sv,SIP_parse_text); return REASON_PHRASE;
											// New style
											num_chars+=SIP_parse_leng;
											SIP_parse_lval.sv=stream_buffer+pos_in_buf;
											pos_in_buf+=SIP_parse_leng+1;
											strcpy(SIP_parse_lval.sv,SIP_parse_text);
											return REASON_PHRASE;
											}

<generalcontent,organization>({ANLWS}|{NONLWS}|{SP}|{HT})+                              {//num_chars+=SIP_parse_leng; SIP_parse_lval.sv=(char *)Malloc(SIP_parse_leng+1); strcpy(SIP_parse_lval.sv,SIP_parse_text); return CONTENT_WITHOUTENDINGCRLF;
											// New style
											num_chars+=SIP_parse_leng;
											SIP_parse_lval.sv=stream_buffer+pos_in_buf;
											pos_in_buf+=SIP_parse_leng+1;
											strcpy(SIP_parse_lval.sv,SIP_parse_text);
											return CONTENT_WITHOUTENDINGCRLF;
											}
<acceptstencoding,contentencoding,contentlang>({ANLWS}|{NONLWSA}|{SP}|{HT})+            {//num_chars+=SIP_parse_leng; SIP_parse_lval.sv=(char *)Malloc(SIP_parse_leng+1); strcpy(SIP_parse_lval.sv,SIP_parse_text); return _STOKEN;
											// New style
											num_chars+=SIP_parse_leng; 
											SIP_parse_lval.sv=stream_buffer+pos_in_buf;
											pos_in_buf+=SIP_parse_leng+1;
											strcpy(SIP_parse_lval.sv,SIP_parse_text); 
											return _STOKEN;
											}
<acceptstencoding,contentencoding,contentlang,alloweventst>{ANLWS}*[,]                  num_chars+=SIP_parse_leng; return SOMELWSCOMMA;

<front>{CRLF}                                                                           num_chars+=SIP_parse_leng; BEGIN(INITIAL); return LONE_CRLF;

<via1,via2,via3,via4,viaparam,viaport,acceptst,acceptstencoding,acceptstlang>{ANCRLF}   num_chars+=SIP_parse_leng; BEGIN(front); return _CRLF;
<tofield,uriwithparamscheme,uriwithparamusrtel,urn,uriwithoutparamusrtel>{ANCRLF}           num_chars+=SIP_parse_leng; BEGIN(front); return _CRLF;
<uriwithparamcolpas,uriwithoutparamcolpas,alertinfo,allow,authinfo,callinfo>{ANCRLF}    num_chars+=SIP_parse_leng; BEGIN(front); return _CRLF;
<uriwithparampasswd,uriwithoutparampasswd,errorinfo,expires,minexpires>{ANCRLF}         num_chars+=SIP_parse_leng; BEGIN(front); return _CRLF;
<uriwithparampassat,uriwithoutparampassat,mimever,proxyreq,requirest,replacesst>{ANCRLF}           num_chars+=SIP_parse_leng; BEGIN(front); return _CRLF;
<uriwithparamhstprt,uriwithoutparamhstprt,server,supportedst,timestamp>{ANCRLF}         num_chars+=SIP_parse_leng; BEGIN(front); return _CRLF;
<uriwithparamcolprt,uriwithoutparamcolprt,unsupportedst,useragent,privacyst>{ANCRLF}    num_chars+=SIP_parse_leng; BEGIN(front); return _CRLF;
<uriwithparamport,uriwithoutparamport,warning,contact,contactbeg,eventst,alloweventst,eventparamst>{ANCRLF}       num_chars+=SIP_parse_leng; BEGIN(front); return _CRLF;
<uriparam,uriheadr,uriheadrhvalue,toparam,recroute,routest,replyto,billinginfost,xfci>{ANCRLF} num_chars+=SIP_parse_leng; BEGIN(front); return _CRLF;
<fromparam,contentencoding,contentlang,par,retryafter,rackst,rseqst>{ANCRLF}            num_chars+=SIP_parse_leng; BEGIN(front); return _CRLF;
<cseq,geolocationerror,contentlength,callid,contenttype,datestate,inreplyto,maxforwards>{ANCRLF}         num_chars+=SIP_parse_leng; BEGIN(front); return _CRLF;
<pserviceindication,pservicenotification,passertedservice,ppreferredservice>{ANCRLF}     num_chars+=SIP_parse_leng; BEGIN(front); return _CRLF;
<INITIAL,generalcontent,requriver,statuscode,reason,reasonsp,organization>{ANCRLF}      num_chars+=SIP_parse_leng; BEGIN(front); return _CRLF;
<xaut,xcarrierinfo,xchgdelay>{ANCRLF}                                                   num_chars+=SIP_parse_leng; BEGIN(front); return _CRLF;

<front>(({A}{C}{C}{E}{P}{T}[-]{C}{O}{N}{T}{A}{C}{T})|{A}){ANLWS}*{COLON}                num_chars+=SIP_parse_leng; BEGIN(fromparam); return ACCEPTCONTACTLWSCOLON;
<front>(({R}{E}{J}{E}{C}{T}[-]{C}{O}{N}{T}{A}{C}{T})|{J}){ANLWS}*{COLON}                num_chars+=SIP_parse_leng; BEGIN(fromparam); return REJECTCONTACTLWSCOLON;
<front>(({R}{E}{Q}{U}{E}{S}{T}[-]{D}{I}{S}{P}{O}{S}{I}{T}{I}{O}{N})|{D}){ANLWS}*{COLON} num_chars+=SIP_parse_leng; BEGIN(fromparam); return REQDISPLWSCOLON;
<front>(({R}{E}{F}{E}{R}[-]{T}{O})|{R}){ANLWS}*{COLON}                                  num_chars+=SIP_parse_leng; BEGIN(fromfield); return REFER_TOLWSCOLON;
<front>(({R}{E}{F}{E}{R}{R}{E}{D}[-]{B}{Y})|{B}){ANLWS}*{COLON}                         num_chars+=SIP_parse_leng; BEGIN(fromfield); return REFERREDBYTOLWSCOLON;
<front>(({F}{R}{O}{M})|{F}){ANLWS}*{COLON}                                              num_chars+=SIP_parse_leng; BEGIN(fromfield); return FROMLWSCOLON;
<fromfield>{QDSTR}                                                                      {//num_chars+=SIP_parse_leng; SIP_parse_lval.sv=(char *)Malloc(SIP_parse_leng+1); strcpy(SIP_parse_lval.sv,SIP_parse_text); return QUOTED_STRING;
											// New style
											num_chars+=SIP_parse_leng;
											SIP_parse_lval.sv=stream_buffer+pos_in_buf;
											pos_in_buf+=SIP_parse_leng+1;
											strcpy(SIP_parse_lval.sv,SIP_parse_text);
											return QUOTED_STRING;
											}
<fromfield>{TOKEN}(({ANLWS}*{TOKEN})*)                                                  {//num_chars+=SIP_parse_leng; SIP_parse_lval.sv=(char *)Malloc(SIP_parse_leng+1); strcpy(SIP_parse_lval.sv,SIP_parse_text); return TOKENS;
											// New style
											num_chars+=SIP_parse_leng;
											SIP_parse_lval.sv=stream_buffer+pos_in_buf;
											pos_in_buf+=SIP_parse_leng+1;
											strcpy(SIP_parse_lval.sv,SIP_parse_text);
											return TOKENS;
											}
<fromfield>[<]                                                                          num_chars+=SIP_parse_leng; SIP_parse_lval.cv=SIP_parse_text[0]; BEGIN(uriwithparamscheme);kovall=fromparam; return _ABO;
<fromfield>{TOKEN}{COLON}                                                               {//num_chars+=SIP_parse_leng; if(strcasecmp(SIP_parse_text,"tel:")){BEGIN(uriwithoutparamusrtel);} else {BEGIN(uriwithoutparamhstprt);};kovall=fromparam; SIP_parse_lval.sv=(char *)Malloc(SIP_parse_leng+1); strcpy(SIP_parse_lval.sv,SIP_parse_text); SIP_parse_lval.sv[SIP_parse_leng-1]='\0'; return SCHEME;
											// New style
											num_chars+=SIP_parse_leng;

                      if(!strcasecmp(SIP_parse_text,"urn:")){
											  BEGIN(urn);
											} else if(strcasecmp(SIP_parse_text,"tel:")){
											  BEGIN(uriwithoutparamusrtel);
											} else {
											  BEGIN(uriwithoutparamhstprt);
											}

											kovall=fromparam;
											
											SIP_parse_lval.sv=stream_buffer+pos_in_buf;
											pos_in_buf+=SIP_parse_leng+1;
											strcpy(SIP_parse_lval.sv,SIP_parse_text);
											SIP_parse_lval.sv[SIP_parse_leng-1]='\0';
											return SCHEME;}
											
<passertedservice,ppreferredservice>[u][r][n]{COLON}[u][r][n][-][7]{COLON}{TOKEN}       {num_chars+=SIP_parse_leng; 
                                                                                        SIP_parse_lval.sv=stream_buffer+pos_in_buf;
                                                                                        pos_in_buf+=SIP_parse_leng+1;
                                                                                        strcpy(SIP_parse_lval.sv,SIP_parse_text); 
                                                                                        return _TOKEN;
											}																									

<authorization,proxyauthentication,proxyauthorization,wauth>{D}{I}{G}{E}{S}{T}          num_chars+=SIP_parse_leng; return _DIGEST;


<authorization,proxyauthentication,proxyauthorization,wauth,authinfo,privacyst,pserviceindication,pservicenotification>{TOKEN}  {//num_chars+=SIP_parse_leng; SIP_parse_lval.sv=(char *)Malloc(SIP_parse_leng+1); strcpy(SIP_parse_lval.sv,SIP_parse_text); return _TOKEN;
											// New style
											num_chars+=SIP_parse_leng; 
											SIP_parse_lval.sv=stream_buffer+pos_in_buf;
											pos_in_buf+=SIP_parse_leng+1;
											strcpy(SIP_parse_lval.sv,SIP_parse_text); 
											return _TOKEN;
											}

<authorization,proxyauthentication,proxyauthorization,wauth,privacyst,eventst,alloweventst,eventparamst>{ANLWS}+  num_chars+=SIP_parse_leng;  return SOMELWS;
<authorization,proxyauthentication,proxyauthorization,wauth>[=]                         num_chars+=SIP_parse_leng; SIP_parse_lval.cv=SIP_parse_text[0]; return EQUALSIGN;
<authorization,proxyauthentication,proxyauthorization,wauth>{HOST}                      {//num_chars+=SIP_parse_leng; SIP_parse_lval.sv=(char *)Malloc(SIP_parse_leng+1); strcpy(SIP_parse_lval.sv,SIP_parse_text); return _HOST;
											// New style
											num_chars+=SIP_parse_leng; 
											SIP_parse_lval.sv=stream_buffer+pos_in_buf;
											pos_in_buf+=SIP_parse_leng+1;
											strcpy(SIP_parse_lval.sv,SIP_parse_text); 
											return _HOST;
											}

<authorization,proxyauthentication,proxyauthorization,wauth>{HOST2}                      {//num_chars+=SIP_parse_leng; SIP_parse_lval.sv=(char *)Malloc(SIP_parse_leng+1); strcpy(SIP_parse_lval.sv,SIP_parse_text); return _HOST;
											// New style
                      if(!wildcarded_enabled_parser){
                        num_chars+=SIP_parse_leng;
                        SIP_parse_lval.cv='!';
                        return '!';
                      }
											num_chars+=SIP_parse_leng; 
											SIP_parse_lval.sv=stream_buffer+pos_in_buf;
											pos_in_buf+=SIP_parse_leng+1;
											strcpy(SIP_parse_lval.sv,SIP_parse_text); 
											return _HOST;
											}


<authorization,proxyauthentication,proxyauthorization,wauth>{QDSTR}                     {//num_chars+=SIP_parse_leng; SIP_parse_lval.sv=(char *)Malloc(SIP_parse_leng+1); strcpy(SIP_parse_lval.sv,SIP_parse_text); return QUOTED_STRING;
											// New style
											num_chars+=SIP_parse_leng; 
											SIP_parse_lval.sv=stream_buffer+pos_in_buf;
											pos_in_buf+=SIP_parse_leng+1;
											strcpy(SIP_parse_lval.sv,SIP_parse_text); 
											return QUOTED_STRING;
											}

<authorization,proxyauthentication,proxyauthorization,wauth>{ANLWS}*[,]                 num_chars+=SIP_parse_leng; return SOMELWSCOMMA;
<authorization,proxyauthentication,proxyauthorization,wauth,pmeadiaauth>{ANCRLF}        num_chars+=SIP_parse_leng; BEGIN(front); return _CRLF;

<via1,via2,via3,via4,viaparam,viaport,acceptst,acceptstlang,alertinfo,authinfo,passertedservice,ppreferredservice>{ANLWS}+ num_chars+=SIP_parse_leng; return SOMELWS;
<toparam,tofield,fromparam,fromfield,geolocationerror,cseq,contentlength,callid,allow,callinfo>{ANLWS}+  num_chars+=SIP_parse_leng; return SOMELWS;
<proxyreq,requirest,retryafter,server,supportedst,timestamp,unsupportedst>{ANLWS}+      num_chars+=SIP_parse_leng; return SOMELWS;
<warning,contact,replyto,recroute,routest,contactbeg,useragent,rackst,rseqst>{ANLWS}+   num_chars+=SIP_parse_leng; return SOMELWS;
<viaparam,toparam,fromparam,acceptst,acceptstlang,alertinfo,callinfo>{ANLWS}*[;]        num_chars+=SIP_parse_leng; return SOMELWS_SEMICOLON;
<retryafter,privacyst>{ANLWS}*[;]                                                       num_chars+=SIP_parse_leng; return SOMELWS_SEMICOLON;
<viaparam,toparam,fromparam,acceptst,acceptstlang,alertinfo,callinfo,allow>{TOKEN}      {//num_chars+=SIP_parse_leng; SIP_parse_lval.sv=(char *)Malloc(SIP_parse_leng+1); strcpy(SIP_parse_lval.sv,SIP_parse_text); if (strcmp(SIP_parse_lval.sv,"*")){return _TOKEN;}  else {return _STAR;};
											// New style
											num_chars+=SIP_parse_leng; 
											SIP_parse_lval.sv=stream_buffer+pos_in_buf;
											pos_in_buf+=SIP_parse_leng+1;
											strcpy(SIP_parse_lval.sv,SIP_parse_text); 
											if (strcmp(SIP_parse_lval.sv,"*")){
											  return _TOKEN;
											} else {
											  return _STAR;
											}
											}

<viaparam,toparam,fromparam,acceptst,acceptstlang,alertinfo,callinfo,authinfo>[=]       num_chars+=SIP_parse_leng; SIP_parse_lval.cv=SIP_parse_text[0]; return EQUALSIGN;
<viaparam,toparam,fromparam,acceptst,acceptstlang,alertinfo,callinfo,authinfo>{HOST}    {//num_chars+=SIP_parse_leng; SIP_parse_lval.sv=(char *)Malloc(SIP_parse_leng+1); strcpy(SIP_parse_lval.sv,SIP_parse_text); return _HOST;
											// New style
											num_chars+=SIP_parse_leng; 
											SIP_parse_lval.sv=stream_buffer+pos_in_buf;
											pos_in_buf+=SIP_parse_leng+1;
											strcpy(SIP_parse_lval.sv,SIP_parse_text); 
											return _HOST;
											}
<viaparam>{IPVSIXA}    {//num_chars+=SIP_parse_leng; SIP_parse_lval.sv=(char *)Malloc(SIP_parse_leng+1); strcpy(SIP_parse_lval.sv,SIP_parse_text); return _HOST;
											// New style
											num_chars+=SIP_parse_leng; 
											SIP_parse_lval.sv=stream_buffer+pos_in_buf;
											pos_in_buf+=SIP_parse_leng+1;
											strcpy(SIP_parse_lval.sv,SIP_parse_text); 
											return _HOST;
											}
<viaparam,toparam,fromparam,acceptst,acceptstlang,alertinfo,callinfo,authinfo>{HOST2}    {//num_chars+=SIP_parse_leng; SIP_parse_lval.sv=(char *)Malloc(SIP_parse_leng+1); strcpy(SIP_parse_lval.sv,SIP_parse_text); return _HOST;
											// New style
                      if(!wildcarded_enabled_parser){
                        num_chars+=SIP_parse_leng;
                        SIP_parse_lval.cv='!';
                        return '!';
                      }
											num_chars+=SIP_parse_leng; 
											SIP_parse_lval.sv=stream_buffer+pos_in_buf;
											pos_in_buf+=SIP_parse_leng+1;
											strcpy(SIP_parse_lval.sv,SIP_parse_text); 
											return _HOST;
											}
<viaparam,toparam,fromparam,acceptst,acceptstlang,alertinfo,callinfo,authinfo>{QDSTR}   {//num_chars+=SIP_parse_leng; SIP_parse_lval.sv=(char *)Malloc(SIP_parse_leng+1); strcpy(SIP_parse_lval.sv,SIP_parse_text); return QUOTED_STRING;
											// New style
											num_chars+=SIP_parse_leng; 
											SIP_parse_lval.sv=stream_buffer+pos_in_buf;
											pos_in_buf+=SIP_parse_leng+1;
											strcpy(SIP_parse_lval.sv,SIP_parse_text); 
											return QUOTED_STRING;
											}
<acceptst,acceptstlang,alertinfo,callinfo,allow,authinfo,errorinfo,passertedservice,ppreferredservice>{ANLWS}*[,]          num_chars+=SIP_parse_leng; return SOMELWSCOMMA;
<proxyreq,requirest,supportedst,unsupportedst,warning,contact>{ANLWS}*[,]               num_chars+=SIP_parse_leng; return SOMELWSCOMMA;
<recroute,routest,inreplyto,contentdisp,fromparam,pmeadiaauth>{ANLWS}*[,]               num_chars+=SIP_parse_leng; return SOMELWSCOMMA;
<acceptst>[/]                                                                           num_chars+=SIP_parse_leng; SIP_parse_lval.cv=SIP_parse_text[0]; return _SLASH;

<server,useragent>{NONLWSD}+                                                            {//num_chars+=SIP_parse_leng; SIP_parse_lval.sv=(char *)Malloc(SIP_parse_leng+1); strcpy(SIP_parse_lval.sv,SIP_parse_text); return _TOKEN;
											// New style
											num_chars+=SIP_parse_leng; 
											SIP_parse_lval.sv=stream_buffer+pos_in_buf;
											pos_in_buf+=SIP_parse_leng+1;
											strcpy(SIP_parse_lval.sv,SIP_parse_text); 
											return _TOKEN;
											}

<callinfo>[<]                                                                           num_chars+=SIP_parse_leng; SIP_parse_lval.cv=SIP_parse_text[0]; BEGIN(callinfouri); return _ABO;
<callinfouri>{NONLWSB}*                                                                 {//num_chars+=SIP_parse_leng; SIP_parse_lval.sv=(char *)Malloc(SIP_parse_leng+1); strcpy(SIP_parse_lval.sv,SIP_parse_text); return _URLTOKEN;
											// New style
											num_chars+=SIP_parse_leng; 
											SIP_parse_lval.sv=stream_buffer+pos_in_buf;
											pos_in_buf+=SIP_parse_leng+1;
											strcpy(SIP_parse_lval.sv,SIP_parse_text); 
											return _URLTOKEN;
											}
<callinfouri>[>]                                                                        num_chars+=SIP_parse_leng; SIP_parse_lval.cv=SIP_parse_text[0]; BEGIN(callinfo); return _ABC;

<contentdisp,contenttype,datestate,pserviceindication,pservicenotification,errorinfo,expires,inreplyto,maxforwards,xaut,xcarrierinfo,xchgdelay>{ANLWS}+     num_chars+=SIP_parse_leng; return SOMELWS;
<contentdisp,errorinfo,eventparamst,contact,replyto,recroute,routest>{ANLWS}*[;]        num_chars+=SIP_parse_leng; return SOMELWS_SEMICOLON;
<eventst>{ANLWS}*[;]                          	      	      	      	      	      	num_chars+=SIP_parse_leng; BEGIN(eventparamst);return SOMELWS_SEMICOLON;
<contentdisp,eventparamst,errorinfo,expires,minexpires,proxyreq,requirest,retryafter,xaut,xcarrierinfo,xchgdelay>{TOKEN} {//num_chars+=SIP_parse_leng; SIP_parse_lval.sv=(char *)Malloc(SIP_parse_leng+1); strcpy(SIP_parse_lval.sv,SIP_parse_text); return _TOKEN;
												     // New style
												     num_chars+=SIP_parse_leng; 
												     SIP_parse_lval.sv=stream_buffer+pos_in_buf;
												     pos_in_buf+=SIP_parse_leng+1;
												     strcpy(SIP_parse_lval.sv,SIP_parse_text); 
												     return _TOKEN;
												     }

<warning>{PORT}                                                                         num_chars+=SIP_parse_leng;  SIP_parse_lval.iv=atoi(SIP_parse_text); return _PORT;
<supportedst,unsupportedst,warning,contact,replyto,recroute,routest>{TOKEN}             {//num_chars+=SIP_parse_leng; SIP_parse_lval.sv=(char *)Malloc(SIP_parse_leng+1); strcpy(SIP_parse_lval.sv,SIP_parse_text); return _TOKEN;
											// New style
											num_chars+=SIP_parse_leng; 
											SIP_parse_lval.sv=stream_buffer+pos_in_buf;
											pos_in_buf+=SIP_parse_leng+1;
											strcpy(SIP_parse_lval.sv,SIP_parse_text); 
											return _TOKEN;
											}
<contentdisp,eventparamst,errorinfo,retryafter,contact,replyto,recroute,routest>[=]                  num_chars+=SIP_parse_leng; SIP_parse_lval.cv=SIP_parse_text[0]; return EQUALSIGN;
<contentdisp,eventparamst,errorinfo,retryafter,contact,replyto,recroute,routest,warning>{HOST}       {//num_chars+=SIP_parse_leng; SIP_parse_lval.sv=(char *)Malloc(SIP_parse_leng+1); strcpy(SIP_parse_lval.sv,SIP_parse_text); return _HOST;
												     // New style
												     num_chars+=SIP_parse_leng; 
												     SIP_parse_lval.sv=stream_buffer+pos_in_buf;
												     pos_in_buf+=SIP_parse_leng+1;
												     strcpy(SIP_parse_lval.sv,SIP_parse_text); 
												     return _HOST;
												     }
<contentdisp,eventparamst,errorinfo,retryafter,contact,replyto,recroute,routest,warning>{HOST2}       {//num_chars+=SIP_parse_leng; SIP_parse_lval.sv=(char *)Malloc(SIP_parse_leng+1); strcpy(SIP_parse_lval.sv,SIP_parse_text); return _HOST;
												     // New style
                      if(!wildcarded_enabled_parser){
                        num_chars+=SIP_parse_leng;
                        SIP_parse_lval.cv='!';
                        return '!';
                      }
												     num_chars+=SIP_parse_leng; 
												     SIP_parse_lval.sv=stream_buffer+pos_in_buf;
												     pos_in_buf+=SIP_parse_leng+1;
												     strcpy(SIP_parse_lval.sv,SIP_parse_text); 
												     return _HOST;
												     }
<contentdisp,eventparamst,errorinfo,retryafter,recroute,routest,warning>{QDSTR}                      {//num_chars+=SIP_parse_leng; SIP_parse_lval.sv=(char *)Malloc(SIP_parse_leng+1); strcpy(SIP_parse_lval.sv,SIP_parse_text); return QUOTED_STRING;
												     // New style
												     num_chars+=SIP_parse_leng; 
												     SIP_parse_lval.sv=stream_buffer+pos_in_buf;
												     pos_in_buf+=SIP_parse_leng+1;
												     strcpy(SIP_parse_lval.sv,SIP_parse_text); 
												     return QUOTED_STRING;
												     }
<contentdisp>{ANCRLF}                                                                   num_chars+=SIP_parse_leng; BEGIN(front); return _CRLF;
<rackst>{WTOKEN}                                                                        {//num_chars+=SIP_parse_leng; SIP_parse_lval.sv=(char *)Malloc(SIP_parse_leng+1); strcpy(SIP_parse_lval.sv,SIP_parse_text); return _TOKEN;
											// New style
											num_chars+=SIP_parse_leng; 
											SIP_parse_lval.sv=stream_buffer+pos_in_buf;
											pos_in_buf+=SIP_parse_leng+1;
											strcpy(SIP_parse_lval.sv,SIP_parse_text); 
											return _TOKEN;
											}
<eventst,alloweventst>{ANLWS}*[.]                                                                    num_chars+=SIP_parse_leng; return _DOT;
<eventst,alloweventst>{TOKEN_NO_DOT}                                                                 {//num_chars+=SIP_parse_leng; SIP_parse_lval.sv=(char *)Malloc(SIP_parse_leng+1); strcpy(SIP_parse_lval.sv,SIP_parse_text); return _TOKEN_NO_DOT;
												     // New style
												     num_chars+=SIP_parse_leng; 
												     SIP_parse_lval.sv=stream_buffer+pos_in_buf;
												     pos_in_buf+=SIP_parse_leng+1;
												     strcpy(SIP_parse_lval.sv,SIP_parse_text); 
												     return _TOKEN_NO_DOT;
												     }

<retryafter>[(]                                                                         num_chars+=SIP_parse_leng; SIP_parse_lval.cv=SIP_parse_text[0]; BEGIN(par);kovall=retryafter;level=1; return SPARENT;
<server>[(]                                                                             num_chars+=SIP_parse_leng; SIP_parse_lval.cv=SIP_parse_text[0]; BEGIN(par);kovall=server;level=1; return SPARENT;
<useragent>[(]                                                                          num_chars+=SIP_parse_leng; SIP_parse_lval.cv=SIP_parse_text[0]; BEGIN(par);kovall=useragent;level=1; return SPARENT;

<par>({ANLWS}|{NONLWSD}|{SP}|{HT})+                                                     {//num_chars+=SIP_parse_leng; SIP_parse_lval.sv=(char *)Malloc(SIP_parse_leng+1); strcpy(SIP_parse_lval.sv,SIP_parse_text); return _COMMENT;
											// New style
											num_chars+=SIP_parse_leng; 
											SIP_parse_lval.sv=stream_buffer+pos_in_buf;
											pos_in_buf+=SIP_parse_leng+1;
											strcpy(SIP_parse_lval.sv,SIP_parse_text); 
											return _COMMENT;
											}
<par>[(]                                                                                {//num_chars+=SIP_parse_leng; SIP_parse_lval.sv=(char *)Malloc(SIP_parse_leng+1); strcpy(SIP_parse_lval.sv,SIP_parse_text); level++; return _COMMENT;
											// New style
											num_chars+=SIP_parse_leng; 
											SIP_parse_lval.sv=stream_buffer+pos_in_buf;
											pos_in_buf+=SIP_parse_leng+1;
											strcpy(SIP_parse_lval.sv,SIP_parse_text);
											level++;
											return _COMMENT;
											}
<par>[)]                                                                                {//num_chars+=SIP_parse_leng; level--;
                                                                                        //        if(!level) {BEGIN(kovall); SIP_parse_lval.cv=SIP_parse_text[0]; return EPARENT;}
                                                                                        //        else {SIP_parse_lval.sv=(char *)Malloc(SIP_parse_leng+1); strcpy(SIP_parse_lval.sv,SIP_parse_text); return _COMMENT;}
											
											// New style
											num_chars+=SIP_parse_leng; level--;
                                                                                        if(!level) {
											  BEGIN(kovall);
											  SIP_parse_lval.cv=SIP_parse_text[0];
											  return EPARENT;}
                                                                                        else {
											  SIP_parse_lval.sv=stream_buffer+pos_in_buf;
											  pos_in_buf+=SIP_parse_leng+1;
											  strcpy(SIP_parse_lval.sv,SIP_parse_text);
											  return _COMMENT;
											}
											}

<minexpires,pmeadiaauth,billinginfost,xfci>{ANLWS}+                                          num_chars+=SIP_parse_leng; return SOMELWS;
<billinginfost>{HEX}+                                                                   {//num_chars+=SIP_parse_leng; SIP_parse_lval.sv=(char *)Malloc(SIP_parse_leng+1); strcpy(SIP_parse_lval.sv,SIP_parse_text);return _HEXTOKEN;
											// New style
											num_chars+=SIP_parse_leng; 
											SIP_parse_lval.sv=stream_buffer+pos_in_buf;
											pos_in_buf+=SIP_parse_leng+1;
											strcpy(SIP_parse_lval.sv,SIP_parse_text); 
											return _HEXTOKEN;
											}
<xfci>{HEX}+                                                                            {
											num_chars+=SIP_parse_leng; 
											SIP_parse_lval.sv=stream_buffer+pos_in_buf;
											pos_in_buf+=SIP_parse_leng+1;
											strcpy(SIP_parse_lval.sv,SIP_parse_text); 
											return _HEXTOKEN;
											}                                                                                        
<pmeadiaauth>{HEX}+                                                                     {//num_chars+=SIP_parse_leng; SIP_parse_lval.sv=(char *)Malloc(SIP_parse_leng+1); strcpy(SIP_parse_lval.sv,SIP_parse_text);return _TOKEN;
											// New style
											num_chars+=SIP_parse_leng; 
											SIP_parse_lval.sv=stream_buffer+pos_in_buf;
											pos_in_buf+=SIP_parse_leng+1;
											strcpy(SIP_parse_lval.sv,SIP_parse_text); 
											return _TOKEN;
											}
<mimever,replacesst>{ANLWS}+                                                            num_chars+=SIP_parse_leng; return SOMELWS;
<mimever,timestamp>[.]                                                                  num_chars+=SIP_parse_leng; SIP_parse_lval.cv=SIP_parse_text[0]; return _DOT;

<alertinfo>[<]                                                                          num_chars+=SIP_parse_leng; SIP_parse_lval.cv=SIP_parse_text[0]; BEGIN(alertinfouri);kovall=fromparam; return _ABO;
<alertinfouri>{NONLWSB}*                                                                {//num_chars+=SIP_parse_leng; SIP_parse_lval.sv=(char *)Malloc(SIP_parse_leng+1); strcpy(SIP_parse_lval.sv,SIP_parse_text); return _URLTOKEN;
											// New style
											num_chars+=SIP_parse_leng; 
											SIP_parse_lval.sv=stream_buffer+pos_in_buf;
											pos_in_buf+=SIP_parse_leng+1;
											strcpy(SIP_parse_lval.sv,SIP_parse_text); 
											return _URLTOKEN;
											}
<alertinfouri>[>]                                                                       num_chars+=SIP_parse_leng; SIP_parse_lval.cv=SIP_parse_text[0]; BEGIN(alertinfo); return _ABC;

<errorinfo>[<]                                                                          num_chars+=SIP_parse_leng; SIP_parse_lval.cv=SIP_parse_text[0]; BEGIN(errorinfouri);kovall=fromparam; return _ABO;
<errorinfouri>{NONLWSB}*                                                                {//num_chars+=SIP_parse_leng; SIP_parse_lval.sv=(char *)Malloc(SIP_parse_leng+1); strcpy(SIP_parse_lval.sv,SIP_parse_text); return _URLTOKEN;
											// New style
											num_chars+=SIP_parse_leng; 
											SIP_parse_lval.sv=stream_buffer+pos_in_buf;
											pos_in_buf+=SIP_parse_leng+1;
											strcpy(SIP_parse_lval.sv,SIP_parse_text); 
											return _URLTOKEN;
											}
<errorinfouri>[>]                                                                       num_chars+=SIP_parse_leng; SIP_parse_lval.cv=SIP_parse_text[0]; BEGIN(errorinfo); return _ABC;

<front>(({T}{O})|{T}){ANLWS}*{COLON}                                                    num_chars+=SIP_parse_leng; BEGIN(tofield); return TOLWSCOLON;
<tofield,contact,replyto,contactbeg>{QDSTR}                                             {//num_chars+=SIP_parse_leng; SIP_parse_lval.sv=(char *)Malloc(SIP_parse_leng+1); strcpy(SIP_parse_lval.sv,SIP_parse_text); return QUOTED_STRING;
											// New style
											num_chars+=SIP_parse_leng; 
											SIP_parse_lval.sv=stream_buffer+pos_in_buf;
											pos_in_buf+=SIP_parse_leng+1;
											strcpy(SIP_parse_lval.sv,SIP_parse_text); 
											return QUOTED_STRING;
											}
<tofield,contact,replyto,recroute,routest>{TOKEN}(({ANLWS}*{TOKEN})*)                   {//num_chars+=SIP_parse_leng; SIP_parse_lval.sv=(char *)Malloc(SIP_parse_leng+1); strcpy(SIP_parse_lval.sv,SIP_parse_text); return TOKENS;
											// New style
											num_chars+=SIP_parse_leng; 
											SIP_parse_lval.sv=stream_buffer+pos_in_buf;
											pos_in_buf+=SIP_parse_leng+1;
											strcpy(SIP_parse_lval.sv,SIP_parse_text); 
											return TOKENS;
											}
<contactbeg>{TOKEN}(({ANLWS}*{TOKEN})*)                                                 {//num_chars+=SIP_parse_leng; SIP_parse_lval.sv=(char *)Malloc(SIP_parse_leng+1); strcpy(SIP_parse_lval.sv,SIP_parse_text); 
                                                                                        //if (strcmp(SIP_parse_lval.sv,"*")){return TOKENS;}
                                                                                        //else {return _STAR;}
											// New style
											num_chars+=SIP_parse_leng; 
											SIP_parse_lval.sv=stream_buffer+pos_in_buf;
											pos_in_buf+=SIP_parse_leng+1;
											strcpy(SIP_parse_lval.sv,SIP_parse_text); 
											if (strcmp(SIP_parse_lval.sv,"*")) { 
											  return TOKENS;
											} else {
											  return _STAR;
											}
											}

<tofield>[<]                                                                            num_chars+=SIP_parse_leng; SIP_parse_lval.cv=SIP_parse_text[0]; BEGIN(uriwithparamscheme); kovall=toparam; return _ABO;
<tofield>{TOKEN}{COLON}                                                                 {//num_chars+=SIP_parse_leng; if(strcasecmp(SIP_parse_text,"tel:")){BEGIN(uriwithoutparamusrtel);} else {BEGIN(uriwithoutparamhstprt);}; kovall=toparam; SIP_parse_lval.sv=(char *)Malloc(SIP_parse_leng+1); strcpy(SIP_parse_lval.sv,SIP_parse_text); SIP_parse_lval.sv[SIP_parse_leng-1]='\0'; return SCHEME;
											// New style
											num_chars+=SIP_parse_leng;

                      if(!strcasecmp(SIP_parse_text,"urn:")){
											  BEGIN(urn);
											} else if(strcasecmp(SIP_parse_text,"tel:")){
											  BEGIN(uriwithoutparamusrtel);
											} else {
											  BEGIN(uriwithoutparamhstprt);
											}


											kovall=toparam;
											
											SIP_parse_lval.sv=stream_buffer+pos_in_buf;
											pos_in_buf+=SIP_parse_leng+1;
											strcpy(SIP_parse_lval.sv,SIP_parse_text);
											SIP_parse_lval.sv[SIP_parse_leng-1]='\0';
											return SCHEME;											
											}

<contact,contactbeg>[<]                                                                 num_chars+=SIP_parse_leng; SIP_parse_lval.cv=SIP_parse_text[0]; BEGIN(uriwithparamscheme); kovall=contact; return _ABO;
<contact,contactbeg>{TOKEN}{COLON}                                                      {//num_chars+=SIP_parse_leng; if(strcasecmp(SIP_parse_text,"tel:")){BEGIN(uriwithoutparamusrtel);} else {BEGIN(uriwithoutparamhstprt);}; kovall=contact; SIP_parse_lval.sv=(char *)Malloc(SIP_parse_leng+1); strcpy(SIP_parse_lval.sv,SIP_parse_text); SIP_parse_lval.sv[SIP_parse_leng-1]='\0'; return SCHEME;
											// New style
											num_chars+=SIP_parse_leng;

                      if(!strcasecmp(SIP_parse_text,"urn:")){
											  BEGIN(urn);
											} else if(strcasecmp(SIP_parse_text,"tel:")){
											  BEGIN(uriwithoutparamusrtel);
											} else {
											  BEGIN(uriwithoutparamhstprt);
											}


											kovall=contact;
											
											SIP_parse_lval.sv=stream_buffer+pos_in_buf;
											pos_in_buf+=SIP_parse_leng+1;
											strcpy(SIP_parse_lval.sv,SIP_parse_text);
											SIP_parse_lval.sv[SIP_parse_leng-1]='\0';
											return SCHEME;											
											}

<recroute>[<]                                                                           num_chars+=SIP_parse_leng; SIP_parse_lval.cv=SIP_parse_text[0]; BEGIN(uriwithparamscheme); kovall=recroute; return _ABO;

<routest>[<]                                                                            num_chars+=SIP_parse_leng; SIP_parse_lval.cv=SIP_parse_text[0]; BEGIN(uriwithparamscheme); kovall=routest; return _ABO;

<replyto>[<]                                                                            num_chars+=SIP_parse_leng; SIP_parse_lval.cv=SIP_parse_text[0]; BEGIN(uriwithparamscheme); kovall=replyto; return _ABO;
<replyto>{TOKEN}{COLON}                                                                 {//num_chars+=SIP_parse_leng;if(strcasecmp(SIP_parse_text,"tel:")){BEGIN(uriwithoutparamusrtel);} else {BEGIN(uriwithoutparamhstprt);} kovall=replyto; SIP_parse_lval.sv=(char *)Malloc(SIP_parse_leng+1); strcpy(SIP_parse_lval.sv,SIP_parse_text); SIP_parse_lval.sv[SIP_parse_leng-1]='\0'; return SCHEME;
											// New style
											num_chars+=SIP_parse_leng;

                      if(!strcasecmp(SIP_parse_text,"urn:")){
											  BEGIN(urn);
											} else if(strcasecmp(SIP_parse_text,"tel:")){
											  BEGIN(uriwithoutparamusrtel);
											} else {
											  BEGIN(uriwithoutparamhstprt);
											}


											kovall=replyto;
											
											SIP_parse_lval.sv=stream_buffer+pos_in_buf;
											pos_in_buf+=SIP_parse_leng+1;
											strcpy(SIP_parse_lval.sv,SIP_parse_text);
											SIP_parse_lval.sv[SIP_parse_leng-1]='\0';
											return SCHEME;											
											}
<replacesst>{TOKEN_ID}                                                                  {//num_chars+=SIP_parse_leng; SIP_parse_lval.sv=(char *)Malloc(SIP_parse_leng+1); strcpy(SIP_parse_lval.sv,SIP_parse_text); return _CALLID;
											// New style
											num_chars+=SIP_parse_leng; 
											SIP_parse_lval.sv=stream_buffer+pos_in_buf;
											pos_in_buf+=SIP_parse_leng+1;
											strcpy(SIP_parse_lval.sv,SIP_parse_text); 
											return _CALLID;
											}


 /******************  SIP URI *****************/
<uriwithparamscheme>{TOKEN}{COLON}                                                      {//num_chars+=SIP_parse_leng; if(strcasecmp(SIP_parse_text,"tel:")){BEGIN(uriwithparamusrtel);} else {BEGIN(uriwithparamhstprt);}  SIP_parse_lval.sv=(char *)Malloc(SIP_parse_leng+1); strcpy(SIP_parse_lval.sv,SIP_parse_text); SIP_parse_lval.sv[SIP_parse_leng-1]='\0'; return SCHEME;
											// New style
											num_chars+=SIP_parse_leng;

                      if(!strcasecmp(SIP_parse_text,"urn:")){
											  BEGIN(urnwithparams);
											} else if(strcasecmp(SIP_parse_text,"tel:")){
											  BEGIN(uriwithparamusrtel);
											} else {
											  BEGIN(uriwithparamhstprt);
											}

											
											SIP_parse_lval.sv=stream_buffer+pos_in_buf;
											pos_in_buf+=SIP_parse_leng+1;
											strcpy(SIP_parse_lval.sv,SIP_parse_text);
											SIP_parse_lval.sv[SIP_parse_leng-1]='\0';
											return SCHEME;											
											}
<uriwithparamusrtel>{USERIN}                                                            {//num_chars+=SIP_parse_leng; BEGIN(uriwithparamhstprt); SIP_parse_lval.sv=(char *)Malloc(SIP_parse_leng+1); strcpy(SIP_parse_lval.sv,SIP_parse_text);SIP_parse_lval.sv[SIP_parse_leng-1]='\0'; return USERINFO_AT;
											// New style
											num_chars+=SIP_parse_leng;
											BEGIN(uriwithparamhstprt); 
											SIP_parse_lval.sv=stream_buffer+pos_in_buf;
											pos_in_buf+=SIP_parse_leng+1;
											strcpy(SIP_parse_lval.sv,SIP_parse_text); 
											SIP_parse_lval.sv[SIP_parse_leng-1]='\0';
											return USERINFO_AT;
											}
<uriwithparamusrtel>{USERIN2}                                                            {//num_chars+=SIP_parse_leng; BEGIN(uriwithparamhstprt); SIP_parse_lval.sv=(char *)Malloc(SIP_parse_leng+1); strcpy(SIP_parse_lval.sv,SIP_parse_text);SIP_parse_lval.sv[SIP_parse_leng-1]='\0'; return USERINFO_AT;
											// New style
                      if(!wildcarded_enabled_parser){
                        num_chars+=SIP_parse_leng;
                        SIP_parse_lval.cv='[';
                        return '[';
                      }
											num_chars+=SIP_parse_leng;
											BEGIN(uriwithparamhstprt); 
											SIP_parse_lval.sv=stream_buffer+pos_in_buf;
											pos_in_buf+=SIP_parse_leng+1;
											strcpy(SIP_parse_lval.sv,SIP_parse_text); 
											SIP_parse_lval.sv[SIP_parse_leng-1]='\0';
											return USERINFO_AT;
											}
<uriwithoutparamusrtel>{USERIN}                                                         {//num_chars+=SIP_parse_leng; BEGIN(uriwithoutparamhstprt); SIP_parse_lval.sv=(char *)Malloc(SIP_parse_leng+1); strcpy(SIP_parse_lval.sv,SIP_parse_text); SIP_parse_lval.sv[SIP_parse_leng-1]='\0';return USERINFO_AT;
											// New style
											num_chars+=SIP_parse_leng;
											BEGIN(uriwithoutparamhstprt); 
											SIP_parse_lval.sv=stream_buffer+pos_in_buf;
											pos_in_buf+=SIP_parse_leng+1;
											strcpy(SIP_parse_lval.sv,SIP_parse_text); 
											SIP_parse_lval.sv[SIP_parse_leng-1]='\0';
											return USERINFO_AT;
											}
<uriwithoutparamusrtel>{USERIN2}                                                         {//num_chars+=SIP_parse_leng; BEGIN(uriwithoutparamhstprt); SIP_parse_lval.sv=(char *)Malloc(SIP_parse_leng+1); strcpy(SIP_parse_lval.sv,SIP_parse_text); SIP_parse_lval.sv[SIP_parse_leng-1]='\0';return USERINFO_AT;
											// New style
                      if(!wildcarded_enabled_parser){
                        num_chars+=SIP_parse_leng;
                        SIP_parse_lval.cv='[';
                        return '[';
                      }
											num_chars+=SIP_parse_leng;
											BEGIN(uriwithoutparamhstprt); 
											SIP_parse_lval.sv=stream_buffer+pos_in_buf;
											pos_in_buf+=SIP_parse_leng+1;
											strcpy(SIP_parse_lval.sv,SIP_parse_text); 
											SIP_parse_lval.sv[SIP_parse_leng-1]='\0';
											return USERINFO_AT;
											}
<uriwithparamusrtel>([/]*){HOST}                                                        {//num_chars+=SIP_parse_leng; BEGIN(uriwithparamcolprt); SIP_parse_lval.sv=(char *)Malloc(SIP_parse_leng+1); strcpy(SIP_parse_lval.sv,SIP_parse_text); return _HOST;
											// New style
											num_chars+=SIP_parse_leng;
											BEGIN(uriwithparamcolprt); 
											SIP_parse_lval.sv=stream_buffer+pos_in_buf;
											pos_in_buf+=SIP_parse_leng+1;
											strcpy(SIP_parse_lval.sv,SIP_parse_text); 
											return _HOST;
											}
<uriwithparamusrtel>([/]*){HOST2}                                                        {//num_chars+=SIP_parse_leng; BEGIN(uriwithparamcolprt); SIP_parse_lval.sv=(char *)Malloc(SIP_parse_leng+1); strcpy(SIP_parse_lval.sv,SIP_parse_text); return _HOST;
											// New style
                      if(!wildcarded_enabled_parser){
                        num_chars+=SIP_parse_leng;
                        SIP_parse_lval.cv='!';
                        return '!';
                      }
											num_chars+=SIP_parse_leng;
											BEGIN(uriwithparamcolprt); 
											SIP_parse_lval.sv=stream_buffer+pos_in_buf;
											pos_in_buf+=SIP_parse_leng+1;
											strcpy(SIP_parse_lval.sv,SIP_parse_text); 
											return _HOST;
											}
<uriwithoutparamusrtel>([/]*){HOST}                                                     {//num_chars+=SIP_parse_leng; BEGIN(uriwithoutparamcolprt); SIP_parse_lval.sv=(char *)Malloc(SIP_parse_leng+1); strcpy(SIP_parse_lval.sv,SIP_parse_text); return _HOST;
											// New style
											num_chars+=SIP_parse_leng;
											BEGIN(uriwithoutparamcolprt); 
											SIP_parse_lval.sv=stream_buffer+pos_in_buf;
											pos_in_buf+=SIP_parse_leng+1;
											strcpy(SIP_parse_lval.sv,SIP_parse_text); 
											return _HOST;
											}
<uriwithoutparamusrtel>([/]*){HOST2}                                                     {//num_chars+=SIP_parse_leng; BEGIN(uriwithoutparamcolprt); SIP_parse_lval.sv=(char *)Malloc(SIP_parse_leng+1); strcpy(SIP_parse_lval.sv,SIP_parse_text); return _HOST;
											// New style
                      if(!wildcarded_enabled_parser){
                        num_chars+=SIP_parse_leng;
                        SIP_parse_lval.cv='!';
                        return '!';
                      }
											num_chars+=SIP_parse_leng;
											BEGIN(uriwithoutparamcolprt); 
											SIP_parse_lval.sv=stream_buffer+pos_in_buf;
											pos_in_buf+=SIP_parse_leng+1;
											strcpy(SIP_parse_lval.sv,SIP_parse_text); 
											return _HOST;
											}

<uriwithparamhstprt>([/]*){HOST}                                                        {//num_chars+=SIP_parse_leng; BEGIN(uriwithparamcolprt); SIP_parse_lval.sv=(char *)Malloc(SIP_parse_leng+1); strcpy(SIP_parse_lval.sv,SIP_parse_text); return _HOST;
											// New style
											num_chars+=SIP_parse_leng;
											BEGIN(uriwithparamcolprt); 
											SIP_parse_lval.sv=stream_buffer+pos_in_buf;
											pos_in_buf+=SIP_parse_leng+1;
											strcpy(SIP_parse_lval.sv,SIP_parse_text); 
											return _HOST;
											}
<uriwithparamhstprt>([/]*){HOST2}                                                        {//num_chars+=SIP_parse_leng; BEGIN(uriwithparamcolprt); SIP_parse_lval.sv=(char *)Malloc(SIP_parse_leng+1); strcpy(SIP_parse_lval.sv,SIP_parse_text); return _HOST;
											// New style
                      if(!wildcarded_enabled_parser){
                        num_chars+=SIP_parse_leng;
                        SIP_parse_lval.cv='!';
                        return '!';
                      }
											num_chars+=SIP_parse_leng;
											BEGIN(uriwithparamcolprt); 
											SIP_parse_lval.sv=stream_buffer+pos_in_buf;
											pos_in_buf+=SIP_parse_leng+1;
											strcpy(SIP_parse_lval.sv,SIP_parse_text); 
											return _HOST;
											}
<uriwithoutparamhstprt>([/]*){HOST}                                                     {//num_chars+=SIP_parse_leng; BEGIN(uriwithoutparamcolprt); SIP_parse_lval.sv=(char *)Malloc(SIP_parse_leng+1); strcpy(SIP_parse_lval.sv,SIP_parse_text); return _HOST;
											// New style
											num_chars+=SIP_parse_leng;
											BEGIN(uriwithoutparamcolprt); 
											SIP_parse_lval.sv=stream_buffer+pos_in_buf;
											pos_in_buf+=SIP_parse_leng+1;
											strcpy(SIP_parse_lval.sv,SIP_parse_text); 
											return _HOST;
											}
<urnwithparams>{URNDEF}         {
											// New style
											num_chars+=SIP_parse_leng;
											BEGIN(uriwithparamcolprt); 
											SIP_parse_lval.sv=stream_buffer+pos_in_buf;
											pos_in_buf+=SIP_parse_leng+1;
											strcpy(SIP_parse_lval.sv,SIP_parse_text); 
											return _HOST;
											}

<urn>{URNDEF2}         {
											// New style
											num_chars+=SIP_parse_leng;
											BEGIN(kovall); 
											SIP_parse_lval.sv=stream_buffer+pos_in_buf;
											pos_in_buf+=SIP_parse_leng+1;
											strcpy(SIP_parse_lval.sv,SIP_parse_text); 
											return _HOST;
											}
<uriwithoutparamhstprt>([/]*){HOST2}                                                     {//num_chars+=SIP_parse_leng; BEGIN(uriwithoutparamcolprt); SIP_parse_lval.sv=(char *)Malloc(SIP_parse_leng+1); strcpy(SIP_parse_lval.sv,SIP_parse_text); return _HOST;
											// New style
                      if(!wildcarded_enabled_parser){
                        num_chars+=SIP_parse_leng;
                        SIP_parse_lval.cv='!';
                        return '!';
                      }
											num_chars+=SIP_parse_leng;
											BEGIN(uriwithoutparamcolprt); 
											SIP_parse_lval.sv=stream_buffer+pos_in_buf;
											pos_in_buf+=SIP_parse_leng+1;
											strcpy(SIP_parse_lval.sv,SIP_parse_text); 
											return _HOST;
											}

<uriwithparamcolprt>{COLON}                                                             num_chars+=SIP_parse_leng; BEGIN(uriwithparamport); SIP_parse_lval.cv=SIP_parse_text[0]; return _COLON;
<uriwithoutparamcolprt>{COLON}                                                          num_chars+=SIP_parse_leng; BEGIN(uriwithoutparamport); SIP_parse_lval.cv=SIP_parse_text[0]; return _COLON;
<uriwithoutparamcolprt>{SP}                                                             num_chars+=SIP_parse_leng; BEGIN(kovall); return _SP;
<uriwithoutparamcolprt>{ANLWS}+                                                         num_chars+=SIP_parse_leng; BEGIN(kovall); return SOMELWS;
<uriwithoutparamcolprt>{ANLWS}*[,]                                                      num_chars+=SIP_parse_leng; BEGIN(kovall); return SOMELWSCOMMA;

<uriwithparamcolprt>[>]                                                                 num_chars+=SIP_parse_leng; SIP_parse_lval.cv=SIP_parse_text[0]; BEGIN(kovall); return _ABC;
<uriwithparamcolprt>[\042]                                                              num_chars+=SIP_parse_leng; SIP_parse_lval.cv=SIP_parse_text[0]; BEGIN(kovall); return _ABC;
<uriwithparamcolprt>{SP}                                                                num_chars+=SIP_parse_leng; SIP_parse_lval.cv=SIP_parse_text[0]; BEGIN(kovall); return _SP;
<uriwithparamcolprt>[;]                                                                 num_chars+=SIP_parse_leng; SIP_parse_lval.cv=SIP_parse_text[0]; BEGIN(uriparam);return SEMICOLON;
<uriwithparamcolprt>[\077]                                                              num_chars+=SIP_parse_leng; SIP_parse_lval.cv=SIP_parse_text[0]; BEGIN(uriheadr);  return QUESTMARK;
<uriwithoutparamcolprt>{ANLWS}*[;]                                                      num_chars+=SIP_parse_leng; BEGIN(kovall); return SOMELWS_SEMICOLON;

<uriwithparamport>{PORT}                                                                num_chars+=SIP_parse_leng; BEGIN(uriparam); SIP_parse_lval.iv=atoi(SIP_parse_text); return _PORT;
<uriwithoutparamport>{PORT}                                                             num_chars+=SIP_parse_leng; BEGIN(kovall);  SIP_parse_lval.iv=atoi(SIP_parse_text); return _PORT;

<uriparam>[>]                                                                           num_chars+=SIP_parse_leng; SIP_parse_lval.cv=SIP_parse_text[0]; BEGIN(kovall); return _ABC;
<uriparam>[\042]                                                                        num_chars+=SIP_parse_leng; SIP_parse_lval.cv=SIP_parse_text[0]; BEGIN(kovall); return _ABC;
<uriparam>{SP}                                                                          num_chars+=SIP_parse_leng; SIP_parse_lval.cv=SIP_parse_text[0]; BEGIN(kovall); return _SP;
<uriparam>[;]                                                                           num_chars+=SIP_parse_leng; SIP_parse_lval.cv=SIP_parse_text[0]; return SEMICOLON;
<uriparam>{TOKEN}                                                                       {//num_chars+=SIP_parse_leng; SIP_parse_lval.sv=(char *)Malloc(SIP_parse_leng+1); strcpy(SIP_parse_lval.sv,SIP_parse_text); return _TOKEN;
											// New style
											num_chars+=SIP_parse_leng;
											SIP_parse_lval.sv=stream_buffer+pos_in_buf;
											pos_in_buf+=SIP_parse_leng+1;
											strcpy(SIP_parse_lval.sv,SIP_parse_text); 
											return _TOKEN;
											}
<uriparam>{PNAME}                                                                       {//num_chars+=SIP_parse_leng; SIP_parse_lval.sv=(char *)Malloc(SIP_parse_leng+1); strcpy(SIP_parse_lval.sv,SIP_parse_text); return _TOKEN;
											// New style
											num_chars+=SIP_parse_leng;
											SIP_parse_lval.sv=stream_buffer+pos_in_buf;
											pos_in_buf+=SIP_parse_leng+1;
											strcpy(SIP_parse_lval.sv,SIP_parse_text); 
											return _TOKEN;
											}
<uriparam>[=]                                                                           num_chars+=SIP_parse_leng; BEGIN (uriparamvalue); SIP_parse_lval.cv=SIP_parse_text[0]; return EQUALSIGN;
<uriparamvalue>{PVALUE}                                                                  {//num_chars+=SIP_parse_leng;BEGIN (uriparam); SIP_parse_lval.sv=(char *)Malloc(SIP_parse_leng+1); strcpy(SIP_parse_lval.sv,SIP_parse_text); return _TOKEN;
											// New style
											num_chars+=SIP_parse_leng;
											BEGIN (uriparam);
											SIP_parse_lval.sv=stream_buffer+pos_in_buf;
											pos_in_buf+=SIP_parse_leng+1;
											strcpy(SIP_parse_lval.sv,SIP_parse_text); 
											return _TOKEN;
											}
<uriparamvalue>{HOST}                                                                   {//num_chars+=SIP_parse_leng;BEGIN (uriparam); SIP_parse_lval.sv=(char *)Malloc(SIP_parse_leng+1); strcpy(SIP_parse_lval.sv,SIP_parse_text); return _HOST;
											// New style
											num_chars+=SIP_parse_leng;
											BEGIN (uriparam);
											SIP_parse_lval.sv=stream_buffer+pos_in_buf;
											pos_in_buf+=SIP_parse_leng+1;
											strcpy(SIP_parse_lval.sv,SIP_parse_text); 
											return _HOST;
											}
<uriparamvalue>{HOST2}                                                                   {//num_chars+=SIP_parse_leng;BEGIN (uriparam); SIP_parse_lval.sv=(char *)Malloc(SIP_parse_leng+1); strcpy(SIP_parse_lval.sv,SIP_parse_text); return _HOST;
											// New style
                      if(!wildcarded_enabled_parser){
                        num_chars+=SIP_parse_leng;
                        SIP_parse_lval.cv='!';
                        return '!';
                      }
											num_chars+=SIP_parse_leng;
											BEGIN (uriparam);
											SIP_parse_lval.sv=stream_buffer+pos_in_buf;
											pos_in_buf+=SIP_parse_leng+1;
											strcpy(SIP_parse_lval.sv,SIP_parse_text); 
											return _HOST;
											}
<uriparamvalue>{QDSTR}                                                                  {//num_chars+=SIP_parse_leng;BEGIN (uriparam); SIP_parse_lval.sv=(char *)Malloc(SIP_parse_leng+1); strcpy(SIP_parse_lval.sv,SIP_parse_text); return QUOTED_STRING;
											// New style
											num_chars+=SIP_parse_leng;
											BEGIN (uriparam);
											SIP_parse_lval.sv=stream_buffer+pos_in_buf;
											pos_in_buf+=SIP_parse_leng+1;
											strcpy(SIP_parse_lval.sv,SIP_parse_text); 
											return QUOTED_STRING;
											}
<uriparam,uriparamvalue>[\077]                                                          num_chars+=SIP_parse_leng; SIP_parse_lval.cv=SIP_parse_text[0]; BEGIN(uriheadr);   return QUESTMARK;

<uriheadr>[>]                                                                           num_chars+=SIP_parse_leng; SIP_parse_lval.cv=SIP_parse_text[0]; BEGIN(kovall); return _ABC;
<uriheadr>[\042                                                                         num_chars+=SIP_parse_leng; SIP_parse_lval.cv=SIP_parse_text[0]; BEGIN(kovall); return _ABC;
<uriheadr>{SP}                                                                          num_chars+=SIP_parse_leng; SIP_parse_lval.cv=SIP_parse_text[0]; BEGIN(kovall); return _SP;
<uriheadr>[&]                                                                           num_chars+=SIP_parse_leng; SIP_parse_lval.cv=SIP_parse_text[0]; return AMPERSANT;
<uriheadr>{HNAME}                                                                       {//num_chars+=SIP_parse_leng; SIP_parse_lval.sv=(char *)Malloc(SIP_parse_leng+1); strcpy(SIP_parse_lval.sv,SIP_parse_text); return _HNAME;
											// New style
											num_chars+=SIP_parse_leng;
											SIP_parse_lval.sv=stream_buffer+pos_in_buf;
											pos_in_buf+=SIP_parse_leng+1;
											strcpy(SIP_parse_lval.sv,SIP_parse_text); 
											return _HNAME;
											}
<uriheadr>[=]                                                                           num_chars+=SIP_parse_leng; BEGIN (uriheadrhvalue); SIP_parse_lval.cv=SIP_parse_text[0]; return EQUALSIGN;
<uriheadrhvalue>{HVALUE}                                                                {//num_chars+=SIP_parse_leng; BEGIN(uriheadr); SIP_parse_lval.sv=(char *)Malloc(SIP_parse_leng+1); strcpy(SIP_parse_lval.sv,SIP_parse_text); return _HVALUE;
											// New style
											num_chars+=SIP_parse_leng;
											BEGIN(uriheadr);
											SIP_parse_lval.sv=stream_buffer+pos_in_buf;
											pos_in_buf+=SIP_parse_leng+1;
											strcpy(SIP_parse_lval.sv,SIP_parse_text); 
											return _HVALUE;
											}
 /***************** SIP URI end ***********/


<front>(({C}{O}{N}{T}{A}{C}{T})|{M}){ANLWS}*{COLON}                                     num_chars+=SIP_parse_leng; BEGIN(contactbeg); return CONTACTLWSCOLON;
<front>({P}[-]{A}{S}{2}{E}{R}{T}{E}{D}[-]{I}{D}{E}{N}{T}{I}{T}{Y}){ANLWS}*{COLON}       num_chars+=SIP_parse_leng; BEGIN(contactbeg); return PASSERTEDLWSCOLON;
<front>({P}[-]{P}{R}{E}{F}{E}{R}{2}{E}{D}[-]{I}{D}{E}{N}{T}{I}{T}{Y}){ANLWS}*{COLON}    num_chars+=SIP_parse_leng; BEGIN(contactbeg); return PPREFERREDLWSCOLON;

<front>({P}{R}{O}{X}{Y}[-]{A}{U}{T}{H}{E}{N}{T}{I}{C}{A}{T}{E}){ANLWS}*{COLON}          num_chars+=SIP_parse_leng; BEGIN(proxyauthentication); return PROXY_AUTHENTICATELWSCOLON;
<front>({W}{3}[-]{A}{U}{T}{H}{E}{N}{T}{I}{C}{A}{T}{E}){ANLWS}*{COLON}                   num_chars+=SIP_parse_leng; BEGIN(wauth); return WWW_AUTHENTICATELWSCOLON;

<front>(({C}{A}{L}{2}[-]{I}{D})|{I}){ANLWS}*{COLON}                                     num_chars+=SIP_parse_leng; BEGIN(callid); return CALL_IDLWSCOLON;




<callid,inreplyto>{NONLWS_NONSC}+                                                            {//num_chars+=SIP_parse_leng; SIP_parse_lval.sv=(char *)Malloc(SIP_parse_leng+1); strcpy(SIP_parse_lval.sv,SIP_parse_text); return _CALLID;
											// New style
											num_chars+=SIP_parse_leng;
											SIP_parse_lval.sv=stream_buffer+pos_in_buf;
											pos_in_buf+=SIP_parse_leng+1;
											strcpy(SIP_parse_lval.sv,SIP_parse_text); 
											return _CALLID;
											}

<callid>{ANLWS}*[;]                                                                     {
                                                                                        num_chars+=SIP_parse_leng; BEGIN(fromparam);return SOMELWS_SEMICOLON;}



<front>(({S}{U}{P}{2}{O}{R}{T}{E}{D})|{K}){ANLWS}*{COLON}                               {num_chars+=SIP_parse_leng; BEGIN(supportedst);
                                                                                        optioncount=suppcount;
                                                                                        if(optioncount){
                                                                                                optptr=&((OptionTag__List&)((Supported&)headerptr->supported()).optionsTags());
                                                                                        }
                                                                                        else{
                                                                                                optptr=new OptionTag__List;
                                                                                        }
                                                                                        return SUPPORTEDLWSCOLON;}
<front>(({V}{I}{A})|{V}){ANLWS}*{COLON}                                                 num_chars+=SIP_parse_leng; BEGIN(via1);  return VIALWSCOLON;
<via1>{PRTNAME}                                                                         {//num_chars+=SIP_parse_leng; BEGIN(via2); SIP_parse_lval.sv=(char *)Malloc(SIP_parse_leng+1); strcpy(SIP_parse_lval.sv,SIP_parse_text); return PROTOCOL_NAME;
											// New style
											num_chars+=SIP_parse_leng;
											BEGIN(via2);
											SIP_parse_lval.sv=stream_buffer+pos_in_buf;
											pos_in_buf+=SIP_parse_leng+1;
											strcpy(SIP_parse_lval.sv,SIP_parse_text); 
											return PROTOCOL_NAME;
											}
<via2>{PRTVERS}                                                                         {//num_chars+=SIP_parse_leng; BEGIN(via3); SIP_parse_lval.sv=(char *)Malloc(SIP_parse_leng+1); strcpy(SIP_parse_lval.sv,SIP_parse_text); return PROTOCOL_VERSION;
											// New style
											num_chars+=SIP_parse_leng;
											BEGIN(via3);
											SIP_parse_lval.sv=stream_buffer+pos_in_buf;
											pos_in_buf+=SIP_parse_leng+1;
											strcpy(SIP_parse_lval.sv,SIP_parse_text); 
											return PROTOCOL_VERSION;
											}
<via3>{TRNSPRT}                                                                         {//num_chars+=SIP_parse_leng; BEGIN(via4); SIP_parse_lval.sv=(char *)Malloc(SIP_parse_leng+1); strcpy(SIP_parse_lval.sv,SIP_parse_text); return TRANSPORT;
											// New style
											num_chars+=SIP_parse_leng;
											BEGIN(via4);
											SIP_parse_lval.sv=stream_buffer+pos_in_buf;
											pos_in_buf+=SIP_parse_leng+1;
											strcpy(SIP_parse_lval.sv,SIP_parse_text); 
											return TRANSPORT;
											}
<via4>{HOST}                                                                            {//num_chars+=SIP_parse_leng; BEGIN(via1); SIP_parse_lval.sv=(char *)Malloc(SIP_parse_leng+1); strcpy(SIP_parse_lval.sv,SIP_parse_text); return _HOST;
											// New style
											num_chars+=SIP_parse_leng;
											BEGIN(via1);
											SIP_parse_lval.sv=stream_buffer+pos_in_buf;
											pos_in_buf+=SIP_parse_leng+1;
											strcpy(SIP_parse_lval.sv,SIP_parse_text); 
											return _HOST;
											}
<via4>{HOST2}                                                                            {//num_chars+=SIP_parse_leng; BEGIN(via1); SIP_parse_lval.sv=(char *)Malloc(SIP_parse_leng+1); strcpy(SIP_parse_lval.sv,SIP_parse_text); return _HOST;
											// New style
                      if(!wildcarded_enabled_parser){
                        num_chars+=SIP_parse_leng;
                        SIP_parse_lval.cv='!';
                        return '!';
                      }
											num_chars+=SIP_parse_leng;
											BEGIN(via1);
											SIP_parse_lval.sv=stream_buffer+pos_in_buf;
											pos_in_buf+=SIP_parse_leng+1;
											strcpy(SIP_parse_lval.sv,SIP_parse_text); 
											return _HOST;
											}
<via1>{COLON}                                                                           num_chars+=SIP_parse_leng; BEGIN(viaport); return _COLON;
<viaport>{PORT}                                                                         num_chars+=SIP_parse_leng; BEGIN(via1); SIP_parse_lval.iv=atoi(SIP_parse_text); return _PORT;
<via1,viaparam>{ANLWS}*[,](({ANLWS}|[,])*)                                              num_chars+=SIP_parse_leng; BEGIN(via1); return SOMELWS_COMMA_SOMELWS;
<via2,via3,billinginfost>{ANLWS}*[/]({ANLWS}*)                                          num_chars+=SIP_parse_leng; SIP_parse_lval.cv='/'; return SOMELWS_SLASH_SOMELWS;
<billinginfost>{ANLWS}*{AT}({ANLWS}*)                                                   num_chars+=SIP_parse_leng; BEGIN(routest);return _AT;
<via1>{ANLWS}*[;]                                                                       num_chars+=SIP_parse_leng; BEGIN(viaparam); return SOMELWS_SEMICOLON;
<replacesst>{ANLWS}*[;]                                                                 num_chars+=SIP_parse_leng; BEGIN(fromparam); return SOMELWS_SEMICOLON;


<front>({P}[-]{D}{C}{S}[-]{L}{A}{E}{S}){ANLWS}*{COLON}                                  num_chars+=SIP_parse_leng; BEGIN(laessthost);return PLAESLWSCOLON;
<laesst>([c][o][n][t][e][n][t]){ANLWS}*[=]                                              num_chars+=SIP_parse_leng; BEGIN(laessthost); return _LAES_CONTENT;
<laessthost>{HOST}                                                                      {//num_chars+=SIP_parse_leng; SIP_parse_lval.sv=(char *)Malloc(SIP_parse_leng+1); strcpy(SIP_parse_lval.sv,SIP_parse_text); return _HOST;
											// New style
											num_chars+=SIP_parse_leng;
											SIP_parse_lval.sv=stream_buffer+pos_in_buf;
											pos_in_buf+=SIP_parse_leng+1;
											strcpy(SIP_parse_lval.sv,SIP_parse_text); 
											return _HOST;
											}
<laessthost>{HOST2}                                                                      {//num_chars+=SIP_parse_leng; SIP_parse_lval.sv=(char *)Malloc(SIP_parse_leng+1); strcpy(SIP_parse_lval.sv,SIP_parse_text); return _HOST;
											// New style
                      if(!wildcarded_enabled_parser){
                        num_chars+=SIP_parse_leng;
                        SIP_parse_lval.cv='!';
                        return '!';
                      }
											num_chars+=SIP_parse_leng;
											SIP_parse_lval.sv=stream_buffer+pos_in_buf;
											pos_in_buf+=SIP_parse_leng+1;
											strcpy(SIP_parse_lval.sv,SIP_parse_text); 
											return _HOST;
											}
<laessthost>{COLON}                                                                     num_chars+=SIP_parse_leng; BEGIN(laesst2); return _COLON;
<laesst2>{PORT}                                                                         num_chars+=SIP_parse_leng; BEGIN(laesst); SIP_parse_lval.iv=atoi(SIP_parse_text); return _PORT;
<laesst,laessthost>{ANLWS}*[;]                                                          num_chars+=SIP_parse_leng; BEGIN(laesst); return SOMELWS_SEMICOLON;
<laesst,laesst2,laessthost>{ANLWS}+                                                     num_chars+=SIP_parse_leng; return SOMELWS;
<laesst,laessthost>{ANCRLF}                                                             num_chars+=SIP_parse_leng; BEGIN(front); return _CRLF;
<laesst>{TOKEN}                                                                         {//num_chars+=SIP_parse_leng; SIP_parse_lval.sv=(char *)Malloc(SIP_parse_leng+1); strcpy(SIP_parse_lval.sv,SIP_parse_text); return _TOKEN;
											// New style
											num_chars+=SIP_parse_leng;
											SIP_parse_lval.sv=stream_buffer+pos_in_buf;
											pos_in_buf+=SIP_parse_leng+1;
											strcpy(SIP_parse_lval.sv,SIP_parse_text); 
											return _TOKEN;
											}
<laesst>[=]                                                                             num_chars+=SIP_parse_leng; SIP_parse_lval.cv=SIP_parse_text[0]; return EQUALSIGN;
<laesst>{QDSTR}                                                                         {//num_chars+=SIP_parse_leng; SIP_parse_lval.sv=(char *)Malloc(SIP_parse_leng+1); strcpy(SIP_parse_lval.sv,SIP_parse_text); return QUOTED_STRING;
											// New style
											num_chars+=SIP_parse_leng;
											SIP_parse_lval.sv=stream_buffer+pos_in_buf;
											pos_in_buf+=SIP_parse_leng+1;
											strcpy(SIP_parse_lval.sv,SIP_parse_text); 
											return QUOTED_STRING;
											}



<front>(({S}{U}{B}{J}{E}{C}{T})|{S}){ANLWS}*{COLON}                                     num_chars+=SIP_parse_leng; BEGIN(generalcontent); return SUBJECTLWSCOLON;
<front>(({C}{O}{N}{T}{E}{N}{T}[-]{E}{N}{C}{O}{D}{I}{N}{G})|{E}){ANLWS}*{COLON}          num_chars+=SIP_parse_leng; BEGIN(contentencoding); return CONTENT_ENCODINGLWSCOLON;
<front>(({C}{O}{N}{T}{E}{N}{T}[-]{L}{E}{N}{G}{T}{H})|{L}){ANLWS}*{COLON}                num_chars+=SIP_parse_leng; BEGIN(contentlength); return CONTENT_LENGTHLWSCOLON;
<contentlength,cseq,maxforwards,mimever,timestamp,rackst,rseqst>{DIGIT}+                {//num_chars+=SIP_parse_leng; SIP_parse_lval.sv=(char *)Malloc(SIP_parse_leng+1); strcpy(SIP_parse_lval.sv,SIP_parse_text); return SOMEDIGITS;
											// New style
											num_chars+=SIP_parse_leng;
											SIP_parse_lval.sv=stream_buffer+pos_in_buf;
											pos_in_buf+=SIP_parse_leng+1;
											strcpy(SIP_parse_lval.sv,SIP_parse_text); 
											return SOMEDIGITS;
											}
<geolocationerror>{DIGIT}+                {//num_chars+=SIP_parse_leng; SIP_parse_lval.sv=(char *)Malloc(SIP_parse_leng+1); strcpy(SIP_parse_lval.sv,SIP_parse_text); return SOMEDIGITS;
											// New style
											num_chars+=SIP_parse_leng;
											SIP_parse_lval.sv=stream_buffer+pos_in_buf;
											pos_in_buf+=SIP_parse_leng+1;
											strcpy(SIP_parse_lval.sv,SIP_parse_text);
                      BEGIN(fromparam);
											return SOMEDIGITS;
											}
<front>(({C}{O}{N}{T}{E}{N}{T}[-]{T}{Y}{P}{E})|{C}){ANLWS}*{COLON}                      num_chars+=SIP_parse_leng; BEGIN(contenttype); return CONTENT_TYPELWSCOLON;
<contenttype,datestate>({ANLWS}|{NONLWS}|{SP}|{HT})+                                    {//num_chars+=SIP_parse_leng; SIP_parse_lval.sv=(char *)Malloc(SIP_parse_leng+1); strcpy(SIP_parse_lval.sv,SIP_parse_text); return _TYPEID;
											// New style
											num_chars+=SIP_parse_leng;
											SIP_parse_lval.sv=stream_buffer+pos_in_buf;
											pos_in_buf+=SIP_parse_leng+1;
											strcpy(SIP_parse_lval.sv,SIP_parse_text); 
											return _TYPEID;
											}

<front>({A}{C}{2}{E}{P}{T}){ANLWS}*{COLON}                                              {num_chars+=SIP_parse_leng; BEGIN(acceptst); return ACCEPTLWSCOLON;}
<front>({A}{C}{2}{E}{P}{T}[-]{E}{N}{C}{O}{D}{I}{N}{G}){ANLWS}*{COLON}                   num_chars+=SIP_parse_leng; BEGIN(acceptstencoding); return ACCEPT_ENCODINGLWSCOLON;
<front>({A}{C}{2}{E}{P}{T}[-]{L}{A}{N}{G}{U}{A}{G}{E}){ANLWS}*{COLON}                   num_chars+=SIP_parse_leng; BEGIN(acceptstlang); return ACCEPT_LANGUAGELWSCOLON;
<front>({C}{A}{L}{2}[-]{I}{N}{F}{O}){ANLWS}*{COLON}                                     num_chars+=SIP_parse_leng; BEGIN(callinfo); return CALL_INFOLWSCOLON;
<front>({C}{S}{E}{Q}){ANLWS}*{COLON}                                                    num_chars+=SIP_parse_leng; BEGIN(cseq); return CSEQLWSCOLON;
<cseq>{METHOD}                                                                          {//num_chars+=SIP_parse_leng; SIP_parse_lval.sv=(char *)Malloc(SIP_parse_leng+1); strcpy(SIP_parse_lval.sv,SIP_parse_text); return _METHOD;
											// New style
											num_chars+=SIP_parse_leng;
											SIP_parse_lval.sv=stream_buffer+pos_in_buf;
											pos_in_buf+=SIP_parse_leng+1;
											strcpy(SIP_parse_lval.sv,SIP_parse_text); 
											return _METHOD;
											}
<front>({D}{A}{T}{E}){ANLWS}*{COLON}                                                    num_chars+=SIP_parse_leng; BEGIN(datestate); return DATELWSCOLON;

<front>({M}{I}{M}{E}[-]{V}{E}{R}{S}{I}{O}{N}){ANLWS}*{COLON}                            num_chars+=SIP_parse_leng; BEGIN(mimever); return MIME_VERSIONLWSCOLON;
<front>({O}{R}{G}{A}{N}{I}{Z}{A}{T}{I}{O}{N}){ANLWS}*{COLON}                            num_chars+=SIP_parse_leng; BEGIN(organization); return ORGANIZATIONLWSCOLON;
<front>({P}{R}{I}{V}{A}{C}{Y}){ANLWS}*{COLON}                                           num_chars+=SIP_parse_leng; BEGIN(privacyst); return PRIVACYLWSCOLON;
<front>({R}{E}{C}{O}{R}{D}[-]{R}{O}{U}{T}{E}){ANLWS}*{COLON}                            {num_chars+=SIP_parse_leng; BEGIN(recroute); 
                                                                                        rcount=recroutecount;
                                                                                        if(rcount){
                                                                                                routeptr=& headerptr->recordRoute()().routeBody();
                                                                                        }
                                                                                        else{
                                                                                                routeptr=new RouteBody__List;
                                                                                        }
                                                                                        return RECORD_ROUTELWSCOLON;}
<front>({R}{E}{Q}{U}{I}{R}{E}){ANLWS}*{COLON}                                           {num_chars+=SIP_parse_leng; BEGIN(requirest); 
                                                                                        optioncount=reqcount;
                                                                                        if(optioncount){
                                                                                                optptr=& headerptr->require()().optionsTags();
                                                                                        }
                                                                                        else{
                                                                                                optptr=new OptionTag__List;
                                                                                        }
                                                                                        return REQUIRELWSCOLON;}
<front>({T}{I}{M}{E}{S}{T}{A}{M}{P}){ANLWS}*{COLON}                                     num_chars+=SIP_parse_leng; BEGIN(timestamp); return TIMESTAMPLWSCOLON;
<front>({R}{A}{C}{K}){ANLWS}*{COLON}                                                    num_chars+=SIP_parse_leng; BEGIN(rackst); return RACKLWSCOLON;
<front>({R}{S}{E}{Q}){ANLWS}*{COLON}                                                    num_chars+=SIP_parse_leng; BEGIN(rseqst); return RSEQLWSCOLON;
<front>(({E}{V}{E}{N}{T})|{O}){ANLWS}*{COLON}                                           num_chars+=SIP_parse_leng; BEGIN(eventst); return EVENTLWSCOLON;
<front>({A}{C}{C}{E}{P}{T}[-]{R}{E}{S}{O}{U}{R}{C}{E}[-]{P}{R}{I}{O}{R}{I}{T}{Y}){ANLWS}*{COLON}                                           num_chars+=SIP_parse_leng; BEGIN(alloweventst); return ACCEPTRESPRIOLWSCOLON;
<front>({R}{E}{S}{O}{U}{R}{C}{E}[-]{P}{R}{I}{O}{R}{I}{T}{Y}){ANLWS}*{COLON}                                           num_chars+=SIP_parse_leng; BEGIN(alloweventst); return RESPRIOLWSCOLON;
<front>(({A}{L}{L}{O}{W}[-]{E}{V}{E}{N}{T}{S})|{U}){ANLWS}*{COLON}                      num_chars+=SIP_parse_leng; BEGIN(alloweventst); return ALLOWEVENTLWSCOLON;
<front>({U}{S}{E}{R}[-]{A}{G}{E}{N}{T}){ANLWS}*{COLON}                                  num_chars+=SIP_parse_leng; BEGIN(useragent); return USER_AGENTLWSCOLON;
<front>({E}{R}{2}{O}{R}[-]{I}{N}{F}{O}){ANLWS}*{COLON}                                  num_chars+=SIP_parse_leng; BEGIN(errorinfo); return ERROR_INFOLWSCOLON;
<front>({R}{E}{T}{R}{Y}[-]{A}{F}{T}{E}{R}){ANLWS}*{COLON}                               num_chars+=SIP_parse_leng; BEGIN(retryafter);level=0; return RETRY_AFTERLWSCOLON;
<front>({M}{I}{N}[-]{S}{E}){ANLWS}*{COLON}                                              num_chars+=SIP_parse_leng; BEGIN(retryafter); return MINSELWSCOLON;
<front>({S}{E}{C}{U}{R}{I}{T}{Y}[-]{C}{L}{I}{E}{N}{T}){ANLWS}*{COLON}                   num_chars+=SIP_parse_leng; BEGIN(routest); return SECCLIENTLWSCOLON;
<front>({S}{E}{C}{U}{R}{I}{T}{Y}[-]{S}{E}{R}{V}{E}{R}){ANLWS}*{COLON}                   num_chars+=SIP_parse_leng; BEGIN(routest); return SECSERVERLWSCOLON;
<front>({S}{E}{C}{U}{R}{I}{T}{Y}[-]{V}{E}{R}{I}{F}{Y}){ANLWS}*{COLON}                   num_chars+=SIP_parse_leng; BEGIN(routest); return SECVERIFYLWSCOLON;
<front>(({S}{E}{S}{S}{I}{O}{N}[-]{E}{X}{P}{I}{R}{E}{S})|({X})){ANLWS}*{COLON}           num_chars+=SIP_parse_leng; BEGIN(routest); return SESSIONEXPWSCOLON;
<front>({S}{E}{S}{S}{I}{O}{N}[-]{I}{D}){ANLWS}*{COLON}                                  num_chars+=SIP_parse_leng; BEGIN(routest); return SESSIONIDLWSCOLON;
<front>({S}{E}{R}{V}{E}{R}){ANLWS}*{COLON}                                              num_chars+=SIP_parse_leng; BEGIN(server); return SERVERLWSCOLON;
<front>({U}{N}{S}{U}{P}{2}{O}{R}{T}{E}{D}){ANLWS}*{COLON}                               {num_chars+=SIP_parse_leng; BEGIN(unsupportedst); 
                                                                                        optioncount=unsuppcount;
                                                                                        if(optioncount){
                                                                                                optptr=& headerptr->unsupported()().optionsTags();
                                                                                        }
                                                                                        else{
                                                                                                optptr=new OptionTag__List;
                                                                                        }
                                                                                        return UNSUPPORTEDLWSCOLON;}
<front>({W}{A}{R}{N}{I}{N}{G}){ANLWS}*{COLON}                                           num_chars+=SIP_parse_leng; BEGIN(warning); return WARNINGLWSCOLON;
<warning>{COLON}                                                                        num_chars+=SIP_parse_leng; return _COLON;
<front>({A}{L}{E}{R}{T}[-]{I}{N}{F}{O}){ANLWS}*{COLON}                                  num_chars+=SIP_parse_leng; BEGIN(alertinfo); return ALERT_INFOLWSCOLON;
<front>({A}{U}{T}{H}{O}{R}{I}{Z}{A}{T}{I}{O}{N}){ANLWS}*{COLON}                         num_chars+=SIP_parse_leng; BEGIN(authorization); return AUTHORIZATIONLWSCOLON;
<front>({A}{U}{T}{H}{E}{N}{T}{I}{C}{A}{T}{I}{O}{N}[-]{I}{N}{F}{O}){ANLWS}*{COLON}       num_chars+=SIP_parse_leng; BEGIN(authinfo); return AUTHINFOLWSCOLON;
<front>({I}{N}[-]{R}{E}{P}{L}{Y}[-]{T}{O}){ANLWS}*{COLON}                               num_chars+=SIP_parse_leng; BEGIN(inreplyto); return IN_REPLY_TOLWSCOLON;
<front>({R}{E}{P}{L}{Y}[-]{T}{O}){ANLWS}*{COLON}                                        num_chars+=SIP_parse_leng; BEGIN(replyto); return REPLY_TOLWSCOLON;
<front>({M}{A}{X}[-]{F}{O}{R}{W}{A}{R}{D}{S}){ANLWS}*{COLON}                            num_chars+=SIP_parse_leng; BEGIN(maxforwards); return MAX_FORWARDSLWSCOLON;
<front>({P}{R}{I}{O}{R}{I}{T}{Y}){ANLWS}*{COLON}                                        num_chars+=SIP_parse_leng; BEGIN(generalcontent); return PRIORITYLWSCOLON;
<front>({P}{R}{O}{X}{Y}[-]{A}{U}{T}{H}{O}{R}{I}{Z}{A}{T}{I}{O}{N}){ANLWS}*{COLON}       num_chars+=SIP_parse_leng; BEGIN(proxyauthorization); return PROXY_AUTHORIZATIONLWSCOLON;
<front>({P}{R}{O}{X}{Y}[-]{R}{E}{Q}{U}{I}{R}{E}){ANLWS}*{COLON}                         {num_chars+=SIP_parse_leng; BEGIN(proxyreq); 
                                                                                        optioncount=proxyreqcount;
                                                                                        if(optioncount){
                                                                                                optptr=& headerptr->proxyRequire()().optionsTags();
                                                                                        }
                                                                                        else{
                                                                                                optptr=new OptionTag__List;
                                                                                        }
                                                                                        return PROXY_REQUIRELWSCOLON;}
<front>({S}{I}{P}[-]{I}{F}[-]{M}{A}{T}{C}{H}){ANLWS}*{COLON}                            {num_chars+=SIP_parse_leng; BEGIN(routest);return IFMATCHLWSCOLON;}
<front>({S}{I}{P}[-]{E}{T}{A}{G}){ANLWS}*{COLON}                                        {num_chars+=SIP_parse_leng; BEGIN(routest);return ETAGLWSCOLON;}
<front>({R}{E}{P}{L}{A}{C}{E}{S}){ANLWS}*{COLON}                                        {num_chars+=SIP_parse_leng; BEGIN(replacesst);return REPLACESLWSCOLON;}
<front>({J}{O}{I}{N}){ANLWS}*{COLON}                                                    {num_chars+=SIP_parse_leng; BEGIN(replacesst);return JOINLWSCOLON;}
<front>({H}{I}{S}{T}{O}{R}{Y}[-]{I}{N}{F}{O}){ANLWS}*{COLON}                            {num_chars+=SIP_parse_leng; BEGIN(routest);return HISTORYLWSCOLON;}
<front>({P}[-]{D}{C}{S}[-]{B}{I}{L}{L}{I}{N}{G}[-]{I}{N}{F}{O}){ANLWS}*{COLON}          {num_chars+=SIP_parse_leng; BEGIN(billinginfost);return PBILLINGINFOLWSCOLON;}
<front>({P}[-]{E}{A}{R}{L}{Y}[-]{M}{E}{D}{I}{A}){ANLWS}*{COLON}                         {num_chars+=SIP_parse_leng; BEGIN(routest);return PEARLYMEDIALWSCOLON;}
<front>({P}[-]{D}{C}{S}[-]{O}{S}{P}{S}){ANLWS}*{COLON}                                  {num_chars+=SIP_parse_leng; BEGIN(routest);return POSPSLWSCOLON;}
<front>({P}[-]{D}{C}{S}[-]{R}{E}{D}{I}{R}{E}{C}{T}){ANLWS}*{COLON}{ANLWS}*[\042]        {num_chars+=SIP_parse_leng; BEGIN(uriwithparamscheme);kovall=routest;return PDCSREDIRLWSCOLON;}
<front>({P}[-]{U}{S}{E}{R}[-]{D}{A}{T}{A}{B}{A}{S}{E}){ANLWS}*{COLON}                   {num_chars+=SIP_parse_leng; BEGIN(routest);return PUSERDBASELWSCOLON;}
<front>({P}[-]{D}{C}{S}[-]{T}{R}{A}{C}{E}[-]{P}{A}{R}{T}{Y}[-]{I}{D}){ANLWS}*{COLON}    {num_chars+=SIP_parse_leng; BEGIN(routest);return PTARCEPTYIDLWSCOLON;}
<front>({P}[-]{A}{S}{S}{O}{C}{I}{A}{T}{E}{D}[-]{U}{R}{I}){ANLWS}*{COLON}                {num_chars+=SIP_parse_leng; BEGIN(routest);return PASSOCURILWSCOLON;}
<front>({G}{E}{O}{L}{O}{C}{A}{T}{I}{O}{N}){ANLWS}*{COLON}                               {num_chars+=SIP_parse_leng; BEGIN(routest);return GEOLOCATIONLWSCOLON;}
<front>({G}{E}{O}{L}{O}{C}{A}{T}{I}{O}{N}[-]{R}{O}{U}{T}{I}{N}{G}){ANLWS}*{COLON}       {num_chars+=SIP_parse_leng; BEGIN(fromparam);return GEOROUTINGLWSCOLON;}
<front>({G}{E}{O}{L}{O}{C}{A}{T}{I}{O}{N}[-]{E}{R}{R}{O}{R}){ANLWS}*{COLON}             {num_chars+=SIP_parse_leng; BEGIN(geolocationerror);return GEOLOCERRORLWSCOLON;}
<front>({P}[-]{C}{A}{L}{L}{E}{D}[-]{P}{A}{R}{T}{Y}[-]{I}{D}){ANLWS}*{COLON}             {num_chars+=SIP_parse_leng; BEGIN(routest);return PCALLEPPTYLWSCOLON;}
<front>({P}[-]{V}{I}{S}{I}{T}{E}{D}[-]{N}{E}{T}{W}{O}{R}{K}[-]{I}{D}){ANLWS}*{COLON}    {num_chars+=SIP_parse_leng; BEGIN(routest);return PVISITEDNETLWSCOLON;}
<front>({P}[-]{A}{C}{C}{E}{S}{S}[-]{N}{E}{T}{W}{O}{R}{K}[-]{I}{N}{F}{O}){ANLWS}*{COLON} {num_chars+=SIP_parse_leng; BEGIN(routest);return PACCESSNETLWSCOLON;}
<front>({A}{N}{S}{W}{E}{R}[-]{M}{O}{D}{E}){ANLWS}*{COLON}                               {num_chars+=SIP_parse_leng; BEGIN(routest);return ANSWERMODELWSCOLON;}
<front>({P}{R}{I}{V}[-]{A}{N}{S}{W}{E}{R}[-]{M}{O}{D}{E}){ANLWS}*{COLON}                {num_chars+=SIP_parse_leng; BEGIN(routest);return PRIVANSWERMODELWSCOLON;}
<front>({A}{L}{E}{R}{T}[-]{M}{O}{D}{E}){ANLWS}*{COLON}                                  {num_chars+=SIP_parse_leng; BEGIN(routest);return ALERTMODELWSCOLON;}
<front>({R}{E}{F}{E}{R}[-]{S}{U}{B}){ANLWS}*{COLON}                                     {num_chars+=SIP_parse_leng; BEGIN(routest);return REFERSUBLWSCOLON;}
<front>({P}[-]{A}{L}{E}{R}{T}{I}{N}{G}[-]{M}{O}{D}{E}){ANLWS}*{COLON}                   {num_chars+=SIP_parse_leng; BEGIN(routest);return PALERTINGMODELWSCOLON;}
<front>({P}[-]{A}{N}{S}{W}{E}{R}[-]{S}{T}{A}{T}{E}){ANLWS}*{COLON}                      {num_chars+=SIP_parse_leng; BEGIN(routest);return PANSWERSTATELWSCOLON;}
<front>({P}[-]{C}{H}{A}{R}{G}{I}{N}{G}[-]{F}{U}{N}{C}{T}{I}{O}{N}[-]{A}{D}{D}{R}{E}{S}{S}{E}{S}){ANLWS}*{COLON} {num_chars+=SIP_parse_leng; BEGIN(routest);return PCHARGEADDRLWSCOLON;}
<front>({P}[-]{C}{H}{A}{R}{G}{I}{N}{G}[-]{V}{E}{C}{T}{O}{R}){ANLWS}*{COLON}             {num_chars+=SIP_parse_leng; BEGIN(routest);return PCHARGEVECTORLWSCOLON;}
<front>({P}{A}{T}{H}){ANLWS}*{COLON}                                                    num_chars+=SIP_parse_leng; BEGIN(routest); return PATHLWSCOLON;
<front>({S}{E}{R}{V}{I}{C}{E}[-]{R}{O}{U}{T}{E}){ANLWS}*{COLON}                         num_chars+=SIP_parse_leng; BEGIN(routest); return SERVICEROUTELWSCOLON;
<front>({R}{O}{U}{T}{E}){ANLWS}*{COLON}                                                 {num_chars+=SIP_parse_leng; BEGIN(routest); 
                                                                                        rcount=routecount;
                                                                                        if(rcount){
                                                                                                routeptr=& headerptr->route()().routeBody();
                                                                                        }
                                                                                        else{
                                                                                                routeptr=new RouteBody__List;
                                                                                        }
                                                                                        return ROUTELWSCOLON;}
<front>({D}{I}{V}{E}{R}{S}{I}{O}{N}){ANLWS}*{COLON}                                     {num_chars+=SIP_parse_leng; BEGIN(routest);return DIVERSIONWSCOLON;}
<front>({A}{L}{2}{O}{W}){ANLWS}*{COLON}                                                 num_chars+=SIP_parse_leng; BEGIN(allow); return ALLOWLWSCOLON;
<front>({C}{O}{N}{T}{E}{N}{T}[-]{D}{I}{S}{P}{O}{S}{I}{T}{I}{O}{N}){ANLWS}*{COLON}       num_chars+=SIP_parse_leng; BEGIN(contentdisp); return CONTENT_DISPOSITIONLWSCOLON;
<front>({R}{E}{A}{S}{O}{N}){ANLWS}*{COLON}                                              num_chars+=SIP_parse_leng; BEGIN(contentdisp); return REASONLWSCOLON;
<front>({S}{U}{B}{S}{C}{R}{I}{P}{T}{I}{O}{N}[-]{S}{T}{A}{T}{E}){ANLWS}*{COLON}          num_chars+=SIP_parse_leng; BEGIN(contentdisp); return SUBSTATEWSCOLON;



<front>({T}{A}{R}{G}{E}{T}[-]{D}{I}{A}{L}{O}{G}){ANLWS}*{COLON}                         num_chars+=SIP_parse_leng; BEGIN(callid); return TARGETDIALOGLWSCOLON;
<front>(({F}{E}{A}{T}{U}{R}{E}[-]{C}{A}{P}{S}|{F}{C})){ANLWS}*{COLON}                   num_chars+=SIP_parse_leng; BEGIN(routest); return FEATURECAPSLWSCOLON;
<front>({I}{N}{F}{O}[-]{P}{A}{C}{K}{A}{G}{E}){ANLWS}*{COLON}                            num_chars+=SIP_parse_leng; BEGIN(contentdisp); return INFOPACKAGELWSCOLON;
<front>({R}{E}{C}{V}[-]{I}{N}{F}{O}){ANLWS}*{COLON}                                     num_chars+=SIP_parse_leng; BEGIN(acceptstlang); return RECVINFOLWSCOLON;

<front>({C}{O}{N}{T}{E}{N}{T}[-]{L}{A}{N}{G}{U}{A}{G}{E}){ANLWS}*{COLON}                num_chars+=SIP_parse_leng; BEGIN(contentlang); return CONTENT_LANGUAGELWSCOLON;
<front>({P}[-]{M}{E}{D}{I}{A}[-]{A}{U}{T}{H}{O}{R}{I}{Z}{A}{T}{I}{O}{N}){ANLWS}*{COLON} num_chars+=SIP_parse_leng; BEGIN(pmeadiaauth); return PMEDIAAUTHLWSCOLON;
<front>({E}{X}{P}{I}{R}{E}{S}){ANLWS}*{COLON}                                           num_chars+=SIP_parse_leng; BEGIN(expires); return EXPIRESLWSCOLON;
<front>({M}{I}{N}[-]{E}{X}{P}{I}{R}{E}{S}){ANLWS}*{COLON}                               num_chars+=SIP_parse_leng; BEGIN(minexpires); return MINEXPIRESLWSCOLON;
<front>({P}[-]{S}{E}{R}{V}{E}{D}[-]{U}{S}{E}{R}){ANLWS}*{COLON}                         num_chars+=SIP_parse_leng; BEGIN(fromfield); return PSERVEDUSERLWSCOLON;
<front>({P}[-]{P}{R}{O}{F}{I}{L}{E}[-]{K}{E}{Y}){ANLWS}*{COLON}                         num_chars+=SIP_parse_leng; BEGIN(fromfield); return PPROFILEKEYLWSCOLON;

<front>({P}[-]{S}{E}{R}{V}{I}{C}{E}[-]{I}{N}{D}{I}{C}{A}{T}{I}{O}{N}){ANLWS}*{COLON}    num_chars+=SIP_parse_leng; BEGIN(pserviceindication); return PSERVICEINDICATIONLWSCOLON;
<front>({P}[-]{S}{E}{R}{V}{I}{C}{E}[-]{N}{O}{T}{I}{F}{I}{C}{A}{T}{I}{O}{N}){ANLWS}*{COLON}    num_chars+=SIP_parse_leng; BEGIN(pservicenotification); return PSERVICENOTIFICATIONLWSCOLON;

<front>({P}[-]{A}{S}{S}{E}{R}{T}{E}{D}[-]{S}{E}{R}{V}{I}{C}{E}){ANLWS}*{COLON}           num_chars+=SIP_parse_leng; BEGIN(passertedservice);return PASSERTEDSERVICELWSCOLON;
<front>({P}[-]{P}{R}{E}{F}{E}{R}{R}{E}{D}[-]{S}{E}{R}{V}{I}{C}{E}){ANLWS}*{COLON}        num_chars+=SIP_parse_leng; BEGIN(ppreferredservice); return PPREFERREDSERVICELWSCOLON;

<front>({X}[-]{A}{U}{T}){ANLWS}*{COLON}                                                 num_chars+=SIP_parse_leng; BEGIN(xaut); return XAUTLWSCOLON;
<front>({X}[-]{C}{A}{R}{R}{I}{E}{R}[-]{I}{N}{F}{O}){ANLWS}*{COLON}                      num_chars+=SIP_parse_leng; BEGIN(xcarrierinfo); return XCARRIERINFOLWSCOLON;
<front>({X}[-]{C}{H}{G}{D}{E}{L}{A}{Y}){ANLWS}*{COLON}                                  num_chars+=SIP_parse_leng; BEGIN(xchgdelay); return XCHGDELAYLWSCOLON;
<front>({X}[-]{F}{C}{I}){ANLWS}*{COLON}                                                 num_chars+=SIP_parse_leng; BEGIN(xfci);return XFCILWSCOLON;

<front>({P}[-]{A}{R}{E}{A}[-]{I}{N}{F}{O}){ANLWS}*{COLON}                               num_chars+=SIP_parse_leng; BEGIN(routest); return PAREAINFOLWSCOLON;
<front>({X}[-]{C}{H}{G}{I}{N}{F}{O}){ANLWS}*{COLON}                                     num_chars+=SIP_parse_leng; BEGIN(routest); return XCHGINFOLWSCOLON;


<front>({BADID}*)({ANLWS}*){COLON}                                                      {//num_chars+=SIP_parse_leng; BEGIN(generalcontent); SIP_parse_lval.sv=(char *)Malloc(SIP_parse_leng+1); strcpy(SIP_parse_lval.sv,SIP_parse_text); SIP_parse_lval.sv[strlen(SIP_parse_lval.sv)-1]='\0'; return OTHERLWSCOLON;
											// New style
											num_chars+=SIP_parse_leng;
											BEGIN(generalcontent);
											SIP_parse_lval.sv=stream_buffer+pos_in_buf;
											pos_in_buf+=SIP_parse_leng+1;
											strcpy(SIP_parse_lval.sv,SIP_parse_text);
											SIP_parse_lval.sv[strlen(SIP_parse_lval.sv)-1]='\0'; 
											return OTHERLWSCOLON;
											}

<*>.                                                                                    num_chars+=SIP_parse_leng; SIP_parse_lval.cv=SIP_parse_text[0];  return SIP_parse_text[0];

<*><<EOF>>                                                                              BEGIN(INITIAL); yyterminate();

%%

#include "SIP_parse.h"

char myinput[BUF_SIZE];
const char *myinputptr;
const char *myinputlim;

int SIP_parse_error(const char *s)
{
        if (SIP_parse_text[0]=='\n'){
          switch(erro_handling_sip_parser){
            case 2:
              break;
            case 1:
              TTCN_warning("SIP Test Port:  %s \"\\n\" -> unexpected character at character position %i.",s,num_chars);
              break;
            default:
              TTCN_error("SIP Test Port:  %s \"\\n\" -> unexpected character at character position %i.",s,num_chars);
              break;
          }
        }  
        else if (SIP_parse_text[0]=='\r'){
          switch(erro_handling_sip_parser){
            case 2:
              break;
            case 1:
              TTCN_warning("SIP Test Port:  %s \"\\r\" -> unexpected character at character position %i.",s,num_chars);
              break;
            default:
              TTCN_error("SIP Test Port:  %s \"\\r\" -> unexpected character at character position %i.",s,num_chars);
              break;
          }
        } else{
          switch(erro_handling_sip_parser){
            case 2:
              break;
            case 1:
              TTCN_warning("SIP Test Port:  %s \"%s\" -> unexpected character at character position %i.",s,SIP_parse_text,num_chars);
              break;
            default:
              TTCN_error("SIP Test Port:  %s \"%s\" -> unexpected character at character position %i.",s,SIP_parse_text,num_chars);
              break;
          }
        }
        return 0;
}

/*int my_SIP_parse_input(char *buffer, int max_size)
        {
        int n = myinputlim - myinputptr;
        if(n>0)
                {
                memcpy(buffer, myinputptr, n);
                myinputptr += n;
                }
        return n;
        }
*/
void initcounters(){
        acceptcount=0;
        aceptenccount=0;
        acceptlangcount=0;
        alertinfcount=0;
        allowcount=0;
        callinfocount=0;
        contactcount=0;
        contentenccount=0;
        contentlangcount=0;
        errorinfocount=0;
	featureCapscount=0;
        inreplytocount=0;
        passertedidcount=0;
        ppreferredidcount=0;
        privacycount=0;
        proxyreqcount=0;
        reasoncount=0;
        recroutecount=0;
	recvinfocount=0;
        routecount=0;
        reqcount=0;
        suppcount=0;
        unsuppcount=0;
        servercount=0;
        useragentcount=0;
        viacount=0;
        warncount=0;
        undefcount=0;
        comment_buf[0]=comment_buf[1]='\0';
        rcount=optioncount=paramcount=urlparamcount=headercount=0;
        
        delete paramptr;
        paramptr = new GenericParam__List;
        delete uriptr;
        uriptr=new SipUrl;
}

char* strupr(char* str){
        int a=0;
        while(str[a]){str[a]=toupper(str[a]);a++;}
        return str;
}

//char * getstream() {
//    return YY_CURRENT_BUFFER_LVALUE->yy_ch_buf;
//} /* EPTEBAL */
