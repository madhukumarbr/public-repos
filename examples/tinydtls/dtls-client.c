/*
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the Institute nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE INSTITUTE AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE INSTITUTE OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * This file is part of the Contiki operating system.
 *
 */

#include "contiki.h"
#include "contiki-lib.h"
#include "contiki-net.h"

#include "dev/serial-line.h"

#include <string.h>

#include "tinydtls.h"

#ifndef DEBUG
#define DEBUG DEBUG_PRINT
#endif
#include "net/uip-debug.h"

#include "debug.h"
#include "dtls.h"

#ifdef DTLS_PSK
/* The PSK information for DTLS */
/* make sure that default identity and key fit into buffer, i.e.
 * sizeof(PSK_DEFAULT_IDENTITY) - 1 <= PSK_ID_MAXLEN and
 * sizeof(PSK_DEFAULT_KEY) - 1 <= PSK_MAXLEN
*/

#define PSK_ID_MAXLEN 32
#define PSK_MAXLEN 32
#define PSK_DEFAULT_IDENTITY "Client_identity"
#define PSK_DEFAULT_KEY      "secretPSK"
#endif /* DTLS_PSK */

#define UIP_IP_BUF   ((struct uip_ip_hdr *)&uip_buf[UIP_LLH_LEN])
#define UIP_UDP_BUF  ((struct uip_udp_hdr *)&uip_buf[UIP_LLIPH_LEN])

#define MAX_PAYLOAD_LEN 120

static struct uip_udp_conn *client_conn;
static char buf[200];
static size_t buflen = 0;
dtls_context_t *dtls_context = NULL;

static void
try_send(struct dtls_context_t *ctx, session_t *dst) {
  int res;
  res = dtls_write(ctx, dst, (uint8 *)buf, buflen);
  if (res >= 0) {
    memmove(buf, buf + res, buflen - res);
    buflen -= res;
  }
}

static int
read_from_peer(struct dtls_context_t *ctx, 
	       session_t *session, uint8 *data, size_t len) {
  size_t i;
  for (i = 0; i < len; i++)
    PRINTF("%c", data[i]);
  return 0;
}

static int
send_to_peer(struct dtls_context_t *ctx, 
	     session_t *session, uint8 *data, size_t len) {

  struct uip_udp_conn *conn = (struct uip_udp_conn *)dtls_get_app_data(ctx);

  uip_ipaddr_copy(&conn->ripaddr, &session->addr);
  conn->rport = session->port;

  PRINTF("send to ");
  PRINT6ADDR(&conn->ripaddr);
  PRINTF(":%u\n", uip_ntohs(conn->rport));

  uip_udp_packet_send(conn, data, len);

  /* Restore server connection to allow data from any node */
  /* FIXME: do we want this at all? */
  memset(&conn->ripaddr, 0, sizeof(conn->ripaddr));
  memset(&conn->rport, 0, sizeof(conn->rport));

  return len;
}

#ifdef DTLS_PSK
static unsigned char psk_id[PSK_ID_MAXLEN] = PSK_DEFAULT_IDENTITY;
static size_t psk_id_length = sizeof(PSK_DEFAULT_IDENTITY) - 1;
static unsigned char psk_key[PSK_MAXLEN] = PSK_DEFAULT_KEY;
static size_t psk_key_length = sizeof(PSK_DEFAULT_KEY) - 1;

#ifdef __GNUC__
#define UNUSED_PARAM __attribute__((unused))
#else
#define UNUSED_PARAM
#endif /* __GNUC__ */

/* This function is the "key store" for tinyDTLS. It is called to
 * retrieve a key for the given identity within this particular
 * session. */
static int
get_psk_info(struct dtls_context_t *ctx UNUSED_PARAM,
	    const session_t *session UNUSED_PARAM,
	    dtls_credentials_type_t type,
	    const unsigned char *id, size_t id_len,
	    unsigned char *result, size_t result_length) {

  switch (type) {
  case DTLS_PSK_IDENTITY:
    if (result_length < psk_id_length) {
      dtls_warn("cannot set psk_identity -- buffer too small\n");
      return dtls_alert_fatal_create(DTLS_ALERT_INTERNAL_ERROR);
    }

    memcpy(result, psk_id, psk_id_length);
    return psk_id_length;
  case DTLS_PSK_KEY:
    if (id_len != psk_id_length || memcmp(psk_id, id, id_len) != 0) {
      dtls_warn("PSK for unknown id requested, exiting\n");
      return dtls_alert_fatal_create(DTLS_ALERT_ILLEGAL_PARAMETER);
    } else if (result_length < psk_key_length) {
      dtls_warn("cannot set psk -- buffer too small\n");
      return dtls_alert_fatal_create(DTLS_ALERT_INTERNAL_ERROR);
    }

    memcpy(result, psk_key, psk_key_length);
    return psk_key_length;
  default:
    dtls_warn("unsupported request type: %d\n", type);
  }

  return dtls_alert_fatal_create(DTLS_ALERT_INTERNAL_ERROR);
}
#endif /* DTLS_PSK */

PROCESS(rust_client_process, "RUST client process");
AUTOSTART_PROCESSES(&rust_client_process);

/*---------------------------------------------------------------------------*/
static void
dtls_handle_read(dtls_context_t *ctx) {
  static session_t session;

  if(uip_newdata()) {
    uip_ipaddr_copy(&session.addr, &UIP_IP_BUF->srcipaddr);
    session.port = UIP_UDP_BUF->srcport;
    session.size = sizeof(session.addr) + sizeof(session.port);

    ((char *)uip_appdata)[uip_datalen()] = 0;
    PRINTF("Client received message from ");
    PRINT6ADDR(&session.addr);
    PRINTF(":%d\n", uip_ntohs(session.port));

    dtls_handle_message(ctx, &session, uip_appdata, uip_datalen());
  }
}
/*---------------------------------------------------------------------------*/
void
print_local_addresses(void)
{
  int i;
  uint8_t state;
  PRINTF("Client IPv6 addresses: ");
  for(i = 0; i < UIP_DS6_ADDR_NB; i++) {
    state = uip_ds6_if.addr_list[i].state;
    if(uip_ds6_if.addr_list[i].isused &&
       (state == ADDR_TENTATIVE || state == ADDR_PREFERRED)) {
      PRINT6ADDR(&uip_ds6_if.addr_list[i].ipaddr);
      PRINTF("\n");
    }
  }
}

void
set_connection_address(uip_ipaddr_t *ipaddr)
{
#define _QUOTEME(x) #x
#define QUOTEME(x) _QUOTEME(x)
#ifdef UDP_CONNECTION_ADDR
  if(uiplib_ipaddrconv(QUOTEME(UDP_CONNECTION_ADDR), ipaddr) == 0) {
    PRINTF("UDP client failed to parse address '%s'\n", QUOTEME(UDP_CONNECTION_ADDR));
  }
#elif UIP_CONF_ROUTER
  uip_ip6addr(ipaddr,0xfe80,0,0,0,0x0201,0x0001,0x0001,0x0001);
#else
  uip_ip6addr(ipaddr,0xaaaa,0,0,0,0x0201,0x0001,0x0001,0x0001);
#endif /* UDP_CONNECTION_ADDR */
}
/*---------------------------------------------------------------------------*/
extern session_t dst;
extern uint8_t rust_init_dtls();
/*---------Wrappers from Rust to C------------------------------*/

uint8_t rust_uip_htons(int32_t port_num) {
	  return UIP_HTONS(port_num);
}

struct uip_udp_conn* rust_set_connection(session_t *dst)
{
  client_conn = udp_new(&dst->addr, 0, NULL);
  udp_bind(client_conn, dst->port);

  PRINTF("set connection address to ");
  PRINT6ADDR(&dst->addr);
  PRINTF(":%d\n", uip_ntohs(dst->port));
  return client_conn;
}

dtls_context_t * rust_dtls_new_context(struct uip_udp_conn* client_conn)
{
	  return (dtls_new_context(client_conn));
}
void rust_dtls_init(void)
{
  dtls_init();
}
void rust_serial_line_init(void)
{
  serial_line_init();
}
/*---------Wrappers from Rust to C------------------------------*/
/*---------------------------------------------------------------------------*/
PROCESS_THREAD(rust_client_process, ev, data)
{
  static int connected = 0;

  PROCESS_BEGIN();
  if (!rust_init_dtls())
  {
	printf("cannot create context\n");
    PROCESS_EXIT();
  }

  while(1) {
			PROCESS_YIELD();
			if(ev == tcpip_event) {
					dtls_handle_read(dtls_context);
			} else if (ev == serial_line_event_message) {
					register size_t len = min(strlen(data), sizeof(buf) - buflen);
					memcpy(buf + buflen, data, len);
					buflen += len;
					if (buflen < sizeof(buf) - 1)
					buf[buflen++] = '\n';	/* serial event does not contain LF */
					printf("Data to be sent from client: %s \n", data);
			} 
	

    if (buflen) {
      if (!connected)
	connected = dtls_connect(dtls_context, &dst) >= 0;
      
      try_send(dtls_context, &dst);
    }
  }
  
  PROCESS_END();
}
/*---------------------------------------------------------------------------*/
