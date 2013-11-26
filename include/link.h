/*
 *  link.h - definitions definitions for TCP control link
 *  (c) John Weber, rjohnweber@gmail.com
 * 
 *  This file is part of the GLIVE package.
 *
 *  Videodemo is free software: you can redistribute it and/or modify
 *  it under the terms of version 2 of GNU General Public License as 
 *  published by the Free Software Foundation.
 *
 *  Videodemo is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with the videodemo package.  If not, see 
 *  <http://www.gnu.org/licenses/>.
 */

#ifndef LINK_H_
#define LINK_H_

#include <stdint.h>

#define LINK_FRAME_DELIMITER   "VIDO"
#define LINK_PAYLOAD_SIZE 256
#define LINK_MSG_SIZE sizeof(link_message_t)
#define LINK_COMMAND_MIN_SIZE sizeof(link_msg_header_t)

#define LINK_CLIENT_CONNECTED 1
#define LINK_CLIENT_NOT_AVAIL 2
#define LINK_CLIENT_PENDING   3
#define LINK_CLIENT_NONE     -1

#define LINK_ERROR_NOT_ENOUGH  -10

typedef enum _link_msg_type_t {
	LINK_STATUS_REQUEST = 0x01,
	LINK_HEARTBEAT_REQUEST = 0x02,
	LINK_HEARTBEAT_ACK = 0x03,
	LINK_COMMAND_REQUEST = 0x04,
	LINK_COMMAND_ACK = 0x05,
	LINK_LOOPBACK_REQUEST = 0x06,
	LINK_LOOPBACK_ACK = 0x07,
	LINK_NONE = 0x99,
} link_msg_type_t;

/*
 * We have several types:
 * Status request:      Request from the client to server on the server status.
 *   (C => S)           Examples: Video uptime, bytes transmitted, frames transmitted
 *                      servo status and speed, CPU temperature, CPU load, battery
 *                      level, etc.
 * Heartbeat request:   Request from the server to the client to respond to a
 *   (S => C)           heartbeat message.  The purpose of this message is to determine
 *                      link existence as we are dealing with a wireless connection
 *                      which can fail at any time without warning.
 * Heartbeat ack:       Client acknowledge to a server's heartbeat message.  The server will
 *   (C => S)           transmits heartbeat messages periodically to determine the
 *                      status of the communications link.  The client is expected to
 *                      respond to this within a certain amount of time.
 * Command request:     Client requests that the server do certain things such as
 *   (C => S)           start a new video stream, stop a video stream, locally record
 *                      a video stream, provide control outputs, etc.
 * Command ack:         Server response to specific client command request.
 */

/*
 * Represents the status of the server
 */
typedef struct __attribute__((packed)) _link_status_t {
	/*  */
	int8_t dummy;
} link_status_t;

/*
 *  Link Message Structure
 */
typedef struct __attribute__((packed)) _link_msg_header_t {
	/* Frame delimiter */
	int8_t frame_delimiter[sizeof(LINK_FRAME_DELIMITER)];

	/* Message type */
	link_msg_type_t msgtype;

	/* Payload size */
	uint8_t size;

	/* Sequence number */
	uint32_t seqnum;

} link_msg_header_t;

/*
 *  Link Message Structure
 */
typedef struct __attribute__((packed)) _link_message_t {

	/* Header */
	link_msg_header_t header;

	/* Payload */
	uint8_t payload[LINK_PAYLOAD_SIZE];

} link_message_t;

/*
 * Prototypes
 */

int link_init_as_server(int port);
int link_init_as_client(char * server_ip_addr, int port);
int link_create_client(void);
int link_close_client(void);
int link_check_pending_client(void);
int link_recv(void);
int link_recv_msg(link_message_t *msg, int timeout_ms);
int link_process_msg(link_message_t *msg);
int link_start_server(void);
int link_stop_server(void);
int link_get_server_fd(void);
int link_get_client_fd(void);
char * link_get_remote_ip_addr(void);
int link_get_client_state(void);
int link_send_ping(void);
int link_send_ping_ack(void);
int link_send_msg(link_msg_type_t msgtype, uint8_t size, void *payload);
int link_random_loopback_test(void);
int link_send_msg_nopayload(link_msg_type_t msgtype);

#endif /* LINK_H_ */
