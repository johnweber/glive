/*
 *  link.c - TCP control link for videodemo
 *  (c) John Weber, rjohnweber@gmail.com
 *  Avnet Electronics Marketing
 * 
 *  This file is part of the videodemo package.
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

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "common.h"
#include "link.h"
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>  	/*  inet (3) funtions         */
#include <poll.h>			/* For poll() */
#include <fcntl.h>			/* For open() */
#include <unistd.h>   		/* For read() */
#include <ctype.h>    		/* For toupper() */
#include <errno.h>			/* For errno */
#include <time.h>			/* For time functions */

const char link_frame_delimiter[] = LINK_FRAME_DELIMITER;

#define LINK_MODE_SERVER 1
#define LINK_MODE_CLIENT 2
#define LINK_QUEUE_SIZE  LINK_MSG_SIZE * 3
#define LINK_SERVER_BACKLOG 			1

typedef struct _msg_queue_t {
	int8_t buf[LINK_QUEUE_SIZE];
	int client_fd;
	int client_state;
	int server_fd;
	const char * server_ip_addr;
	char remote_ip_addr[20];
	int port;
	int mode;
	uint32_t msgs_rx;
	uint32_t msgs_tx;
	uint32_t bytes_rx;
	uint32_t bytes_tx;
	uint32_t tx_seqnum;
} msg_queue_t;

msg_queue_t link_msg_queue;

void link_print_hex(int8_t* buffer, int32_t size) {
	int32_t i = 0;

	while (i < size){
		printf("%02X ",buffer[i]);

		if(!((i+1) % 16))
			printf("\n");

		i++;
	}

	printf("\n");
}

int link_init_msg_queue(void){

	/* Zero out the structure */
	memset((char*)&link_msg_queue, 0, sizeof(msg_queue_t));

	link_msg_queue.client_fd = -1;

	return 0;

}

/*
 *  Returns true on success, or false if there was an error
 */
int link_set_blocking(int fd, int blocking)
{
   if (fd < 0)
	   return -1;

   int flags = fcntl(fd, F_GETFL, 0);

   if (flags < 0)
	   return -1;

   flags = blocking ? (flags&~O_NONBLOCK) : (flags|O_NONBLOCK);

   return (fcntl(fd, F_SETFL, flags) == 0) ? 0 : -1;
}

/*
 * link_get_client_state() - Queries the state of the client socket.
 */
int link_get_client_state(void) {

	if(link_msg_queue.client_fd < 0) {
		link_msg_queue.client_state = LINK_CLIENT_NONE;
	}

	return link_msg_queue.client_state;
}

/*
 * link_get_client_state() - Queries the state of the client socket.
 */
int link_check_pending_client(void) {

	if(link_msg_queue.client_fd < 0) {
		link_msg_queue.client_state = LINK_CLIENT_NONE;
	}

	/* Further test for connection per connect(2) manpage */
	int err;
	socklen_t errlen;
	if(getsockopt(link_get_client_fd(), SOL_SOCKET,
			SO_ERROR, (int*)&err, (socklen_t*)&errlen) !=0) {
		link_close_client();
		return -1;
	}

	link_msg_queue.client_state = LINK_CLIENT_CONNECTED;
	return 0;
}

/*******************************************************************************   link_create_client() : Creates a client socket and attempts a connection
   to the server.  The address and port of the server are in the vc_cfg_data
   structure, which is loaded from the configuration file.
*******************************************************************************/
int link_create_client(void)
{

	/* Socket address structures */
	struct sockaddr_in addr;
	int on = 1;
	int errnum;

	if(link_msg_queue.mode == LINK_MODE_CLIENT) {

		if(link_msg_queue.client_fd < 0) /* No client exists yet */
		{
			/* Create client socket */
			link_msg_queue.client_fd = socket (AF_INET, SOCK_STREAM, 0);

			/* A valid descriptor is always a positive value */
			if (link_msg_queue.client_fd < 0) {
				debug_printf ("Failed creating socket\n");
				return -1;
			}

			/* Initialize the server address struct to zero */
			bzero ((char *) &addr, sizeof (addr));

			/*  Set the remote IP address  */
			if ( inet_aton(link_msg_queue.server_ip_addr, &addr.sin_addr) <= 0 ) {
				debug_printf("%s: Invalid remote IP address.\n",__func__);
				return -1;
			}

			/* Fill server's address family */
			addr.sin_family = AF_INET;
			addr.sin_port = htons (link_msg_queue.port);
		}

		/* Set the socket as blocking */
		link_set_blocking(link_msg_queue.client_fd, 1);

		/* Attempt to connect to the server */
		if ( connect(link_msg_queue.client_fd, (struct sockaddr *) &addr,
				sizeof(addr) ) < 0 ) {

			errnum = errno;

			/*
			 * Need to check for certain error conditions.
			 */
			if  (errnum == ECONNREFUSED || errnum == EHOSTUNREACH) {
				close(link_msg_queue.client_fd);
				link_msg_queue.client_fd = -1;
				link_msg_queue.client_state = LINK_CLIENT_PENDING;
				goto exit;
			}
			else {
				/* Some other error occurred. Close the socket */
				close(link_msg_queue.client_fd);
				printf("%s: Error connecting to server. %s\n", __func__, strerror(errnum));
				/* Invalidate the FD */
				link_msg_queue.client_fd = -1;
				link_msg_queue.client_state = LINK_CLIENT_NONE;
				goto exit;
			}
		}
		else {
			/* Client is connected and writable */
			link_msg_queue.client_state = LINK_CLIENT_CONNECTED;
			link_set_blocking(link_msg_queue.client_fd, 1);
			debug_printf("%s: Connected to %s on port: %d\n", __func__,
					link_msg_queue.server_ip_addr, link_msg_queue.port);
		}
	}
	else {  /* Client socket is created by the accept call on the server socket */

		int size = sizeof(addr);

		link_msg_queue.client_fd = accept(link_msg_queue.server_fd,
				(struct sockaddr *) &addr, (socklen_t *) &size);

		if (link_msg_queue.client_fd == -1) {
			debug_printf("%s: Failed to accept connection\n",__func__);
			link_msg_queue.client_state = LINK_CLIENT_NONE;
			goto exit;
		}

		/* Set the socket as blocking */
		link_set_blocking(link_msg_queue.client_fd, 1);

		link_msg_queue.client_state = LINK_CLIENT_CONNECTED;

		strcpy(link_msg_queue.remote_ip_addr, (char *)inet_ntoa(addr.sin_addr));
		printf("Connected to remote %s\n", link_msg_queue.remote_ip_addr);
	}

	if(setsockopt(link_msg_queue.client_fd, SOL_SOCKET, SO_KEEPALIVE, (const char *) &on, sizeof(on)) < 0) {
		debug_printf("%s: Failed to setsockopt() for SO_KEEPALIVE on client socket\n",__func__);
	}

exit:
	return link_msg_queue.client_state;
}


/*******************************************************************************
  link_get_remote_ip_addr() : Provides a pointer the remote ip address string
  Returns NULL if no client connection established, and a valid pointer
  otherwise.
*******************************************************************************/
char * link_get_remote_ip_addr(void) {

	if(link_msg_queue.client_fd < 0)
		return NULL;

	return link_msg_queue.remote_ip_addr;
}


/*******************************************************************************
  link_close_client() : Closes a working client socket in an orderly fashion.
*******************************************************************************/
int link_close_client(void)
{
	int ret = 1;

	debug_printf("%s: Client closing\n",__func__);

	if(link_msg_queue.client_fd <= 0)
		return 0;

	/* Call shutdown on client socket */
	if (shutdown(link_msg_queue.client_fd, SHUT_RDWR) < 0) {
		debug_printf("%s: Error shutting down client socket.\n", __func__);
	}

	/*
	 * Read remaining socket data, if any.  For now, don't care where it gets written,
	 * just empty the socket.  We may want to revisit this in the future if we want
	 * to process any remaining messages in the queue.
	 */
	while (ret > 0){
		ret = recv(link_msg_queue.client_fd, link_msg_queue.buf,
				LINK_MSG_SIZE, MSG_DONTWAIT );
	}

	/* Close the socket */
	close(link_msg_queue.client_fd);

	/* Invalidate the FD */
	link_msg_queue.client_fd = -1;
	link_msg_queue.client_state = LINK_CLIENT_NONE;

	/* Should be clean now, leave */
	return 0;
}

/*
 * link_recv_msg - receives data from link socket and returns a complete message.
 * Return value:
 *    On success, a positive integer for the number of bytes read.
 *    On timeout or socket closure, returns 0
 *    On failure, returns a negative value
 */
int link_recv_msg(link_message_t *msg, int timeout_ms){

	int header_ret, payload_ret = 0;
	int total_ret;
	char* buf = (char*)msg;
	struct pollfd fds;
	int myerr;

	if(link_msg_queue.client_fd <= 0)
		return -1;

	/* Grab a header size number of bytes first */
	header_ret = recv(link_msg_queue.client_fd, (void*)msg,
			LINK_COMMAND_MIN_SIZE, MSG_DONTWAIT);
	myerr = errno;  /* Store errno in case we need to decode the error */

	if(header_ret == 0){
		/* Remote has closed, close the client socket */
		debug_printf("%s: recv call for header returned 0.\n",__func__);
		return 0;
	}

	if(header_ret < 0) {
		/* Error occurred */
		debug_printf("%s: Failed to recv header. Error: %s",
				__func__, strerror(myerr));
		return header_ret;
	}

	/* Check header magic */
	/* Scan for pattern */
	int j;
	for (j=0; j < sizeof(link_frame_delimiter); j++) {
		if (buf[j] == link_frame_delimiter[j]){
			/* Good, now try the next one */
			continue;
		}
		else
			break; /* For loop */
	}

	if (j < sizeof(link_frame_delimiter)){
		/* Frame delimiter match was not found */
		debug_printf("%s: Expected to find frame and failed.\n",__func__);
		return -1;
	}

	/* Good data received, if no payload (indicated by payload size = 0), then return */
	if(!msg->header.size)
		goto good_return;

	/* Else, we need to wait for a payload to be received */
	fds.fd = link_msg_queue.client_fd;
	fds.events = POLLIN;
	fds.revents = 0;

	/* Wait for return message */
	int pollret = poll(&fds, 1 , timeout_ms);

	if(pollret == 0) {
		debug_printf("%s: poll call for payload timed out after %d ms\n",__func__, timeout_ms);
		return 0;
	}
	else if (pollret < 0) {
		myerr = errno;
		debug_printf("%s: Poll returned error: %s\n", __func__, strerror(myerr));
		return -1;
	}

	if(fds.events & POLLIN){
		payload_ret = recv(link_msg_queue.client_fd, (void*)msg->payload,
				msg->header.size, MSG_DONTWAIT);
		myerr=errno;

		if (payload_ret < 0){
			debug_printf("%s: Failed to recv payload. Error: %s\n",
					__func__,strerror(myerr));
			return payload_ret;
		}
		if (payload_ret == 0){
			debug_printf("%s: Recv call returned 0.  Is the server disconnected?\n",
					__func__);
			return payload_ret;
		}

		if (payload_ret < msg->header.size){
			/*
			 * If you see this message, then recv if returning less than
			 * of bytes we expect to see in the payload even after we waited in POLL
			 * for the next message.  This is a corner case that is possible because
			 * TCP does not guarantee that all bytes sent on particular socket will
			 * be readable.
			 */
			/* TODO: Handle this case */
			debug_printf("%s: BUG - corner case not handled.  Received some, but not all, of payload.\n",__func__);
		}
	}

good_return:

	total_ret = header_ret + payload_ret;

	//debug_printf("%s: recv'd %d bytes\n",__func__, total_ret);

	link_msg_queue.bytes_rx += total_ret;
	link_msg_queue.msgs_rx++;

	return total_ret;

}

/*
 * link_process_msg(). Processes link messages.  Ia a message is not
 * recognized, then it needs to be handled by a higher order processing
 * routine.
 *
 * Return value: positive value if the message was processed,
 * -1 if the message was not, 0 if the any link_send_msg calls return 0.
 */
int link_process_msg(link_message_t * msg){

	int msg_processed = -1;  /* Return value */

	/* Process the msg */
	switch (msg->header.msgtype) {
	case LINK_HEARTBEAT_REQUEST:
		/* Send heartbeat ack */
		link_send_ping_ack();
		msg_processed = 0;
		break;
	case LINK_STATUS_REQUEST:
		/*
		 * Send basic link status
		 */
		msg_processed = 0;
		break;
	case LINK_COMMAND_REQUEST:
		/* Send command ack */
		msg_processed = 0;
		break;
	case LINK_HEARTBEAT_ACK:
		/*
		 * No need to do anything here.
		 */
		msg_processed = 0;
		break;
	case LINK_LOOPBACK_REQUEST:
		/*
		 * Loopback request received, return the message as-is, with a
		 * LINK_LOOPBACK_ACK msgid.
		 */
		link_send_msg(LINK_LOOPBACK_ACK, msg->header.size, msg->payload);
		msg_processed = 0;
		break;
	case LINK_LOOPBACK_ACK:
		/*
		 * No need to do anything here.  The loopback test on the client
		 * will handle all of the loopback ack processing, bypassing this
		 * message processing handler altogether.
		 */
		msg_processed = 0;
		break;
	default:
		break;
	}

	return msg_processed;
}


/*
 * link_send() - Send a message to the other side.
 */

int link_send(int8_t *buf, int32_t size){

	int ret;

	if(link_msg_queue.client_fd <= 0)
		return -1;

	/*
	 * Send data
	 */
	ret = send(link_msg_queue.client_fd, buf, size, MSG_DONTWAIT);

	if(ret == 0){
		/* Remote has closed, close the client socket */
		return 0;
	}

	if(ret < 0) {
		/* Error occurred */
		return ret;
	}

	/* Good data written */
	link_msg_queue.bytes_tx += ret;

	return ret;
}


/*
 * link_init_message() - Initializes a link_message_t structure
 */
int link_init_message(link_message_t * msg){

	if (msg == NULL) return -1;

	strncpy((char*)msg->header.frame_delimiter, LINK_FRAME_DELIMITER, sizeof(LINK_FRAME_DELIMITER));
	msg->header.msgtype = LINK_NONE;
	msg->header.size = 0;
	msg->header.seqnum = link_msg_queue.tx_seqnum;

	return 0;
}

/*
 * link_send_msg_nopayload() - Send a message to the other side
 *
 * Return value:
 * 	Positive value on success
 * 	Negative value on failure
 * 	0 if link connection is down
 *
 */

int link_send_msg_nopayload(link_msg_type_t msgtype){

	int ret;
	link_message_t msg;
	if(link_init_message(&msg) < 0) {
		debug_printf("%s: could not init link message structure\n",__func__);
		return -1;
	}

	msg.header.msgtype = msgtype;
	msg.header.size = 0;  /* No payload */

	ret = link_send((int8_t*)&msg , sizeof(msg.header));

	if(ret < 0){
		debug_printf("%s: error sending link message.\n",__func__);
		return -1;
	}

	//debug_printf("%s: tx_seqnum: %u\n",__func__, msg.header.seqnum);

	/* Message sent */
	link_msg_queue.msgs_tx++;
	link_msg_queue.tx_seqnum++;

	return ret;
}

/*
 * link_send_msg() - Send a message to the other side, with a payload
 *
 * Return value:
 * 	Positive value on success
 * 	Negative value on failure
 * 	0 if link connection is down
 *
 */

int link_send_msg(link_msg_type_t msgtype, uint8_t size, void * payload){

	int ret;
	int tx_bytes;
	link_message_t msg;
	if(link_init_message(&msg) < 0) {
		debug_printf("%s: could not init link message structure\n",__func__);
		return -1;
	}

	msg.header.msgtype = msgtype;
	msg.header.size = size;

	/* copy payload */
	memcpy(&msg.payload, payload, size);

	tx_bytes = size + sizeof(msg.header);

	ret = link_send((int8_t*)&msg , tx_bytes);

	if(ret < 0){
		debug_printf("%s: error sending link message.\n",__func__);
		return -1;
	}

	if(ret == 0){
		debug_printf("%s: link_send returned 0, expected %d\n", __func__, tx_bytes);
		return ret;
	}

	/* TODO: Handle  0 < ret < tx_bytes case as well */

	//debug_printf("%s: tx_seqnum: %u\n",__func__,msg.header.seqnum);

	/* Message sent */
	link_msg_queue.msgs_tx++;
	link_msg_queue.tx_seqnum++;

	return ret;
}

/*
 * link_send_ping() - Send a ping to the other side.
 */

int link_send_ping(void){

	//debug_printf("%s: ping\n",__func__);
	return link_send_msg_nopayload(LINK_HEARTBEAT_REQUEST);
}

/*
 * link_send_ping_ack() - Send a ping response
 */

int link_send_ping_ack(void){

	//debug_printf("%s: ping ack\n",__func__);
	return link_send_msg_nopayload(LINK_HEARTBEAT_ACK);
}


/*******************************************************************************
 link_start_server() : Starts a server socket.
 Return value: 0 if successful, negative if failure.
 If successful, server socket fd is stored in link_msg_queue structure.
 *******************************************************************************/

int link_start_server(void) {

	int status = 0;
	int on = 1;

	/* Socket address structures */
	struct sockaddr_in serv_addr;

	printf("Starting server...\n");

	/* Create server socket */
	link_msg_queue.server_fd = socket(AF_INET, SOCK_STREAM, 0);

	/* A valid descriptor is always a positive value */
	if (link_msg_queue.server_fd < 0) {
		printf("Failed creating socket\n");
		return -1;
	}

	/* Initialize the server address struct to zero */
	bzero((char *) &serv_addr, sizeof(serv_addr));

	/* Fill server's address family */
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_addr.s_addr = INADDR_ANY;
	serv_addr.sin_port = htons(link_msg_queue.port);

	/*
	 * turn off bind address checking, and allow
	 * port numbers to be reused - otherwise
	 * the TIME_WAIT phenomenon will prevent
	 * binding to these address.port combinations
	 * for (2 * MSL) seconds.
	 */

	status = setsockopt(link_msg_queue.server_fd, SOL_SOCKET, SO_REUSEADDR ,
			(const char *) &on, sizeof(on));

	if (status < 0) {
		debug_printf("%s: Failed to setsocketopt()\n",__func__);
		close(link_msg_queue.server_fd);
		return -1;
	}

	/* Bind the server socket to the port */
	if (bind(link_msg_queue.server_fd, (struct sockaddr *) &serv_addr,
			sizeof(serv_addr)) < 0) {
		debug_printf("%s: Failed to bind\n",__func__);
		close(link_msg_queue.server_fd);
		return -1;
	}

	if (listen(link_msg_queue.server_fd, LINK_SERVER_BACKLOG) != 0) {
		debug_printf("%s: Failed to listen.\n",__func__);
		close(link_msg_queue.server_fd);
		return -1;
	}

	return 0;
}

/*******************************************************************************
 link_stop_server() : Stops and closes the server socket.
 Return value: 0 if successful, negative if failure.
 *******************************************************************************/

int link_stop_server(void) {

	if(link_msg_queue.client_fd)
		link_close_client();

	printf("Stopping server...\n");

	/* Shutdown server */
	shutdown(link_msg_queue.server_fd, SHUT_RDWR);

	close(link_msg_queue.server_fd);

	return 0;
}



/*
 * link_init_as_server() - Initialize the link as a server.  Subsequent calls to
 * to link_start_server() will start the server socket.
 */

int link_init_as_server(int port){

	/* Initialize the msg queue structure */
	link_init_msg_queue();

	/* Set up the mode */
	link_msg_queue.mode = LINK_MODE_SERVER;

	/* Set the port */
	link_msg_queue.port = port;

	return 0;
}

/*
 * link_init_as_client() - Initialize the link as a client.  Subsequent calls to
 * to link_create_client() will create the client socket.
 */

int link_init_as_client(char * server_ip_addr, int port){

	/* Initialize the msg queue structure */
	link_init_msg_queue();

	/* Set up the mode */
	link_msg_queue.mode = LINK_MODE_CLIENT;

	/* Set the port */
	link_msg_queue.port = port;

	/* Set the IP address of server */
	link_msg_queue.server_ip_addr = server_ip_addr;

	return 0;
}



/*
 * link_get_server_fd() - Gets the server socket file descriptor.
 * Returns a positive fd if success, negative value on failure.
 */

int link_get_server_fd(void){

	if(link_msg_queue.server_fd > 0)
		return link_msg_queue.server_fd;

	return -1;
}

/*
 * link_get_client_fd() - Gets the client socket file descriptor.
 * Returns a positive fd if success, negative value on failure.
 */

int link_get_client_fd(void){

	if(link_msg_queue.client_fd > 0)
		return link_msg_queue.client_fd;

	return -1;
}

/*
 * link_random_loopback_test() - Sends random data of random message sizes to
 * remote.  Useful for debugging the control link.  This routine blocks all
 * program flow until completion.
 * Returns zero on successful test, -1 on error.
 */

#define NUM_LOOPBACK_ITERATIONS 10000
#define LOOPBACK_RANDOMIZE 1
int link_random_loopback_test(void){

	/*
	 * Loop until messages sent = max number of loopback messages:
	 *  1: Create random length message with random data payload and
	 *     LINK_LOOPBACK_REQUEST as message type.
	 *  2: Send message to remote (blocks)
	 *  3: Read message from remote (blocks)
	 *  4: Compare messages.
	 *  5: Repeat
	 */

	uint8_t payload[LINK_PAYLOAD_SIZE];
	struct pollfd fds;
	link_message_t msg;

	/* Print some stuff */
	printf("Link loopback test started.\n");
	printf("   Number of messages: %d\n", NUM_LOOPBACK_ITERATIONS);
	printf("   Randomized data: ");
    LOOPBACK_RANDOMIZE ? printf("on\n\n") :  printf("off\n\n");

	/*
	 * First, test to make sure we have a valid link established
	 */
	if(link_get_client_state() != LINK_CLIENT_CONNECTED) {
		debug_printf("%s: Link not connected\n",__func__);
		return -1;
	}

	/*
	 * Open random number generator (simple /dev/urandom)
	 */
	FILE *fp;
	if((fp = fopen("/dev/urandom", "r")) == NULL){
		debug_printf("%s: could not open /dev/urandom.\n",__func__);
		return -1;
	}

	/*
	 * Loop
	 */

	int i = 0;
	int k = 0;
	unsigned char psize = 0;
	fds.fd = link_msg_queue.client_fd;
	fds.events = POLLIN;
	fds.revents = 0;
	int ret = 0;
	struct timespec start_time, end_time, interval, test_start_time, test_end_time, test_time;
	double interval_time = 0, total_time = 0, total_test_time = 0;

	/*
	 * Collect time data
	 */
	clock_gettime(CLOCK_MONOTONIC, &test_start_time);

	while(i < NUM_LOOPBACK_ITERATIONS){

		if(LOOPBACK_RANDOMIZE){
			/* Get random payload size */
			fread(&psize, 1, 1, fp);

			/* Get payload */
			fread(payload, 1, psize, fp);
		}
		else {
			psize = 50;
			for (k = 0; k < 50; k++){
				/* Ramp */
				payload[k]=k;
			}
		}

		/*
		 * Collect time data
		 */
		clock_gettime(CLOCK_MONOTONIC, &start_time);

		link_send_msg(LINK_LOOPBACK_REQUEST, psize, payload);

		/* Wait for return message, give ourselves a couple of seconds */
		int pollret = poll(&fds, 1 , 2000);

		if(pollret == 0) {
			printf("%s: Timed out waiting for loopback ack. \n",__func__);
			goto exit_failure;
		}
		else if (pollret < 0) {
			printf("%s: Error in poll return. \n",__func__);
			goto exit_failure;
		}

		if(fds.revents & POLLIN){
			if( (ret = link_recv_msg(&msg, 1000)) == 0) {
				printf("%s: link_recv_msg() returned 0\n",__func__);
				goto exit_failure;
			}
			else if (ret < 0){
				printf("%s: link_recv_msg() returned error\n",__func__);
				goto exit_failure;
			}
		}

		/* Check the message type */
		if(msg.header.msgtype != LINK_LOOPBACK_ACK) {
			debug_printf("%s: Message type not LOOPBACK_ACK\n",__func__);
			continue;
		}

		/* Compare payloads */
		int j;
		for (j=0; j< msg.header.size; j++) {
			if(msg.payload[j] != payload[j]) {
				printf("\n  Failure at loopback iteration %d. \n"
					   "  Expected payload data 0x%02X at payload buffer index %d\n"
					   "  Received 0x%02X\n",i,payload[j],j, msg.payload[j]);
				goto exit_failure;
			}
		}

		clock_gettime(CLOCK_MONOTONIC, &end_time);

		interval.tv_sec = end_time.tv_sec  - start_time.tv_sec;
		interval.tv_nsec = end_time.tv_nsec  - start_time.tv_nsec;
		interval_time = interval.tv_sec * 10e9 + interval.tv_nsec;
		total_time += interval_time;

		i++;
	}

	/* Print results */
	printf("Link loopback test succeeded: \n");

exit_failure:

    clock_gettime(CLOCK_MONOTONIC, &test_end_time);

	test_time.tv_sec = test_end_time.tv_sec - test_start_time.tv_sec;
	test_time.tv_nsec = test_end_time.tv_nsec - test_start_time.tv_nsec;
	total_test_time = test_time.tv_sec * 10e9 + test_time.tv_nsec;

	printf("   Number of messages: %d\n", i);
	printf("   Average roundtrip time: %lf ms\n", (total_time/10e6)/(double)i);
	printf("   Total test time: %lf s\n", total_test_time/10e9);
	fclose(fp);

	return 0;
}
