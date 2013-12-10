/*
 *  GLIVE server application, part of the GLIVE project
 *  GLIVE = Gstreamer Live Example
 *
 *  (c) John Weber, rjohnweber@gmail.com
 *  Avnet Electronics Marketing
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public Licensei, version 2,
 *  as published by the Free Software Foundation.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <gst/gst.h>
#include <glib.h>
#include <signal.h>
#include <string.h>
#include <stropts.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/timerfd.h> /* For timerfd functions */
#include <netinet/in.h>
#include <poll.h>		 /* For poll() */
#include <fcntl.h>		 /* For open() */
#include <unistd.h>   	 /* For read() */
#include <ctype.h>    	 /* For toupper() */
#include "common.h"
#include "link.h"

#define NUM_POLL_FDS 			4
#define FD_INDEX_STDIN			0
#define FD_INDEX_SOCK_SERVER	1
#define FD_INDEX_SOCK_CLIENT	2
#define FD_INDEX_TIMER			3
#define POLL_TIMEOUT_MSECS 		100
#define VS_INTERVAL_TIME_MSEC	500
#define STDIN_BUF_SIZE			50
#define VS_SSRC_ID				0

/* Defaults */
#define DEFAULT_TX_RTP_PORT		5000
#define DEFAULT_TX_RTCP_PORT	5001
#define DEFAULT_RX_RTCP_PORT	5005
#define DEFAULT_SERVER_PORT		50021
#define DEFAULT_BITRATE			4000000

/* Function prototypes */
static void vs_sigint_restore(void);

typedef struct _vs_cfg_data {
	int server_port;
	char remote_ip_addr[30];
	int rtp_send_port;
	int rtcp_send_port;
	int rtcp_recv_port;
	long long encode_bitrate;
} vs_cfg_data;

typedef struct _vs_gst_data {
	GMainLoop *loop;
	GMainContext *context;
	GstElement *pipeline,
		*source,
		*encoder,
		*payloader,
		*rtp_udpsink,
		*rtcp_udpsink,
		*rtcp_udpsrc,
		*rtpbin;
	GstPad *send_rtp_sink_pad,
		*send_rtcp_src_pad,
		*recv_rtcp_sink_pad;
} vs_gst_data;

typedef struct _vs_data {
	vs_gst_data gst_data;
	struct pollfd fds[NUM_POLL_FDS];
	int exit_flag;
	vs_cfg_data cfg;
} vs_data;

/* Global data */
vs_data app_data;

/* SIGINT Handler */
static void vs_sigint_handler(int signum) {
	g_print("Caught interrupt -- ");
	vs_sigint_restore();

	/* Set the exit flag to 1 to exit the main loop */
	app_data.exit_flag = 1;
}

/* Interrupt signal setup */
static void vs_sigint_setup(void) {
	struct sigaction action;

	memset(&action, 0, sizeof(action));
	action.sa_handler = vs_sigint_handler;

	sigaction(SIGINT, &action, NULL );
}

/* Restore default interrupt signal handler */
static void vs_sigint_restore(void) {
	struct sigaction action;

	memset(&action, 0, sizeof(action));
	action.sa_handler = SIG_DFL;

	sigaction(SIGINT, &action, NULL );
}

/* Initialize a CustomData structure */
void vs_init_data(vs_data *data) {

	int i;

	/* Zero out the structure */
	memset(data, 0, sizeof(vs_data));

	/* Invalidate the poll file descriptors */
	for (i=0; i<NUM_POLL_FDS; i++)
		data->fds[i].fd = -1;

}

/*******************************************************************************
 Pipeline teardown function
 *******************************************************************************/
int vs_gst_pipeline_clean(vs_data *data){

	GstStateChangeReturn ret;

	/* Cleanup Gstreamer */
	if(!data->gst_data.pipeline)
		return 0;

	/* Send the main loop a quit signal */
	g_main_loop_quit(data->gst_data.loop);
	g_main_loop_unref(data->gst_data.loop);

	ret = gst_element_set_state(data->gst_data.pipeline, GST_STATE_NULL);
	if (ret == GST_STATE_CHANGE_FAILURE) {
		g_printerr("Unable to set the pipeline to the NULL state.\n");
	}

	g_print("Deleting pipeline\n");
	gst_object_unref(GST_OBJECT (data->gst_data.pipeline));
	gst_object_unref(GST_OBJECT (data->gst_data.recv_rtcp_sink_pad));
	gst_object_unref(GST_OBJECT (data->gst_data.send_rtp_sink_pad));
	gst_object_unref(GST_OBJECT (data->gst_data.send_rtcp_src_pad));

	/* Zero out the structure */
	memset(&data->gst_data, 0, sizeof(vs_gst_data));

	return 0;

}

/*******************************************************************************
 Cleanup function
 *******************************************************************************/
int vs_cleanup(vs_data *data) {

	g_print("Cleanup function\n");

	/* Cleanup Gstreamer */
	vs_gst_pipeline_clean(data);

	/* Close stdin */
	close(data->fds[0].fd);

	/* Close server socket */
	link_stop_server();

	/* Restore signal handler */
	vs_sigint_restore();

	return 0;
}

#define VS_CHECK_ELEMENT_ERROR(e, name) \
if (!e) { \
	g_printerr ("Element %s could not be created. Exiting.\n", name); \
	return -1; \
}

/*******************************************************************************
 Gstreamer pipeline creation and init
 *******************************************************************************/
int vs_gst_pipeline_init(vs_data *data) {
	GstStateChangeReturn ret;

	/* Template */
	GstPadTemplate* rtpbin_pad_template;

	/* Create a new GMainLoop */
	data->gst_data.loop = g_main_loop_new(NULL, FALSE);
	data->gst_data.context = g_main_loop_get_context(data->gst_data.loop);

	/* Create gstreamer elements */
	data->gst_data.pipeline = gst_pipeline_new("videoserver");

	/*
	 * Video source
	 */
	data->gst_data.source = gst_element_factory_make("mfw_v4lsrc", "video-source");
	VS_CHECK_ELEMENT_ERROR(data->gst_data.source, "mfw_v4lsrc");

	g_print("  Setting up element properties...");
	/* we set the up the source paramters */
	g_print("V4L Source, ");
	g_object_set(G_OBJECT (data->gst_data.source), "fps-n", 30, NULL );
	g_object_set(G_OBJECT (data->gst_data.source), "capture-mode", 4, NULL );

	/*
	 * H264 Encoder
	 */
	data->gst_data.encoder = gst_element_factory_make("vpuenc", "encoder");
	VS_CHECK_ELEMENT_ERROR(data->gst_data.encoder, "vpuenc");

	g_print("H264 Encoder, ");
	g_object_set(G_OBJECT (data->gst_data.encoder), "codec", 6, NULL );
	g_object_set(G_OBJECT (data->gst_data.encoder), "bitrate", data->cfg.encode_bitrate,
			NULL );

	/*
	 * RTP H.264 Payloader
	 */
	data->gst_data.payloader = gst_element_factory_make("rtph264pay", "payloader");
	VS_CHECK_ELEMENT_ERROR(data->gst_data.payloader, "rtph264pay");

	/*
	 * RTP UDP sink
	 */
	data->gst_data.rtp_udpsink = gst_element_factory_make("udpsink", "rtp_udpsink");
	VS_CHECK_ELEMENT_ERROR(data->gst_data.rtp_udpsink, "udpsink");

	/*
	 * RTCP UDP sink
	 */
	data->gst_data.rtcp_udpsink = gst_element_factory_make("udpsink", "rtcp_udpsink");
	VS_CHECK_ELEMENT_ERROR(data->gst_data.rtcp_udpsink, "udpsink");

	/*
	 * RTCP UDP Source (for received RTCP messages)
	 */
	data->gst_data.rtcp_udpsrc = gst_element_factory_make("udpsrc", "rtcp_udpsrc");
	VS_CHECK_ELEMENT_ERROR(data->gst_data.rtcp_udpsrc, "udpsrc");

	/*
	 * RTP Bin - for bringing it all together
	 */
	data->gst_data.rtpbin = gst_element_factory_make("gstrtpbin", "rtpbin");
	VS_CHECK_ELEMENT_ERROR(data->gst_data.rtpbin, "gstrtpbin");

	/*
	 * Request pads from rtpbin, starting with the RTP transmit sink pad,
	 * This pad receives RTP data from the RTP payloader,
	 */
	rtpbin_pad_template = gst_element_class_get_pad_template(
			GST_ELEMENT_GET_CLASS (data->gst_data.rtpbin), "send_rtp_sink_%d");

	/* Use the template to request the pad */
	data->gst_data.send_rtp_sink_pad = gst_element_request_pad(
			data->gst_data.rtpbin,
			rtpbin_pad_template,
			"send_rtp_sink_0",
			NULL );

	/* Print the name for confirmation */
	g_print("A new pad %s was created\n",
			gst_pad_get_name (data->gst_data.send_rtp_sink_pad));


	/*
	 * Request RTCP Source Pad
	 */
	rtpbin_pad_template = gst_element_class_get_pad_template(
			GST_ELEMENT_GET_CLASS (data->gst_data.rtpbin), "send_rtcp_src_%d");

	data->gst_data.send_rtcp_src_pad = gst_element_request_pad(data->gst_data.rtpbin, rtpbin_pad_template,
			"send_rtcp_src_0", NULL );

	/* Print the name for confirmation */
	g_print("A new pad %s was created\n", gst_pad_get_name (data->gst_data.send_rtcp_src_pad));


	/*
	 * Request RTCP Sink Pad
	 */
	rtpbin_pad_template = gst_element_class_get_pad_template(
			GST_ELEMENT_GET_CLASS (data->gst_data.rtpbin), "recv_rtcp_sink_%d");

	data->gst_data.recv_rtcp_sink_pad = gst_element_request_pad(data->gst_data.rtpbin, rtpbin_pad_template,
			"recv_rtcp_sink_0", NULL );

	/* Print the name for confirmation */
	g_print("A new pad %s was created\n",
			gst_pad_get_name (data->gst_data.recv_rtcp_sink_pad));

	/*
	 * Set up the pipeline
	 */
	g_print("  RTP Sink\n");
	g_object_set(G_OBJECT (data->gst_data.rtp_udpsink),
			"host", data->cfg.remote_ip_addr,
			"port", data->cfg.rtp_send_port,
			NULL );

	g_print("  RTCP Sink\n");
	g_object_set(G_OBJECT (data->gst_data.rtcp_udpsink),
			"host", data->cfg.remote_ip_addr,
			"port", data->cfg.rtcp_send_port,
			"sync", FALSE,
			"async", FALSE,
			NULL );

	g_print("  RTCP Source\n");
	g_object_set(G_OBJECT (data->gst_data.rtcp_udpsrc),
			"port", data->cfg.rtcp_recv_port,
			NULL );

	/* we add all elements into the pipeline */
	g_print("  Adding elements to pipeline...\n");

	gst_bin_add_many(
			GST_BIN (data->gst_data.pipeline),
			data->gst_data.source,
			data->gst_data.encoder,
			data->gst_data.payloader,
			data->gst_data.rtp_udpsink,
			data->gst_data.rtcp_udpsink,
			data->gst_data.rtcp_udpsrc,
			data->gst_data.rtpbin,
			NULL );

	/* We link the elements together */
	g_print("  Linking elements: Source, encoder, payloader...\n");
	if(!gst_element_link_many(
			data->gst_data.source,
			data->gst_data.encoder,
			data->gst_data.payloader,
			NULL ))
		g_print("Error: could not link source, encoder, and payloader\n");

	/* Link the payloader src pad to the rtpbin send_vrtp_sink_pad */
	if(!gst_element_link_pads(
			data->gst_data.payloader, "src",
			data->gst_data.rtpbin, "send_rtp_sink_0"))
		g_print("Error: could not link payloader to rtp sink\n");

	/* Link the rtpbin send_vrtp_src_pad to the rtp_udpsink sink pad */
	if(!gst_element_link_pads(
			data->gst_data.rtpbin, "send_rtp_src_0",
			data->gst_data.rtp_udpsink, "sink"))
		g_print("Error: could not link rtp source to udpsink\n");

	/* Link the rtpbin sent_rctp_src_pad to the rtcp_udpsink (udpsink) sink pad */
	if(!gst_element_link_pads(
			data->gst_data.rtpbin, "send_rtcp_src_0",
			data->gst_data.rtcp_udpsink, "sink"))
		g_print("Error: could not link rtcp source to udpsink\n");

	/* Link the src pad of rtcp_udpsrc (udpsrc) to the sink pad of rtpbin recv_rtcp_sink_pad */
	if(!gst_element_link_pads(
			data->gst_data.rtcp_udpsrc, "src",
			data->gst_data.rtpbin, "recv_rtcp_sink_0"))
		g_print("Error: could not link udp source to rtcp sink\n");

	/* Set the pipeline to "playing" state*/
	g_print("Now playing\n");
	ret = gst_element_set_state(data->gst_data.pipeline, GST_STATE_PLAYING);

	if (ret == GST_STATE_CHANGE_FAILURE) {
		g_printerr("Unable to set the pipeline to the playing state.\n");
		gst_object_unref(data->gst_data.pipeline);
		return -1;
	}

	return 0;
}

/*******************************************************************************
 vs_start_server() : Starts a server socket.  Upon successful return, the
 socket file descriptor is already entered into the data->fds array.
 *******************************************************************************/

int vs_start_server(vs_data *data) {

	if(link_init_as_server(data->cfg.server_port) < 0){
		debug_printf("%s: Failed to init link as server\n", __func__);
		return -1;
	}

	if(link_start_server() < 0) {
		debug_printf("%s: Failed to start server\n", __func__);
		return -1;
	}

	/* Add socket descriptor to data->fds array for polling */
	data->fds[FD_INDEX_SOCK_SERVER].fd = link_get_server_fd();
	data->fds[FD_INDEX_SOCK_SERVER].events = POLLIN;

	printf("Server started on port: %d\n", data->cfg.server_port);

	return 0;
}



/*******************************************************************************
 vs_process_char_cmd(): Process a character command
 *******************************************************************************/
int vs_process_char_cmd(vs_data *data, char *buf) {

	GstStateChangeReturn ret;
	char cmdchar;

	cmdchar = toupper(buf[0]); /* pick off the first character for now */
	switch (cmdchar) {

	case 'P': /* Toggle the state of the pipeline */
		if (!data->gst_data.pipeline){
			g_printerr("Cannot pause - no pipeline exists yet\n");
			break;
		}

		if (GST_STATE(data->gst_data.pipeline) == GST_STATE_PLAYING) {
			/* pipe is running */
			ret = gst_element_set_state(data->gst_data.pipeline, GST_STATE_PAUSED);
			if (ret == GST_STATE_CHANGE_FAILURE) {
				g_printerr("Unable to set the pipeline to the PAUSED state.\n");
			}
			g_print("Pipeline is PAUSED\n");
		} else if (GST_STATE(data->gst_data.pipeline) == GST_STATE_PAUSED) {
			/* Pipeline is paused */
			ret = gst_element_set_state(data->gst_data.pipeline, GST_STATE_PLAYING);
			if (ret == GST_STATE_CHANGE_FAILURE) {
				g_printerr(
						"Unable to set the pipeline to the PLAYING state.\n");
			}
			g_print("Pipeline is PLAYING\n");
		} else
			g_printerr("Confused. Pipeline neither PLAYING nor PAUSED.\n");
		break;

	case 'Q': /* Quit */
		data->exit_flag = 1;
		break;

	default:
		g_printerr("Unknown command %c\n", (char) cmdchar);
		break;
	}

	return 0;
}

/*******************************************************************************
 vs_setup_timer:  Sets up the timerfd for the main loop
 *******************************************************************************/
int vs_setup_timer (vs_data* data) {

	struct timespec timerval;

	data->fds[FD_INDEX_TIMER].fd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK);

	if(data->fds[FD_INDEX_TIMER].fd < 0){
		debug_printf("%s: failed to create timerfd\n",__func__);
		return -1;
	}

	data->fds[FD_INDEX_TIMER].events = 0;

	return 0;
}

/*******************************************************************************
 vs_start_timer:  Starts the timer to go off relative to the current time.
 This is a one-shot timer.  The 'interval_ms' argument specifies the time in
 milliseconds relative to the current time (i.e. interval_ms in the future,
 unless stopped, reset, and restarted, the timer will 'go off').
 *******************************************************************************/

int vs_start_timer (vs_data *data, int interval_ms) {

	if(data->fds[FD_INDEX_TIMER].fd < 0){
		debug_printf("%s: attempted to operate on an invalid timerfd\n",
				__func__);
		return -1;
	}

	struct itimerspec its;

	its.it_interval.tv_sec = 0;
	its.it_interval.tv_nsec = 0;

	its.it_value.tv_sec = 0;
	its.it_value.tv_nsec = interval_ms * 1000000;

	int ret = 0;
	if((ret = timerfd_settime(data->fds[FD_INDEX_TIMER].fd, 0,
			(const struct itimerspec *) &its, NULL)) < 0)
		return -1;

	data->fds[FD_INDEX_TIMER].events = POLLIN;

	return 0;

}

/*******************************************************************************
 vs_stop_timer:  Starts the timer to go off relative to the current time.
 This is a one-shot timer.  The 'interval_ms' argument specifies the time in
 milliseconds relative to the current time (i.e. interval_ms in the future,
 unless stopped, reset, and restarted, the timer will 'go off').
 *******************************************************************************/

int vs_stop_timer (vs_data *data) {

	if(data->fds[FD_INDEX_TIMER].fd < 0){
		debug_printf("%s: attempted to operate on an invalid timerfd\n",
				__func__);
		return -1;
	}

	struct itimerspec its;
	its.it_interval.tv_sec = 0;
	its.it_interval.tv_nsec = 0;

	its.it_value.tv_sec = 0;
	its.it_value.tv_nsec = 0;

	int ret = 0;
	if((ret = timerfd_settime(data->fds[FD_INDEX_TIMER].fd, 0,
			(const struct itimerspec *) &its, NULL)) < 0)
		return -1;

	data->fds[FD_INDEX_TIMER].events = 0;

	return 0;

}

/*******************************************************************************
 vs_cleaup_timer:  Cleans up timerfd
 *******************************************************************************/
int vs_cleanup_timer (vs_data* data) {

	vs_stop_timer(data);
	close(data->fds[FD_INDEX_TIMER].fd);

	data->fds[FD_INDEX_TIMER].fd = -1;
	data->fds[FD_INDEX_TIMER].events = 0;

	return 0;
}

/*******************************************************************************
 MainLoop
 *******************************************************************************/
int vs_mainloop(vs_data* data) {

	int pollret;
	int fileret;
	char buf[STDIN_BUF_SIZE];
	struct sockaddr_in client_addr;
	link_message_t msg;
	int on = 1;

	while (1) {

		/* Test for exit flag */
		if (data->exit_flag != 0)
			break;

		/* Run the GMainLoop iteration manually */
		if(data->gst_data.context)
			g_main_context_iteration(data->gst_data.context, FALSE);

		/* Look for events on one of the file descriptors */
		if((pollret = poll(data->fds, NUM_POLL_FDS, POLL_TIMEOUT_MSECS))== 0){
			continue; /* No events happened on any of our file descriptors */
		}
		else if (pollret < 0) {
			printf("Poll returned error %s\n", strerror(errno));
			/* TODO: Error handler for this condition */
			continue;
		}

		/* Something happened */
		if (data->fds[FD_INDEX_STDIN].revents & POLLIN) {

			printf("Stdin has data to read.\n");

			/* Data is waiting on /dev/stdin */
			fileret = read(data->fds[FD_INDEX_STDIN].fd, buf, STDIN_BUF_SIZE);
			if (fileret <= 0) {
				printf("Unable to read data from /dev/stdin\n");
				continue;
			}

			vs_process_char_cmd(data, buf);

		}

		if (data->fds[FD_INDEX_SOCK_SERVER].revents & POLLIN) {

			printf("Client attempting to attach to server.\n");

			/* link_create_client works in server mode as well */
			if(link_create_client() < 0){
				debug_printf("%s: error creating client socket.\n",__func__);
			}

			/* Add the client socket to the poll FDS list */
			data->fds[FD_INDEX_SOCK_CLIENT].fd = link_get_client_fd();
			if(data->fds[FD_INDEX_SOCK_CLIENT].fd <= 0){
				debug_printf("%s: error: could not open client connection.\n",__func__);
				return -1;
			}
			data->fds[FD_INDEX_SOCK_CLIENT].events = POLLIN;

			strcpy(data->cfg.remote_ip_addr, link_get_remote_ip_addr());
			debug_printf("%s: Remote IP address: %s\n", __func__, data->cfg.remote_ip_addr);

			if(!data->gst_data.pipeline){
				if (vs_gst_pipeline_init(&app_data) < 0) {
					g_print("Gstreamer pipeline creation and init failed\n");
					return -1;
				}
			}
		}

		if (data->fds[FD_INDEX_SOCK_CLIENT].revents & POLLIN) {

			/* We have data on client socket */
			fileret = link_recv_msg(&msg, 1000);
			if (fileret < 0) {
				printf("Unable to read data from client socket\n");
				continue;
			}
			if (fileret == 0) {
				debug_printf("%s: Client disconnected.\n",__func__);

				link_close_client();

				data->fds[FD_INDEX_SOCK_CLIENT].fd = -1;
				data->fds[FD_INDEX_SOCK_CLIENT].events = 0;
				data->fds[FD_INDEX_SOCK_CLIENT].revents = 0;

				vs_gst_pipeline_clean(data);

			}
			else if (fileret > 0)
				link_process_msg(&msg);
		}
	}

	return 0;
}

/*******************************************************************************
 Main
 *******************************************************************************/

int main(int argc, char *argv[]) {
	int opt;
	int daemonize = 0;
	int quiet = 0;

	/* Parse command line */
	while ((opt = getopt(argc, argv, "dqh")) != -1) {
		switch (opt) {
		case 'd':
			/* Daemonize - do not open /dev/stdin */
			daemonize = 1;
			break;
		case 'q':
			/* Quiet - do not print startup messages */
			quiet = 1;
			break;
		case 'h':
			printf("Usage: %s [-dqh]\n", argv[0]);
			printf("  d: Daemonize mode.  Do not open stdin for input.\n"
				   "  q: Quiet: Do not print copyright information.\n"
				   "  h: Help: print this message\n");
			break;
		default: /* '?' */
			break;
		}
	}
	
	if(!quiet){
		printf("glives - Gstreamer Live Example Server \n"
				"(C) John Weber, Avnet Electronics Marketing\n");
	}	

	/* Initialize the app_data structure */
	vs_init_data(&app_data);

	/* Initialize configuration */
	app_data.cfg.rtp_send_port  = DEFAULT_TX_RTP_PORT;
	app_data.cfg.rtcp_send_port = DEFAULT_TX_RTCP_PORT;
	app_data.cfg.rtcp_recv_port = DEFAULT_RX_RTCP_PORT;
	app_data.cfg.encode_bitrate = DEFAULT_BITRATE;
	app_data.cfg.server_port    = DEFAULT_SERVER_PORT;

	printf("Server port:    %d\n"
			"Sending RTP data on port:    %d\n"
			"Sending RTCP data on port:   %d\n"
			"Expecting RTCP data on port: %d\n"
			"Video encode bit rate:       %lld\n",
			app_data.cfg.server_port,
			app_data.cfg.rtp_send_port,
			app_data.cfg.rtcp_send_port,
			app_data.cfg.rtcp_recv_port,
			app_data.cfg.encode_bitrate);

	/* Setup the file descriptors for polling, starting with /dev/stdin */
	if(!daemonize){
		app_data.fds[FD_INDEX_STDIN].fd = open("/dev/stdin", O_RDONLY);
		if (app_data.fds[FD_INDEX_STDIN].fd == -1) {
			printf("Error opening /dev/stdin for reading\n");
			return -1;
		}
		app_data.fds[FD_INDEX_STDIN].events = POLLIN;
	}
	else
		printf("Starting videoserver in background.\n");

	if (vs_start_server(&app_data) != 0) {
		printf("Error opening server socket\n");
		return -1;
	}

	/* Gstreamer initialization */
	gst_init(&argc, &argv);

	/* Install interrupt handler */
	vs_sigint_setup();

	/* Main Loop */
	g_print("Running...\n");

	vs_mainloop(&app_data);

	/* Out of the main loop, clean up nicely */
	g_print("Returned, stopping playback\n");

	return vs_cleanup(&app_data);

}
