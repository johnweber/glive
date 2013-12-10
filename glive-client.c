/*
 *  GLIVE client application, part of the GLIVE project
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
#include <netinet/in.h>
#include <sys/timerfd.h>    /* For timerfd functions */
#include <arpa/inet.h>  	/*  inet (3) funtions         */
#include <poll.h>			/* For poll() */
#include <fcntl.h>			/* For open() */
#include <unistd.h>   		/* For read() */
#include <ctype.h>    		/* For toupper() */
#include "common.h"
#include "link.h"
#include <linux/kd.h>


#define NUM_POLL_FDS 				3
#define FD_INDEX_STDIN				0
#define FD_INDEX_SOCK_CLIENT		1
#define	FD_INDEX_TIMER				2
#define POLL_TIMEOUT_MSECS 			100
#define STDIN_BUF_SIZE		  		50
#define VC_SSRC_ID					0
#define VC_LINK_WDOG_INTERVAL		2
#define WDOG_STATE_ACTIVE			1
#define WDOG_STATE_PENDING			2
#define WDOG_STATE_INACTIVE			0

/* Defaults */
#define DEFAULT_RX_RTP_PORT		5000
#define DEFAULT_RX_RTCP_PORT	5001
#define DEFAULT_TX_RTCP_PORT	5005
#define DEFAULT_SERVER_PORT		50021
#define DEFAULT_LATENCY_MS		50

static void vc_sigint_restore (void);

typedef struct _vc_cfg_data {
	int server_port;
	char server_ip_addr[20];
	int rtp_recv_port;
	int rtcp_recv_port;
	int rtcp_send_port;
} vc_cfg_data;

typedef struct _vc_gst_data {
	GMainLoop *loop;
	GMainContext *context;
	GstElement *pipeline;
	GstElement *depayloader;
	GstPad *recv_rtp_sink_pad, *recv_rtcp_sink_pad, *send_rtcp_src_pad;
} vc_gst_data;


typedef struct _vc_data {
	vc_gst_data gst_data;
	struct pollfd fds[NUM_POLL_FDS];
	int exit_flag;
	int sock_client;
	vc_cfg_data cfg;
	int watchdog_state;
	int daemonize;
} vc_data;

static void vc_pad_added_handler (GstElement *src, GstPad *new_pad, vc_data *data);
static void vc_on_timeout_handler (GstElement *src, int ssrc, vc_data *data);

/* Global data */
vc_data app_data;

/* SIGINT Handler */
static void vc_sigint_handler (int signum)
{
	g_print ("Caught interrupt -- ");
	vc_sigint_restore ();

	/* Set the exit flag to 1 to exit the main loop */
	app_data.exit_flag = 1;

}

/* Interrupt signal setup */
static void vc_sigint_setup (void)
{
	struct sigaction action;

	memset (&action, 0, sizeof (action));
	action.sa_handler = vc_sigint_handler;

	sigaction (SIGINT, &action, NULL);
}

/* Restore default interrupt signal handler */
static void vc_sigint_restore (void)
{
	struct sigaction action;

	memset (&action, 0, sizeof (action));
	action.sa_handler = SIG_DFL;

	sigaction (SIGINT, &action, NULL);
}

/* Initialize a vc_data structure */
void vc_init_data(vc_data *data)
{
	int i = 0;

	/* Zero out the structure */
	memset(data, 0, sizeof(vc_data));

	/* Invalidate the poll file descriptors */
	for (i=0; i<NUM_POLL_FDS; i++)
		data->fds[i].fd = -1;
}

/*******************************************************************************
 vc_setup_timer:  Sets up the timerfd for the main loop
 *******************************************************************************/
int vc_setup_timer (vc_data* data) {

	data->fds[FD_INDEX_TIMER].fd = timerfd_create(CLOCK_MONOTONIC, 0);

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

int vc_start_timer (vc_data *data, int interval_ms) {

	if(data->fds[FD_INDEX_TIMER].fd < 0){
		debug_printf("%s: attempted to operate on an invalid timerfd\n",
				__func__);
		return -1;
	}

	struct itimerspec its;

	its.it_interval.tv_sec = 0;
	its.it_interval.tv_nsec = 0;

	its.it_value.tv_sec = interval_ms;
	its.it_value.tv_nsec = 0;

	int ret = 0;
	if((ret = timerfd_settime(data->fds[FD_INDEX_TIMER].fd, 0,
			(const struct itimerspec *) &its, NULL)) < 0) {
		debug_printf("%s: failed to settime. \n", __func__);
		return -1;
	}


	data->fds[FD_INDEX_TIMER].events = POLLIN;

	return 0;

}

/*******************************************************************************
 vc_stop_timer:  Stops the timer.
 *******************************************************************************/

int vc_stop_timer (vc_data *data) {

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
 vc_cleaup_timer:  Cleans up timerfd
 *******************************************************************************/
int vc_cleanup_timer (vc_data* data) {

	vc_stop_timer(data);
	close(data->fds[FD_INDEX_TIMER].fd);

	data->fds[FD_INDEX_TIMER].fd = -1;
	data->fds[FD_INDEX_TIMER].events = 0;

	return 0;
}


#define VC_CHECK_ELEMENT_ERROR(e, name) \
if (!e) { \
	g_printerr ("Element %s could not be created. Exiting.\n", name); \
	return -1; \
}



/*******************************************************************************
	Gstreamer pipeline creation and init
*******************************************************************************/
int vc_gst_pipeline_init(vc_data *data)
{
	GstStateChangeReturn ret;
	GstElement *rtp_udpsrc, *rtcp_udpsrc, *rtcp_udpsink, *decoder,
		*depayloader, *converter, *sink, *rtpbin;
	GstCaps *caps;

	/* Request Pads */

	/* Template */
	GstPadTemplate* rtpbin_pad_template;
	/* TODO - Find a way to free the pads when the pipeline is closed */

	/* Create a new GMainLoop */
	data->gst_data.loop = g_main_loop_new (NULL, FALSE);
	data->gst_data.context = g_main_loop_get_context(data->gst_data.loop);

	/* Create gstreamer elements */
	data->gst_data.pipeline  = gst_pipeline_new ("videoclient");
	VC_CHECK_ELEMENT_ERROR(data->gst_data.pipeline, "pipeline");

	/*
	 * RTP UDP Source - for received RTP messages
	 */
	rtp_udpsrc = gst_element_factory_make ("udpsrc", "rtp-udpsrc");
	VC_CHECK_ELEMENT_ERROR(rtp_udpsrc,"rtp-udpsrc");

	g_print ("Setting RTP source port to: %d\n", data->cfg.rtp_recv_port);
	g_object_set (G_OBJECT (rtp_udpsrc),"port", data->cfg.rtp_recv_port, NULL);

	/* Create GstCaps structure from string.  This function allocates
	     memory for the structure */
	caps = gst_caps_from_string(
			"application/x-rtp, media=(string)video, clock-rate=(int)90000, encoding-name=(string)H264");
	g_object_set (G_OBJECT (rtp_udpsrc), "caps", caps, NULL);
	gst_caps_unref(caps); /* Free the structure */

	/*
	 * RTCP UDP Source
	 */
	rtcp_udpsrc = gst_element_factory_make ("udpsrc", "rtcp-udpsrc");
	VC_CHECK_ELEMENT_ERROR(rtcp_udpsrc,"rtcp-udpsrc");

	g_print ("Setting RTCP udp source port to: %d\n",
			data->cfg.rtcp_recv_port);
	g_object_set (G_OBJECT (rtcp_udpsrc), "port", data->cfg.rtcp_recv_port, NULL);

	/*
	 * RTCP UDP Sink (transmits data from rtpbin back to server)
	 */
	rtcp_udpsink = gst_element_factory_make ("udpsink", "rtcp-udpsink");
	VC_CHECK_ELEMENT_ERROR(rtcp_udpsink,"rtcp-udpsink");

	g_print ("Setting RTCP udp sink port to: %d\n",
			data->cfg.rtcp_send_port);
	g_object_set (G_OBJECT (rtcp_udpsink),
			"host", data->cfg.server_ip_addr,
			"port", data->cfg.rtcp_send_port,
			"sync", FALSE,
			"async", FALSE,
			NULL);

	/*
	 * RTP Bin - Automates RTP/RTCP management
	 */
	rtpbin = gst_element_factory_make ("gstrtpbin", "rtpbin");
	VC_CHECK_ELEMENT_ERROR(rtpbin,"gstrtpbin");

	/*
	 * Request pads from rtpbin, starting with the RTP receive sink pad,
	 * This pad receives RTP data from the network (rtp-udpsrc).
	 */
	rtpbin_pad_template = gst_element_class_get_pad_template (
			GST_ELEMENT_GET_CLASS (rtpbin),
			"recv_rtp_sink_%d");
	/* Use the template to request the pad */
	data->gst_data.recv_rtp_sink_pad = gst_element_request_pad (rtpbin, rtpbin_pad_template,
			"recv_rtp_sink_0", NULL);
	/* Print the name for confirmation */
	g_print ("A new pad %s was created\n",
			gst_pad_get_name (data->gst_data.recv_rtp_sink_pad));

	rtpbin_pad_template = gst_element_class_get_pad_template (
			GST_ELEMENT_GET_CLASS (rtpbin),
			"recv_rtcp_sink_%d");
	data->gst_data.recv_rtcp_sink_pad = gst_element_request_pad (rtpbin,
			rtpbin_pad_template,
			"recv_rtcp_sink_0", NULL);
	g_print ("A new pad %s was created\n",
			gst_pad_get_name (data->gst_data.recv_rtcp_sink_pad));

	rtpbin_pad_template = gst_element_class_get_pad_template (
			GST_ELEMENT_GET_CLASS (rtpbin),
			"send_rtcp_src_%d");
	data->gst_data.send_rtcp_src_pad = gst_element_request_pad (rtpbin, rtpbin_pad_template,
			"send_rtcp_src_0", NULL);
	g_print ("A new pad %s was created\n",
			gst_pad_get_name (data->gst_data.send_rtcp_src_pad));

	/* Set the latency of the rtpbin */
	g_object_set (G_OBJECT (rtpbin),
			"latency", DEFAULT_LATENCY_MS,
			"rtcp-sync-interval",1000, NULL);

	/*
	 * RTP H.264 Depayloader
	 */
	depayloader = gst_element_factory_make ("rtph264depay","depayloader");
	VC_CHECK_ELEMENT_ERROR(depayloader,"rtph264depay");
	data->gst_data.depayloader = depayloader;

	/* If we are ARM architecture, then assume that we are an i.MX processor and build
	   the pipeline to decode and display using the i.MX plugins */
#ifdef __arm__
	int assume_imx = 1;
#else
	int assume_imx = 0;
#endif

	if (assume_imx){
		/*
	 	 * i.MX VPU decoder
	 	 */
		decoder = gst_element_factory_make ("vpudec", "decoder");
		VC_CHECK_ELEMENT_ERROR(decoder,"vpudec");

		/*
	 	 * i.MX Video sink
	 	 */
		sink = gst_element_factory_make ("mfw_v4lsink", "sink");
		VC_CHECK_ELEMENT_ERROR(sink,"mfw_v4lsink");

		/* Set max lateness to .5 seconds */
		g_object_set (G_OBJECT(sink), "max-lateness", (long long)50000000, NULL);
		g_object_set (G_OBJECT(sink), "sync", FALSE, NULL);
		g_object_set (G_OBJECT(sink), "device", "/dev/video16",NULL);
		
		/* Add elements into the pipeline */
		g_print("  Adding elements to pipeline...\n");

		gst_bin_add_many (GST_BIN (data->gst_data.pipeline),
			          rtp_udpsrc,
			          rtcp_udpsrc,
			          rtpbin,
			          rtcp_udpsink,
			          depayloader,
			          decoder,
			          sink,
			          NULL);

		/* Link some of the elements together */
		g_print("  Linking some elements...\n");

		if(!gst_element_link_many (depayloader, decoder,  sink, NULL))
			g_print("Error: could not link the depayloader, decoder, and sink\n");
		
	}
	else {
		/*
	 	 * ffmpeg decoder
	 	 */
		decoder = gst_element_factory_make ("ffdec_h264", "decoder");
		VC_CHECK_ELEMENT_ERROR(decoder,"ffdec_h264");
		
		/*
		 *
		 */
		converter = gst_element_factory_make ("ffmpegcolorspace", "converter");
		VC_CHECK_ELEMENT_ERROR(converter,"ffmpegcolorspace");

		/*
	 	 * i.MX Video sink
	 	 */
		sink = gst_element_factory_make ("autovideosink", "sink");
		VC_CHECK_ELEMENT_ERROR(sink,"autovideosink");
		
		/* Add elements into the pipeline */
		g_print("  Adding elements to pipeline...\n");

		gst_bin_add_many (GST_BIN (data->gst_data.pipeline),
			          rtp_udpsrc,
			          rtcp_udpsrc,
			          rtpbin,
			          rtcp_udpsink,
			          depayloader,
			          converter,
			          decoder,
			          sink,
			          NULL);

		/* Link some of the elements together */
		g_print("  Linking some elements...\n");

		if(!gst_element_link_many (depayloader, decoder, converter, sink, NULL))
			g_print("Error: could not link the depayloader, decoder, converter, and sink\n");	
		
	}
	
	/*
	 * Connect to the pad-added signal for the rtpbin.  This allows us to link
	 * the dynamic RTP source pad to the depayloader when it is created.
	 */
	if(!g_signal_connect (rtpbin, "pad-added",
			G_CALLBACK (vc_pad_added_handler), data))
		g_print("Error: could not add signal handler\n");

	/*
	 * Connect the on-timeout signal
	 */
	if(!g_signal_connect (rtpbin, "on-timeout", G_CALLBACK (vc_on_timeout_handler), data))
		g_print("Error: could not add on-timeout signal handler\n");

	/* Link some of the elements together */
	g_print("  Linking RTP and RTCP sources to rtpbin...\n");
	/* Link the payloader src pad to the rtpbin send_vrtp_sink_pad */
	if(!gst_element_link_pads(rtp_udpsrc, "src", rtpbin, "recv_rtp_sink_0"))
		g_print("Error: could not link udp source to rtp sink\n");

	/* Link the rtpbin send_vrtp_src_pad to the rtp_udpsink sink pad */
	if(!gst_element_link_pads(rtcp_udpsrc, "src", rtpbin, "recv_rtcp_sink_0"))
		g_print("Error: could not link udp source to rtcp sink\n");

	/* Link the rtpbin sent_rctp_src_pad to the rtcp_udpsink (udpsink) sink pad */
	if(!gst_element_link_pads(rtpbin, "send_rtcp_src_0", rtcp_udpsink, "sink"))
		g_print("Error: could not link rtcp source to udp sink\n");

	/* Set the pipeline to "playing" state*/
	g_print ("Now playing\n");
	ret = gst_element_set_state (data->gst_data.pipeline, GST_STATE_PLAYING);

	if (ret == GST_STATE_CHANGE_FAILURE) {
		g_printerr ("Unable to set the pipeline to the playing state.\n");
		gst_object_unref (data->gst_data.pipeline);
		return -1;
	}

	return 0;
}

/*
 * This function will be called by the pad-added signal
 */

static void vc_pad_added_handler (GstElement *src,
		GstPad *new_pad, vc_data *data) {
	GstPad *sink_pad = gst_element_get_static_pad (data->gst_data.depayloader, "sink");
	GstPadLinkReturn ret;
	GstCaps *new_pad_caps = NULL;
	GstStructure *new_pad_struct = NULL;
	const gchar *new_pad_type = NULL;

	g_print ("Received new pad '%s' from '%s':\n", GST_PAD_NAME (new_pad), GST_ELEMENT_NAME (src));

	/* Check the new pad's name */
	if (!g_str_has_prefix (GST_PAD_NAME (new_pad), "recv_rtp_src_")) {
		g_print ("  It is not the right pad.  Need recv_rtp_src_. Ignoring.\n");
		goto exit;
	}

	/* If our converter is already linked, we have nothing to do here */
	if (gst_pad_is_linked (sink_pad)) {
		g_print (" Sink pad from %s already linked. Ignoring.\n", GST_ELEMENT_NAME (src));
		goto exit;
	}

	/* Check the new pad's type */
	new_pad_caps = gst_pad_get_caps (new_pad);
	new_pad_struct = gst_caps_get_structure (new_pad_caps, 0);
	new_pad_type = gst_structure_get_name (new_pad_struct);

	/* Attempt the link */
	ret = gst_pad_link (new_pad, sink_pad);
	if (GST_PAD_LINK_FAILED (ret)) {
		g_print ("  Type is '%s' but link failed.\n", new_pad_type);
	} else {
		g_print ("  Link succeeded (type '%s').\n", new_pad_type);
	}

exit:
	/* Unreference the new pad's caps, if we got them */
	if (new_pad_caps != NULL)
		gst_caps_unref (new_pad_caps);

	/* Unreference the sink pad */
	gst_object_unref (sink_pad);
}

/*
 * Timeout Handler
 */

static void vc_on_timeout_handler (GstElement *src, int ssrc, vc_data *data) {

	g_print ("Timeout from ssrc: %d\n", ssrc);

}

/*******************************************************************************
	vs_process_char_cmd(): Process a character command
*******************************************************************************/
int vc_process_char_cmd(vc_data *data, char *buf)
{

	char cmdchar;
	cmdchar = toupper(buf[0]);  /* pick off the first character for now */

	switch (cmdchar) {
	case 'P': /* Toggle the state of the pipeline */

		/*if(data->sock_client > 0)
			write(data->sock_client,"P\n", 2);
		break; */
		link_send_ping();
		break;

	case 'Q': /* Quit */
		data->exit_flag = 1;
		break;

	case 'L': /* Run Link Test - this blocks for the entire test */
		vc_stop_timer(data);
		link_random_loopback_test();
		vc_start_timer(data, VC_LINK_WDOG_INTERVAL);
		break;

	default:
		g_printerr ("Unknown command %c\n", (char)cmdchar);
		break;
	}

	return 0;
}

/*******************************************************************************
	vc_create_client() : Creates a client socket and attempts a connection
	to the server.  The address and port of the server are in the vc_cfg_data
	structure, which is loaded from the configuration file.
*******************************************************************************/
int vc_create_client(vc_data *data)
{
	/*
	 * Start client and attempt to connect.  Call blocks until a either the
	 * is successful or the fails.
	 */
	int state = link_create_client();



	if(state == LINK_CLIENT_CONNECTED) {
		/*
		 * Client is connected, set up the fds events for the main polling loop.
		 */
		data->fds[FD_INDEX_SOCK_CLIENT].fd = link_get_client_fd();
		data->fds[FD_INDEX_SOCK_CLIENT].events = POLLIN | POLLHUP;
	}
	else if (state == LINK_CLIENT_PENDING ) {
		/*
		 * Client connection was not available either because the server was
		 * not available or because the server couldn't be found on the
		 * network (EHOSTUNREACH)
		 */

		/*
		 * Do nothing with the fds because we do not yet have a valid
		 * connection, but be sure that nothing is set to poll.
		 */
		data->fds[FD_INDEX_SOCK_CLIENT].fd = -1;
		data->fds[FD_INDEX_SOCK_CLIENT].events = 0;
	}
	else {
		/* Client connection failed */
		debug_printf("%s: Client connection failed...\n", __func__);
		data->fds[FD_INDEX_SOCK_CLIENT].fd = -1;
		data->fds[FD_INDEX_SOCK_CLIENT].events = 0;
		return -1;
	}

	return 0;
}

/*******************************************************************************
	vc_close_client() : Closes client socket in an orderly fashion.
*******************************************************************************/
int vc_close_client(vc_data *data)
{
	link_close_client();

	/* Invalidate the FD and pollfd struct */
	data->sock_client = -1;
	data->fds[FD_INDEX_SOCK_CLIENT].fd = -1;
	data->fds[FD_INDEX_SOCK_CLIENT].events = 0;
	data->fds[FD_INDEX_SOCK_CLIENT].revents = 0;

	/* Should be clean now, leave */
	return 0;
}

/*******************************************************************************
	Cleanup function
*******************************************************************************/
int vc_gst_pipeline_clean(vc_data *data) {

	GstStateChangeReturn ret;

	/* Cleanup Gstreamer */
	if(!data->gst_data.pipeline)
		return 0;

	/* Send the main loop a quit signal */
	g_main_loop_quit(data->gst_data.loop);
	g_main_loop_unref(data->gst_data.loop);

	ret = gst_element_set_state (data->gst_data.pipeline, GST_STATE_NULL);
	if (ret == GST_STATE_CHANGE_FAILURE) {
		g_printerr ("Unable to set the pipeline to the NULL state.\n");
		gst_object_unref (data->gst_data.pipeline);
		return -1;
	}

	g_print ("Deleting pipeline\n");
	gst_object_unref (GST_OBJECT (data->gst_data.pipeline));
	gst_object_unref (GST_OBJECT (data->gst_data.recv_rtcp_sink_pad));
	gst_object_unref (GST_OBJECT (data->gst_data.recv_rtp_sink_pad));
	gst_object_unref (GST_OBJECT (data->gst_data.send_rtcp_src_pad));

	/* Zero out the structure */
	memset(&data->gst_data, 0, sizeof(vc_gst_data));

	return 0;
}


/*******************************************************************************
	Cleanup function
*******************************************************************************/
int vc_cleanup(vc_data *data)
{
	g_print("Cleanup function\n");

	vc_gst_pipeline_clean(data);

	/* Close stdin */
	close(data->fds[0].fd);

	/* Close client socket */
	close(data->sock_client);

	/* Restore signal handler */
	vc_sigint_restore();

	return 0;
}



/*******************************************************************************
	MainLoop
*******************************************************************************/
int vc_mainloop(vc_data* data)
{
	int pollret;
	int fileret;
	char buf[STDIN_BUF_SIZE];
	link_message_t msg;
	int myerr;

	while (1) {

		/* Test for exit flag */
		if(data->exit_flag != 0)
			break;

		/* Run the GMainLoop iteration manually */
		/* TODO: Guard some of these checks with mutexes */
		if(data->gst_data.context)
			g_main_context_iteration(data->gst_data.context, FALSE);

		if ((pollret = poll(data->fds, NUM_POLL_FDS, POLL_TIMEOUT_MSECS)) == 0) {
			/*
			 * Timeout on poll. Check the link state to see what we need to do.
			 * If the link state is connected, then do nothing.
			 */

			if((fileret = link_get_client_state()) == LINK_CLIENT_CONNECTED)
				continue;

			if((fileret == LINK_CLIENT_NONE) || (fileret == LINK_CLIENT_PENDING)){

				/* We need a new client connection */
				if(vc_create_client(&app_data) < 0) {
					/*
					 * Big problem creating a link.  Some catastrophic error.
					 */
					debug_printf("%s: Error creating client\n",__func__);
					return -1;
				}

				/* Did we succeed? */
				if((fileret = link_get_client_state()) == LINK_CLIENT_CONNECTED) {

					/*
					 * Start a pipeline
					 */
					if(vc_gst_pipeline_init(&app_data) == -1) {
						printf("Gstreamer pipeline creation and init failed\n");
						/* No point in sticking around, this is a critical failure */
						break;
					}

					if(vc_setup_timer(data) < 0)
						break;

					vc_start_timer(data, VC_LINK_WDOG_INTERVAL);
					data->watchdog_state = WDOG_STATE_ACTIVE;
				}

				/*
				 * We tried to connect again and failed, but not because there
				 * is some critical network problem such as no physical media.
				 * So we can continue and try again the next timeout.
				 */
			}
		}
		else if (pollret < 0) {
			printf("Poll returned error %s\n",strerror(errno));
			break;
		}

		/* A event occured on one of our file descriptors for us to handle. */
		if(data->fds[FD_INDEX_STDIN].revents & POLLIN) {

			//debug_printf("Stdin has data to read.\n");

			/* Data is waiting on /dev/stdin */
			fileret = read(data->fds[FD_INDEX_STDIN].fd, buf, STDIN_BUF_SIZE);
			if (fileret <= 0) {
				printf("Unable to read data from /dev/stdin\n");
				continue;
			}

			vc_process_char_cmd(data, buf);

		}

		/* Client socket has data to read */
		if(data->fds[FD_INDEX_SOCK_CLIENT].revents & POLLIN) {

			//debug_printf("%s: Client socket POLLIN.\n",__func__);

			/* We should have a message on the client socket */
			fileret = link_recv_msg(&msg, 1000);
			if (fileret < 0) {
				myerr = errno;
				debug_printf("%s: Error: client socket %s\n",__func__, strerror(myerr));
				continue;
			}
			if (fileret == 0) {
				debug_printf("%s: Server disconnected.\n",__func__);

				vc_close_client(data);
				vc_gst_pipeline_clean(data);
				vc_stop_timer(data);

			}
			else if (fileret > 0) {

				link_process_msg(&msg);

				/* Reset timer */
				data->watchdog_state = WDOG_STATE_ACTIVE;
				vc_start_timer(data, VC_LINK_WDOG_INTERVAL);
			}
		}

		/* Client socket hung up from remote side */
		if(data->fds[FD_INDEX_SOCK_CLIENT].revents & POLLHUP) {

			//printf("Server connection closed: POLLHUP.\n");

			vc_stop_timer(data);
			vc_close_client(data);
			vc_gst_pipeline_clean(data);
		}

		/*
		 * Link watchdog timer expired
		 *
		 * Explanation of WDOG states:
		 * WDOG_STATE_ACTIVE : Watchdog timer is waiting for watchdog to expire
		 * or to be reset.
		 * WDOG_STATE_PENDING: Watchdog has expired once (no data from remote
		 * in the WDOG_INTERVAL).  In this ctate, we should send a ping to the
		 * remote to test link connection.  The response from the remote will
		 * tell us the link state.  This is handled in the client socket fd
		 * handling.  The WDOG is reset to expire again.
		 * WDOG_STATE_INACTIVE:  If the WDOG was pending and we've expired the
		 * link timer again (watchdog) then the remote is unresponsive and we
		 * should consider it disconnected and do things appropriate for a
		 * disconnected link.
		 *
		 * To summarize:
		 * ACTIVE ---> (timer expires) ---> PENDING (and send ping packet, reset timer)
		 * PENDING ---> (timer expires) ---> INACTIVE (shut down and restart link)
		 * INACTIVE ---> (link reestablished) ---> ACTIVE
		 */

		if(data->fds[FD_INDEX_TIMER].revents & POLLIN) {

			//debug_printf("%s: timer expired.\n",__func__);

			if(data->watchdog_state == WDOG_STATE_ACTIVE) {

				/*
				 * Send a ping message and set state to pending
				 */
				link_send_ping();
				data->watchdog_state = WDOG_STATE_PENDING;

				/* Reset timer */
				vc_start_timer(data, VC_LINK_WDOG_INTERVAL);
			}
			else {

				/* Reset timer */
				data->watchdog_state = WDOG_STATE_INACTIVE;
				vc_stop_timer(data);
				vc_close_client(data);
				vc_gst_pipeline_clean(data);
			}
		}
	}

	return 0;
}


void vs_print_help(void){
	printf("glivec - Gstreamer Live Example Client \n"
			"(C) John Weber, Avnet Electronics Marketing\n\n");
	printf("Usage: glivec -s <server IP address> [-dqh]\n");
	printf("  -s <Server IP address>  IP address of server (e.g. 192.168.0.100) \n"
		   "  -d: Daemonize mode.  Do not open stdin for input.\n"
		   "  -q: Quiet: Do not print copyright information.\n"
		   "  -h: Help: print this message\n\n");
}

int main (int   argc, char *argv[])
{
	int opt;
	int quiet = 0;

	/* Initialize the app_data structure */
	vc_init_data(&app_data);

	/* Parse command line */
	while ((opt = getopt(argc, argv, "dqs:h")) != -1) {
		switch (opt) {
		case 'd':
			/* Daemonize - do not open /dev/stdin */
			app_data.daemonize = 1;
			break;
		case 'q':
			/* Quiet - do not print startup messages */
			quiet = 1;
			break;
		case 's':
			/* Server IP address */
			strcpy(app_data.cfg.server_ip_addr, optarg);
			break;
		case 'h':
		default: /* '?' */
			vs_print_help();
			return 0;
		}
	}
	
	if(!strlen(app_data.cfg.server_ip_addr)){
		vs_print_help();
		return 0;
	}

	if(!quiet){
		printf("glivec - Gstreamer Live Example Client \n"
				"(C) John Weber, Avnet Electronics Marketing\n");
	}

	/* Initialize configuration data */
	app_data.cfg.rtp_recv_port  = DEFAULT_RX_RTP_PORT;
	app_data.cfg.rtcp_send_port = DEFAULT_TX_RTCP_PORT;
	app_data.cfg.rtcp_recv_port = DEFAULT_RX_RTCP_PORT;
	app_data.cfg.server_port    = DEFAULT_SERVER_PORT;

	printf( "Server IP address:           %s\n"
			"Server port:                 %d\n"
			"Sending RTP data on port:    %d\n"
			"Sending RTCP data on port:   %d\n"
			"Expecting RTCP data on port: %d\n",
			app_data.cfg.server_ip_addr,
			app_data.cfg.server_port,
			app_data.cfg.rtp_recv_port,
			app_data.cfg.rtcp_send_port,
			app_data.cfg.rtcp_recv_port);

	/* Setup the file descriptors for polling, starting with /dev/stdin */
	if(!app_data.daemonize){
		app_data.fds[FD_INDEX_STDIN].fd = open("/dev/stdin", O_RDONLY);
		if( app_data.fds[FD_INDEX_STDIN].fd == -1) {
			printf("Error opening /dev/stdin for reading\n");
			return -1;
		}
		app_data.fds[FD_INDEX_STDIN].events = POLLIN;
	}
	else {
		printf("glivec starting as background task.\n");
	}

	if(link_init_as_client((char*)app_data.cfg.server_ip_addr, app_data.cfg.server_port) < 0){
		debug_printf("%s: Failed to init link as client\n", __func__);
		return -1;
	}

	/* Initialization */
	gst_init (&argc, &argv);

	vc_sigint_setup();

	/* Main Loop */
	printf ("Running...\n");

	vc_mainloop(&app_data);

	/* Out of the main loop, clean up nicely */
	printf ("Returned, stopping playback\n");

	return vc_cleanup(&app_data);

}
