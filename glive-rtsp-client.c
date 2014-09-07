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
#define DEFAULT_RTSP_PORT		8554
#define DEFAULT_LATENCY_MS		100

static void vc_sigint_restore (void);

typedef struct _vc_cfg_data {
	int server_port;
	char server_ip_addr[20];
} vc_cfg_data;

typedef struct _vc_gst_data {
	GMainLoop *loop;
	GMainContext *context;
	GstElement *pipeline;
	GstElement *depayloader;
	GstPad *recv_rtp_src_pad;
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

/* Global data */
vc_data app_data;

static void vc_pad_added_handler (GstElement *src, GstPad *new_pad, vc_data *data);

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
#define URL_SIZE 100
int vc_gst_pipeline_init(vc_data *data)
{
	GstStateChangeReturn ret;
	GstElement *rtspsrc,*depayloader, *decoder, *converter, *sink;
	char url[URL_SIZE];

	/* Template */
	GstPadTemplate* rtspsrc_pad_template;
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
	rtspsrc = gst_element_factory_make ("rtspsrc", "rtspsrc");
	VC_CHECK_ELEMENT_ERROR(rtspsrc,"rtspsrc");

	snprintf(url,URL_SIZE,"rtsp://%s:%d/camera",data->cfg.server_ip_addr,data->cfg.server_port);

	printf("URL: %s\n",url);

	g_print ("Setting RTSP source properties: \n");
	g_object_set (G_OBJECT (rtspsrc),
			"location", url,
			"latency", DEFAULT_LATENCY_MS,
			NULL);

	/*
	 * RTP H.264 Depayloader
	 */
	depayloader = gst_element_factory_make ("rtph264depay","depayloader");
	VC_CHECK_ELEMENT_ERROR(depayloader,"rtph264depay");
	data->gst_data.depayloader = depayloader;

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

	/*
	 * Request pads from rtpbin, starting with the RTP receive sink pad,
	 * This pad receives RTP data from the network (rtp-udpsrc).
	 */
	rtspsrc_pad_template = gst_element_class_get_pad_template (
			GST_ELEMENT_GET_CLASS (rtspsrc),
			"recv_rtp_src_%d");
	/* Use the template to request the pad */
	data->gst_data.recv_rtp_src_pad = gst_element_request_pad (rtspsrc, rtspsrc_pad_template,
			"recv_rtp_src_0", NULL);
	/* Print the name for confirmation */
	g_print ("A new pad %s was created\n",
			gst_pad_get_name (data->gst_data.recv_rtp_src_pad));

	/* Add elements into the pipeline */
	g_print("  Adding elements to pipeline...\n");

	gst_bin_add_many (GST_BIN (data->gst_data.pipeline),
			rtspsrc,
			depayloader,
			decoder,
			converter,
			sink,
			NULL);

	/* Link some of the elements together */
	g_print("  Linking some elements...\n");

	if(!gst_element_link_many (depayloader, decoder, converter, sink, NULL))
		g_print("Error: could not link all elements\n");

	/*
	 * Connect to the pad-added signal for the rtpbin.  This allows us to link
	 * the dynamic RTP source pad to the depayloader when it is created.
	 */
	if(!g_signal_connect (rtspsrc, "pad-added",
			G_CALLBACK (vc_pad_added_handler), data))
		g_print("Error: could not add signal handler\n");

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

/*******************************************************************************
	vs_process_char_cmd(): Process a character command
*******************************************************************************/
int vc_process_char_cmd(vc_data *data, char *buf)
{

	char cmdchar;
	cmdchar = toupper(buf[0]);  /* pick off the first character for now */

	switch (cmdchar) {
	case 'Q': /* Quit */
		data->exit_flag = 1;
		break;

	default:
		g_printerr ("Unknown command %c\n", (char)cmdchar);
		break;
	}

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
			 * Timeout on poll.
			 */

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
	}

	return 0;
}


void vs_print_help(void){
	printf("glive-rtsp-client - Gstreamer Live Example RTSP Client \n"
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
	app_data.cfg.server_port = DEFAULT_RTSP_PORT;

	printf( "Server IP address:           %s\n"
			"RTSP port:                   %d\n",
			app_data.cfg.server_ip_addr,
			app_data.cfg.server_port);

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
		printf("glive-rtsp-server starting as background task.\n");
	}

	/* Initialization */
	gst_init (&argc, &argv);

	vc_sigint_setup();

	/* Main Loop */
	printf ("Running...\n");

	if(vc_gst_pipeline_init(&app_data) == -1) {
		printf("Gstreamer pipeline creation and init failed\n");
		/* No point in sticking around, this is a critical failure */
		goto cleanup;
	}

	vc_mainloop(&app_data);

	/* Out of the main loop, clean up nicely */
	printf ("Returned, stopping playback\n");

cleanup:
	return vc_cleanup(&app_data);

}
