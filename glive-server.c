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
#include <gst/rtsp-server/rtsp-server.h>
#include <glib.h>
#include <signal.h>
#include <string.h>
#include <stropts.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/timerfd.h> /* For timerfd functions */
#include <netinet/in.h>


#define STR(s) #s
#define XSTR(s) STR(s)
#pragma message "Gstreamer Version=" XSTR(GST_VERSION_MAJOR) "." XSTR(GST_VERSION_MINOR) "." XSTR(GST_VERSION_MICRO)

#if GST_VERSION_MAJOR >= 1
#define GSTREAMER1_0
#endif

/* Defaults */
#ifdef GSTREAMER1_0
#define DEFAULT_LAUNCH_IMX6  "( imxv4l2src ! video/x-raw,format=I420,width=640,height=480,framerate=30/1 ! imxvpuenc_h264 bitrate=1000 ! rtph264pay name=pay0 pt=96 )"
#define DEFAULT_LAUNCH_THERMAL "( v4l2src device=/dev/video1 ! videoconvert ! imxvpuenc_h264 bitrate=1000 ! rtph264pay name=pay0 pt=96 )"
#else
#define DEFAULT_LAUNCH_IMX6 "( imxv4l2src capture-mode=4 ! vpuenc codec=6 bitrate=1000000 ! rtph264pay name=pay0 pt=96 )"
#define DEFAULT_LAUNCH_THERMAL "( v4l2src device=/dev/video1 ! ffmpegcolorspace ! vpuenc codec=6 bitrate=1000000 ! rtph264pay name=pay0 pt=96 )"
#endif

#ifdef GSTREAMER1_0
#define DEFAULT_LAUNCH_FTF "( imxv4l2src ! video/x-raw,format=I420,framerate=30/1,width=640,height=480 ! \
videomixer name=mix sink_0::alpha=1.0 sink_1::alpha=1.0 ! imxvpuenc_h264 bitrate=2000 ! rtph264pay name=pay0 pt=96 \
v4l2src device=/dev/video1 ! mix. )"
#endif

#define DEFAULT_LAUNCH_PC "( v4l2src ! x264enc bitrate=1000 ! rtph264pay name=pay0 pt=96 )"
#define DEFAULT_SERVER_PORT 8554



#define LS_BUFSIZE 512

typedef struct _vs_cfg_data {
	int server_port;
	char * launch_string;
	int dual_mode;
	int ftf_demo_mode;
} vs_cfg_data;

/* Global data */
vs_cfg_data cfg_data;

/* Initialize a vs_cfg_data structure */
void vs_init_data(vs_cfg_data *data) {

	/* Zero out the structure */
	memset(data, 0, sizeof(vs_cfg_data));

}


static gboolean
vs_rtsp_timeout (GstRTSPServer * server, gboolean ignored)
{
  GstRTSPSessionPool *pool;

  pool = gst_rtsp_server_get_session_pool (server);
  gst_rtsp_session_pool_cleanup (pool);
  g_object_unref (pool);

  return TRUE;
}


int vs_rtsp_mainloop(vs_cfg_data* cfg) {

	GMainLoop *loop;
	GstRTSPServer *server;

#ifdef GSTREAMER1_0
	// Use GstRTSPMountPoints for Gstreamer 1.0
	GstRTSPMountPoints *mountpoints;
#else
	// Use this for Gstreamer < 1.0
	GstRTSPMediaMapping *mapping;
#endif

	GstRTSPMediaFactory *factory, *factory_thermal;

	loop = g_main_loop_new(NULL, FALSE);
	server = gst_rtsp_server_new();

	// Set the server port
	char port_string[30];
	sprintf(port_string, "%d", cfg->server_port);
	gst_rtsp_server_set_service(server, port_string);

#ifdef GSTREAMER1_0
	// Note: Gstreamer 1.0 (and greater) renamed the 'mapping' to 'mount_points'
	mountpoints = gst_rtsp_server_get_mount_points(server);
#else
	mapping = gst_rtsp_server_get_media_mapping(server);
#endif

	factory = gst_rtsp_media_factory_new();

	factory_thermal = gst_rtsp_media_factory_new();

	/* If we are ARM architecture, then assume that we are an i.MX processor and build
	   the pipeline to decode and display using the i.MX plugins */
#ifdef __arm__
	int assume_imx = 1;
#else
	int assume_imx = 0;
#endif

	/* Set up RTSP launch command */
	if(!strlen(cfg->launch_string) && (cfg->dual_mode == 0)) {
		if (assume_imx)
			strcpy(cfg->launch_string, DEFAULT_LAUNCH_IMX6);
		else
			strcpy(cfg->launch_string, DEFAULT_LAUNCH_PC);
	}

	if (cfg->dual_mode) {
		printf( "Setting thermal camera RTSP pipeline to: \n   %s\n", DEFAULT_LAUNCH_THERMAL);
		gst_rtsp_media_factory_set_launch(factory_thermal, DEFAULT_LAUNCH_THERMAL);

		printf( "Setting visible camera RTSP pipeline to: \n   %s\n", DEFAULT_LAUNCH_IMX6);
		gst_rtsp_media_factory_set_launch(factory, DEFAULT_LAUNCH_IMX6);
	}
#ifdef GSTREAMER1_0
	else if (cfg->ftf_demo_mode) {
		printf( "Setting camera RTSP pipeline to: \n   %s\n", DEFAULT_LAUNCH_FTF);
		gst_rtsp_media_factory_set_launch(factory, DEFAULT_LAUNCH_FTF);
	}
#endif
	else {
		printf( "Setting visible camera RTSP pipeline to: \n   %s\n", cfg->launch_string);
		gst_rtsp_media_factory_set_launch(factory, cfg->launch_string);
	}

	gst_rtsp_media_factory_set_shared(factory, TRUE);
	if(cfg->dual_mode) gst_rtsp_media_factory_set_shared(factory_thermal, TRUE);

#ifdef GSTREAMER1_0
	gst_rtsp_mount_points_add_factory(mountpoints, "/camera", factory);
	if(cfg->dual_mode) gst_rtsp_mount_points_add_factory(mountpoints, "/thermal", factory_thermal);
	g_object_unref(mountpoints);
#else
	gst_rtsp_media_mapping_add_factory(mapping, "/camera", factory);
	if(cfg->dual_mode) gst_rtsp_media_mapping_add_factory(mapping, "/thermal", factory_thermal);
	g_object_unref(mapping);
#endif

	/* attach the server to the default main context */
	if (gst_rtsp_server_attach(server, NULL ) == 0)
		goto failed;

	/* add a timeout for the session cleanup */
	g_timeout_add_seconds(2, (GSourceFunc) vs_rtsp_timeout, server);

	/* start serving, this never stops */
	if(cfg->dual_mode)
		g_print ("Streams ready at rtsp://<THIS IP ADDRESS>:%d/camera and /thermal\n",cfg->server_port);
	else
		g_print ("Stream ready at rtsp://<THIS IP ADDRESS>:%d/camera\n",cfg->server_port);

	g_main_loop_run(loop);

	return 0;

	failed: {
		g_print("RTSP: Failed to attach the server\n");
		return -1;
	}
}

/*******************************************************************************
 Main
 *******************************************************************************/

int main(int argc, char *argv[]) {
	int opt;
	int quiet = 0;

	/* Initialize the app_data structure */
	vs_init_data(&cfg_data);
	cfg_data.launch_string = malloc(LS_BUFSIZE+1);

	/* Initialize configuration */
	cfg_data.server_port = DEFAULT_SERVER_PORT;
	cfg_data.dual_mode = 0;
	cfg_data.ftf_demo_mode = 0;

	/* Parse command line */
	while ((opt = getopt(argc, argv, "qhdfl:p:")) != -1) {
		switch (opt) {
		case 'q':
			/* Quiet - do not print startup messages */
			quiet = 1;
			break;
		case 'h':
			printf("Usage: %s [-qhl <launch string>]\n", argv[0]);
			printf("  -q: Quiet: Do not print copyright information\n"  
			       "  -h: Help: print this message\n"
			       "  -l <launch string>: launch string to use instead of default\n"
				   "  -p <number>: use this port number instead of the default (8554)");
			break;
		case 'd':
			cfg_data.dual_mode = 1;  // Dual mode
			break;
		case 'l':
			if(optarg)
				sprintf(cfg_data.launch_string,"( %s )", optarg);
			break;
		case 'f':  // FTF Demo mode
			cfg_data.ftf_demo_mode = 1;
			break;
		case 'p':
			if(optarg)
				sscanf(optarg,"%d",&cfg_data.server_port);
			break;
		default: /* '?' */
			break;
		}
	}
	
	if(cfg_data.ftf_demo_mode) cfg_data.dual_mode  = 0;  // FTF mode trumps dual mode.

	if(!quiet){
		printf("glive-server - Gstreamer RTSP Server \n"
			"(C) John Weber, Avnet Electronics Marketing\n");
	}	

	printf("Mode: RTSP on port %d.\n", cfg_data.server_port);
	
	/* RTSP loop */
	gst_init(&argc, &argv);

	vs_rtsp_mainloop(&cfg_data);

	printf("gstreamer main loop exiting.\n");
	free(cfg_data.launch_string);

	return 0;

}
