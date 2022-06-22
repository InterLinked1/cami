/*
 * CAMI -- C Asterisk Manager Interface "Simple AMI" demo
 *
 * Copyright (C) 2022, Naveen Albert
 *
 * Naveen Albert <asterisk@phreaknet.org>
 *
 * This program is free software, distributed under the terms of
 * the Mozilla Public License Version 2.
 */

/*! \file
 *
 * \brief C Asterisk Manager Interface "Simple AMI" demo
 *
 * \author Naveen Albert <asterisk@phreaknet.org>
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "include/cami.h"
#include "include/cami_actions.h"

/*
 * This is a simple demo program that will use C AMI to log in,
 * print out all the active channels, then exit. You do NOT need
 * this file to use C-AMI. Typically, you will simply include cami.c,
 * cami.h, and cami_actions.h in the source of your project and
 * use it directly. To use this simple demo program, simply download
 * these files and run "make" using the provided Makefile.
 */

/*! \brief Callback function executing asynchronously when new events are available */
static void simple_callback(struct ami_event *event)
{
	const char *eventname = ami_keyvalue(event, "Event");
	printf("(Callback) Event Received: %s\n", eventname);
#if 0
	/* Or, you could print out the entire event contents for debugging, or to see what's there: */
	ami_dump_event(event); /* Do something with event */
#endif
	ami_event_free(event); /* Free event when done with it */
}

static void simple_disconnect_callback(void)
{
	printf("(Callback) AMI was forcibly disconnected...\n");
	/* Try to re-establish the connection, or other error handling... */
}

static int simple_ami(const char *hostname, const char *username, const char *password)
{
	struct ami_response *resp = NULL;
#if 0
	ami_set_debug(STDERR_FILENO); /* Not recommended for daemon programs */
#endif
	if (ami_connect(hostname, 0, simple_callback, simple_disconnect_callback)) {
		return -1;
	}
	if (ami_action_login(username, password)) {
		fprintf(stderr, "Failed to log in\n");
		return -1;
	}
	fprintf(stderr, "*** Successfully logged in to AMI on %s (%s) ***\n", hostname, username);
	resp = ami_action_show_channels();
	if (resp) { /* Got a response to our action */
#define AMI_CHAN_FORMAT "%-40s | %8s | %s\n"
		int i;
		/* The first "event" is simply the fields in the response itself (so ignore it). */
		/* The last event is simply "CoreShowChannelsComplete", for this action response (so ignore it). */
		printf("Current # of active channels: %d\n", resp->size - 2);
		printf(AMI_CHAN_FORMAT, "Channel", "Duration", "Caller ID");
		for (i = 1; i < resp->size - 1; i++) {
			printf(AMI_CHAN_FORMAT, ami_keyvalue(resp->events[i], "Channel"), ami_keyvalue(resp->events[i], "Duration"), ami_keyvalue(resp->events[i], "CallerIDNum"));
		}
#if 0
		/* Or, you could print out the entire response contents for debugging, or to see what's there: */
		ami_dump_response(resp);
#endif
		ami_resp_free(resp); /* Free response when done with it */
	}
	ami_disconnect();
	return 0;
}

int main(int argc,char *argv[])
{
	if (simple_ami("127.0.0.1", "test", "test")) {
		exit(EXIT_FAILURE);
	}
	return 0;
}
