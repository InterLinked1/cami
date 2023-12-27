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
 * \brief C Asterisk Manager Interface "Simple CLI"
 *
 * \author Naveen Albert <asterisk@phreaknet.org>
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <ctype.h>

#include <cami/cami.h>

/*
 * This is a simple program that will use C AMI to log in,
 * and then accepts AMI commands on STDIN
 * and outputs responses to STDOUT.
 * This is useful for debugging AMI commands and responses.
 * Raw AMI commands are accepted, but do not include ActionID.
 */

/*! \brief Callback function executing asynchronously when new events are available */
static void ami_callback(struct ami_session *ami, struct ami_event *event)
{
	const char *eventname = ami_keyvalue(event, "Event");
	(void) ami;
	printf("(Callback) Event Received: %s\n", eventname);
#ifdef PRINT_EVENTS
	ami_dump_event(event); /* Do something with event */
#endif
	ami_event_free(event); /* Free event when done with it */
}

static void ami_disconnect_callback(struct ami_session *ami)
{
	(void) ami;
	printf("(Callback) AMI was forcibly disconnected...\n");
	exit(EXIT_FAILURE);
}

static int single_ami_command(struct ami_session *ami)
{
	char action[64];
	char buf[8192];
	char *pos;
	size_t left;
	ssize_t res;
	struct ami_response *resp;

	/* Read a full AMI command,
	 * then send it all at once with proper CR LF delimiters. */

	/* Read Action name */
	pos = action;
	left = sizeof(action);
	res = getline(&pos, &left, stdin);
	if (res <= 0) {
		return res;
	}

	/* Remove newline from action */
	pos = strchr(pos, '\n');
	if (!pos) {
		return -1;
	}
	*pos = '\0';

	/* Get rid of Action: */
	pos = action;
	pos = strchr(pos, ':');
	if (!pos) {
		fprintf(stderr, "Must begin with 'Action:'\n");
		return -1;
	}

	pos++;
	while (isspace(*pos)) {
		pos++;
	}

	memmove(action, pos, strlen(pos) + 1);

	/* Read remainder of command */
	pos = buf;
	left = sizeof(buf);
	for (;;) {
		res = getline(&pos, &left, stdin);
		if (res <= 0) {
			return res;
		}
		if (!strncasecmp(pos, "ActionID:", strlen("ActionID:"))) {
			continue; /* Ignore ActionID, since CAMI will autoadd it */
		}
		pos += res;
		left -= res;
		if (*(pos - 1) == '\n' && res > 1 && *(pos - 2) != '\r') {
			/* Change LF endings into CR LF endings */
			*(pos - 1) = '\r';
			*pos = '\n';
			if (!--left) {
				fprintf(stderr, "Buffer exhaustion\n");
				return -1; /* No room for NUL */
			}
			pos++;
			*pos = '\0';
		}
		if (res <= 2) {
			break; /* Empty line signals end of action */
		}
	}

	/* Remove final CR LF, since CAMI will add that. */
	pos = strrchr(buf, '\r');
	if (pos) {
		*pos = '\0';
	}

	resp = ami_action(ami, action, "%s", buf);
	if (!resp) {
		fprintf(stderr, "AMI action '%s' failed\n", action);
		return -1;
	}
	ami_dump_response(resp);
	ami_resp_free(resp); /* Free response when done with it (just LF or CR LF) */
	return 1;
}

int main(int argc,char *argv[])
{
	char c;
	static const char *getopt_settings = "?dhl:p:u:";
	char ami_host[92] = "127.0.0.1"; /* Default to localhost */
	char ami_username[64] = "";
	char ami_password[64] = "";
	int debug = 0;
	struct ami_session *ami;

	while ((c = getopt(argc, argv, getopt_settings)) != -1) {
		switch (c) {
		case '?':
		case 'd':
			debug++;
			break;
		case 'h':
			fprintf(stderr, "amicli [options]\n");
			fprintf(stderr, "  -l hostname (default: 127.0.0.1)\n");
			fprintf(stderr, "  -p password (default: read from /etc/asterisk/manager.conf if loopback)\n");
			fprintf(stderr, "  -u username\n");
			return 0;
		case 'l':
			strncpy(ami_host, optarg, sizeof(ami_host) - 1);
			ami_host[sizeof(ami_host) - 1] = '\0';
			break;
		case 'p':
			strncpy(ami_password, optarg, sizeof(ami_password) - 1);
			ami_password[sizeof(ami_password) - 1] = '\0';
			break;
		case 'u':
			strncpy(ami_username, optarg, sizeof(ami_username) - 1);
			ami_username[sizeof(ami_username) - 1] = '\0';
			break;
		default:
			fprintf(stderr, "Invalid option: %c\n", c);
			return -1;
		}
	}

	if (debug > 10) {
		debug = 10;
	}

	if (ami_username[0] && !ami_password[0] && !strcmp(ami_host, "127.0.0.1")) {
		/* If we're running as a privileged user with access to manager.conf, grab the password ourselves, which is more
		 * secure than getting as a command line arg from the user (and kind of convenient)
		 * Not that running as a user with access to the Asterisk config is great either, but, hey...
		 */
		if (ami_auto_detect_ami_pass(ami_username, ami_password, sizeof(ami_password))) {
			fprintf(stderr, "No password specified, and failed to autodetect from /etc/asterisk/manager.conf\n");
			return -1;
		}
	}

	if (!ami_username[0]) {
		fprintf(stderr, "No username provided (use -u flag)\n");
		return -1;
	}

	ami = ami_connect(ami_host, 0, ami_callback, ami_disconnect_callback);
	if (!ami) {
		return -1;
	}
	ami_set_debug_level(ami, debug);
	ami_set_debug(ami, STDERR_FILENO);
	ami_set_discard_on_failure(ami, 0);
	if (ami_action_login(ami, ami_username, ami_password)) {
		fprintf(stderr, "Failed to log in with username %s\n", ami_username);
		return -1;
	}

	fprintf(stderr, "*** Successfully logged in to AMI on %s (%s) ***\n", ami_host, ami_username);
	while (single_ami_command(ami) > 0);
	ami_disconnect(ami);
	ami_destroy(ami);
	return 0;
}
