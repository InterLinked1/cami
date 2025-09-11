/*
 * CAMI -- C Asterisk Manager Interface
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
 * \brief C Asterisk Manager Interface
 *
 * \author Naveen Albert <asterisk@phreaknet.org>
 */

#define _GNU_SOURCE /* needed for vasprintf */

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <sys/socket.h>
#include <netinet/in.h> /* use sockaddr_in */
#include <sys/types.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <errno.h>
#include <string.h> /* use memset */
#include <ctype.h>	/* use isspace */
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <sys/time.h>	/* use gettimeofday */

#ifdef __linux__
#include <alloca.h>
#endif

#include "include/cami.h"

/*! \brief Default Asterisk Manager Interface port is 5038 */
#define AMI_PORT 5038
/*! \brief This is the finale to any message exchange. */
#define AMI_EOM "\r\n\r\n"

#define AMI_MAX_ACTIONID_STRLEN 9
#define AMI_RESPONSE_PREVIEW_SIZE 32
#define OUTBOUND_BUFFER_SIZE 2048

/*! \brief Simple logger, with second:millisecond, lineno display */
#define ami_debug(ami, level, fmt, ...) { \
	if (ami->debug_level >= level) { \
		struct timeval tv; \
		gettimeofday(&tv, NULL); \
		if (ami->debugfd != -1) dprintf(ami->debugfd, "%llu:%03lu : %d : " fmt, (((unsigned long long)tv.tv_sec)), (unsigned long)(tv.tv_usec/1000), __LINE__, ## __VA_ARGS__); \
	} \
}

#define ami_warning(ami, fmt, ...) ami_debug(ami, 1, "WARNING: " fmt, ## __VA_ARGS__)
#define ami_error(ami, fmt, ...) ami_debug(ami, 1, "WARNING: " fmt, ## __VA_ARGS__)

#define strlen_zero(s) ((!s || *s == '\0'))
#define ltrim(s) while (isspace(*s)) s++;
#define rtrim(s) { \
	if (s) { \
		char *back = s + strlen(s); \
		while (back != s && isspace(*--back)); \
		if (*s) { \
			*(back + 1) = '\0'; \
		} \
	} \
}

struct ami_session {
	pthread_t ami_thread;
	pthread_t dispatch_thread;
	pthread_mutex_t ami_read_lock;	/* Reading is protected by the ami_read_lock */
	struct ami_response *current_response;
	int ami_socket;
	int debugfd;
	int debug_level;
	int ami_pipe[2]; 		/* Pipe for sending actions to Asterisk */
	int ami_read_pipe[2];	/* Pipe for reading action responses from Asterisk */
	int ami_event_pipe[2];	/* Pipe for dispatching events to user callback functions */
	void (*ami_callback)(struct ami_session *ami, struct ami_event *event);
	void (*disconnected_callback)(struct ami_session *ami);
	void *cb_data;			/* User callback data */
	int ami_msg_id;
	int tx;
	int rx;
	unsigned int loggedin:1;
	/* Rather than return failed action responses to the user, return NULL.
	 * Errors will be logged to log level 2.
	 * This can make application development easier as you can check for NULL
	 * instead checking if the response was NULL or not successful.
	 * If you must obtain the error messages in your application, this must
	 * be disabled. */
	unsigned int return_null_on_error:1;
};

/* Used for debugging prior to session creation */
static int ami_initial_debugfd = -1;
static int ami_initial_debug_level = 0;

static struct ami_session *ami_session_new(void)
{
	struct ami_session *ami = calloc(1, sizeof(*ami));
	if (!ami) {
		return NULL;
	}
	ami->ami_socket = -1;
	ami->debugfd = ami_initial_debugfd;
	ami->debug_level = ami_initial_debug_level;
	ami->ami_pipe[0] = ami->ami_pipe[1] = -1;
	ami->ami_read_pipe[0] = ami->ami_read_pipe[1] = -1;
	ami->ami_event_pipe[0] = ami->ami_event_pipe[1] = -1;
	ami->return_null_on_error = 1;
	return ami;
}

static int maxwaitms = AMI_MAX_WAIT_TIME;

/* Forward declarations */
static void *ami_event_dispatch(void *varg);
static void ami_event_handle(struct ami_session *ami, char *data);

static void close_pipes(struct ami_session *ami)
{
	close(ami->ami_pipe[0]);
	close(ami->ami_pipe[1]);
	close(ami->ami_read_pipe[0]);
	close(ami->ami_read_pipe[1]);
	close(ami->ami_event_pipe[0]);
	close(ami->ami_event_pipe[1]);
}

static void ami_cleanup(struct ami_session *ami)
{
	close(ami->ami_socket);
	close_pipes(ami);
	ami->ami_socket = -1;
	ami->loggedin = 0;
	ami->tx = ami->rx = 0;
	if (ami->current_response) {
		ami_resp_free(ami->current_response);
		ami->current_response = NULL;
	}
}

static void *ami_loop(void *varg)
{
	int res, got_id = 0, response_pending = 0, event_pending = 0;
	/* It's incoming data (from Asterisk) that could be very large. Outgoing data (to Asterisk) is unlikely to be particularly large. */
	char inbuf[AMI_BUFFER_SIZE];
	char outbuf[OUTBOUND_BUFFER_SIZE];
	struct pollfd fds[2];
	char *laststart, *lasteventstart, *readinbuf, *nextevent;
	char *endofevent;
	struct ami_session *ami;

	ami = varg;
	if (ami->ami_socket < 0) {
		return NULL;
	}

	fds[0].fd = ami->ami_socket;
	fds[0].events = POLLIN;
	fds[1].fd = ami->ami_pipe[0];
	fds[1].events = POLLIN;

	readinbuf = lasteventstart = laststart = inbuf;

	for (;;) {
		res = poll(fds, event_pending || response_pending ? 1 : 2, -1); /* If we're in the middle of reading a response, don't accept any actions to send to Asterisk. */
		pthread_testcancel();
		if (res < 0) {
			if (errno != EINTR) {
				ami_warning(ami, "poll returned error: %s\n", strerror(errno));
			}
			continue;
		}
		/* Data from AMI to deliver to consumer? */
		if (fds[0].revents) {
			res = recv(ami->ami_socket, readinbuf, AMI_BUFFER_SIZE - 2 - (readinbuf - inbuf), 0);
			if (res < 1) {
				break;
			}
			/* This prevents part of the last response from persisting in msg if that one was longer. */
			/* We could memset(inbuf, '\0', AMI_BUFFER_SIZE), but even better: */
			readinbuf[res] = '\0'; /* Won't be out of bounds, since we only read max AMI_BUFFER_SIZE - 2 - (readinbuf - inbuf) */

			/* lasteventstart, not readinbuf, because if it takes multiple reads to get a full event,
			 * we don't have a full event yet so we won't execute the while loop below at all.
			 * However, eventually we will get the end of the event, and then we need to start
			 * from the beginning of the event, which could have been obtained a previous read,
			 * so using readinbuf (which is what we got THIS read) is WRONG. */
			nextevent = lasteventstart;

			/* It is completely possible that we finished reading from the socket but the current response isn't finished yet. */
			if (got_id) { /* The initial ID from Asterisk that we've connected to AMI is the only thing we get that's not an event */
				/* There are two problems we're concerned about:
				 * One is we finish reading from the socket before we get the entire response (if it is a response).
				 * Two is we read more than an entire event/response and we have multiple events on our hands.
				 * Here, we try to address both of these potential issues that could arise.
				 */
				while ((endofevent = strstr(nextevent, AMI_EOM))) {
					char next;
					int starts_response = 0, middle_of_response = 0, end_of_response = 0;
					endofevent += 4; /* This brings us to the end of a particular event. */
					next = *endofevent; /* save the first char of the next event (if there is one, maybe this is the null terminator...) */
					*endofevent = '\0'; /* Now let's pretend like this is the end. */

					ami_debug(ami, 10, "Next chunk: %.*s ...\n", 18, nextevent);

					starts_response = !strncmp(nextevent, "Response:", 9);
					if (starts_response) {
						ami_debug(ami, 7, "Got start of response... (%s)\n", nextevent);
						/* If there's an EventList field, it's a multi-event response. If not, it's not. */
						if (!strstr(nextevent, "EventList: start")) {
							/* Response is actually just a lone response... there aren't multiple events to follow */
							starts_response = 0; /* Technically, it's the start, middle, AND end... but treat it like it's the end */
							end_of_response = 1;
							ami_debug(ami, 9, "Finished eventless response\n");
						}
					} else { /* If we know this event starts a response, no need to confirm there's an ActionID, there is one!. */
						if (strstr(nextevent, "EventList: Complete")) {
							end_of_response = 1;
						}
						/* Whether this event is the Response bit or a plain Event, some line (NOT necessarily the 2nd)
						 * will have an ActionID, if it belongs to a response. */
						if (strstr(nextevent, "ActionID:")) {
							middle_of_response = 1;
						}
					}
					ami_debug(ami, 10, "Starts response: %d, middle of response: %d, ends response: %d\n", starts_response, middle_of_response, end_of_response);
					/* Now, figure out what we should do. */
					if (!starts_response && !middle_of_response && !end_of_response) {
						if (response_pending) {
							ami_error(ami, "BUG! Failed to detect end of response?\n");
						}
						/* This isn't an event that belongs to a response, including the start of one. It's just a regular unsolicited event. Send it now */
						ami_debug(ami, 9, "Dispatching lone (unsolicited) event (%.*s ...)\n", 18, nextevent);
						ami_event_handle(ami, laststart);
						lasteventstart = laststart = endofevent;
						event_pending = response_pending = 0;
					} else if (end_of_response) { /* We just wrapped up a response. */
						ami_debug(ami, 9, "Response has been finalized\n");
						ami_event_handle(ami, laststart);
						lasteventstart = laststart = endofevent;
						event_pending = response_pending = 0;
					} else if (!ami->loggedin) { /* Response to "Login" */
						/* If we're not logged in, we can only ever get a single event. */
						ami_debug(ami, 5, "Received login response\n");
						ami_event_handle(ami, laststart); /* The "Login" response doesn't contain any events. If we see it, then send it on immediately. */
						lasteventstart = laststart = endofevent;
						event_pending = response_pending = 0;
						if (!strncmp(laststart, "Response: Success", 17)) {
							ami->loggedin = 1; /* We can't actually wait for ami_action_login to set this flag. We need it to be 1 next time we loop (NOW). */
						}
					} else if (starts_response || middle_of_response) { /* We started and/or are in the middle of a response, but events remain. Keep going. */
						ami_debug(ami, 10, "Still in the middle of a response\n");
						response_pending = 1;
						event_pending = 0; /* Only relevant if !response_pending, anyways */
					}
					*endofevent = next; /* Restore what the last character really was. */
					lasteventstart = nextevent = endofevent; /* This is the beginning of the next event (if there is one) */
				}

				/* Here, we peek at what's next to process. *nextevent is the beginning of the substring that we'll loop over next time. */

				/* XXX This is kind of a kludge. Apparently sometimes we'll get a Response: line, and that's it, and ActionID the next line.
				 * Without this, because we're not aware a response is pending yet, we'll execute the !response_pending branch below,
				 * which will set lasteventstart to the current buffer position, overwriting what we just read ("Response:")
				 * This kludge is complete because if we check for this first line, then response_pending will be true afterwards
				 * so we'll execute the right branch if that happens again, and not overwrite what we just read. */

				/* If *nextevent, that means that there's still data remaining from what we already read, but we haven't finished reading yet.
				 * i.e. we have some data but no trailing AMI_EOM so we have a partial event or response available.
				 * XXX Sometimes these 2 branches are triggered when it takes multiple socket reads to receive the entire response.
				 * Don't think anything's actually wrong in that case. */

				if (!event_pending && *nextevent) {
					if (ami->debug_level >= 6) {
						ami_debug(ami, 6, "Empty line in event? Probably incomplete... (%s)\n", nextevent);
					} else {
						ami_debug(ami, 2, "Empty line in event? Probably incomplete...\n");
					}
					event_pending = 1;
				} else if (!response_pending && !strncmp(nextevent, "Response:", 9)) {
					/* In theory, not necessary? (covered by previous branch?) XXX Not so, because the above doesn't care about response_pending. */
					/* Okay, what happened here was we weren't waiting for a response and suddenly we started one. */
					if (ami->debug_level >= 6) {
						ami_debug(ami, 6, "Empty line in response event? Probably incomplete... (%s)\n", nextevent);
					} else {
						ami_debug(ami, 2, "Empty line in response event? Probably incomplete...\n");
					}
					response_pending = 1;
				}

				/* We finished processing all the events we just got. */
				if (response_pending || event_pending) { /* Incomplete, waiting for the end of this response */
					int len;
					/* Ouch... we started a response but didn't get the end of it yet... */
					ami_debug(ami, 6, "Asterisk left us high and dry for the end of the response (%d/%d), polling again...\n", response_pending, event_pending);
#if 0
					if (*nextevent) {
						/* Don't do this: this will actually just terminate some responses so we miss the completion event (see Issue #4) */
						*nextevent = '\0'; /* prevent any string hanky panky here */
					}
#endif
					/* Shift the contents of the buffer, starting at our current head, to the beginning of the buffer. */
					len = strlen(laststart);
					if (laststart != inbuf) { /* Don't needlessly move data unless that actually achieves anything. */
						/* If the logical head of our buffer is past the beginning, shift it back to the beginning. */
						memmove(inbuf, laststart, len + 1); /* Include NUL terminator */
						/* Okay, now we should have a little bit more room left in the buffer. */
					}
					lasteventstart = laststart = inbuf; /* The actual beginning of our data is at the very beginning of the buffer though, still! */
					readinbuf = inbuf + len; /* Start reading into the buffer at the first available space */
				} else {
					readinbuf = lasteventstart = laststart = inbuf; /* We're good to start reading into the beginning of the buffer. */
				}
			} else {
				ami_event_handle(ami, laststart); /* This should only be Asterisk IDing itself to us. */
				got_id = 1; /* Never execute this branch again during this connection. */
			}
		}
		/* Data from consumer to deliver to AMI? */
		if (fds[1].revents) {
			/* Copy data on the pipe into the buffer. We wrote it all at once, so what's here should be what we send. */
			res = read(ami->ami_pipe[0], outbuf, sizeof(outbuf));
			outbuf[res] = '\0'; /* We're only sending the right number of bytes, but null terminate for easy debugging to clearly delineate the end.*/
			if (res < 1) {
				ami_debug(ami, 1, "read returned %d\n", res);
				break;
			}
			res = write(ami->ami_socket, outbuf, res);
			if (res < 1) {
				ami_warning(ami, "write returned %d\n", res);
				break;
			}
		}
	}
	ami_cleanup(ami);
	if (ami->disconnected_callback) {
		ami->disconnected_callback(ami); /* let the caller know we're being forced to exit (e.g. by Asterisk) */
	}
	return NULL;
}

/* Try to prevent user applications from blowing things up.
 * If ami_connect is called by users when it shouldn't be,
 * that could result in starting up multiple AMI connections,
 * and then all hell really breaks loose.
 * Even though that's a user bug, try to prevent that. */
#define REJECT_DUPLICATE_RECONNECTS 1

struct ami_session *ami_connect(const char *hostname, int port, void (*callback)(struct ami_session *ami, struct ami_event *event), void (*dis_callback)(struct ami_session *ami))
{
	int fd;
	struct sockaddr_in saddr;
	struct ami_session *ami;
	int ret;

	ami = ami_session_new();
	if (!ami) {
		return NULL;
	}

	pthread_mutex_init(&ami->ami_read_lock, NULL);
	pthread_mutex_lock(&ami->ami_read_lock);
	if (ami->ami_socket >= 0) {
		/* Should pretty much NEVER happen on a clean cleanup
		 * WILL happen if we reconnect from the disconnect callback */
		ami_warning(ami, "Hmm... socket already registered?\n");
		/*
		 * Just continue and overwrite everything.
		 * It just means that somebody probably called ami_connect twice
		 * without disconnecting inbetween...
		 */
		if (REJECT_DUPLICATE_RECONNECTS) {
			ami_warning(ami, "Rejecting duplicate AMI connection!\n"); /* Somebody's trying to connect again while there's a connection in progress? */
			goto cleanup;
		}
		ami_cleanup(ami); /* Disconnect to prevent a resource leak */
	}

	memset(&saddr, 0, sizeof(saddr));
	if (!port) {
		port = AMI_PORT;
	}

	ami_debug(ami, 1, "Initiating AMI connection on port %d\n", port);

	/* If we can't make a pipe, forget about the socket. */
	if (socketpair(AF_LOCAL, SOCK_STREAM, 0, ami->ami_pipe)) {
		ami_error(ami, "Unable to create pipe: %s\n", strerror(errno));
		goto cleanup;
	}
	if (socketpair(AF_LOCAL, SOCK_STREAM, 0, ami->ami_read_pipe)) {
		ami_error(ami, "Unable to create pipe: %s\n", strerror(errno));
		close(ami->ami_pipe[0]);
		close(ami->ami_pipe[1]);
		goto cleanup;
	}
	if (socketpair(AF_LOCAL, SOCK_STREAM, 0, ami->ami_event_pipe)) {
		ami_error(ami, "Unable to create pipe: %s\n", strerror(errno));
		close(ami->ami_pipe[0]);
		close(ami->ami_pipe[1]);
		close(ami->ami_read_pipe[0]);
		close(ami->ami_read_pipe[1]);
		goto cleanup;
	}

	fd = socket(AF_INET, SOCK_STREAM, 0);
	if (fd < 0) {
		ami_error(ami, "Failed to create socket: %s\n", strerror(errno));
		close_pipes(ami);
		goto cleanup;
	}
	ami->ami_socket = fd;
	if (inet_pton(AF_INET, hostname, &(saddr.sin_addr)) == 1) {
		saddr.sin_family = AF_INET;
		saddr.sin_port = htons(port); /* use network order */
		if (connect(fd, (struct sockaddr *) &saddr, sizeof(saddr)) < 0) {
			ami_error(ami, "connect failed: %s\n", strerror(errno));
			ami_cleanup(ami);
			goto cleanup;
		}
	} else {
		struct addrinfo hints = {
			.ai_family = AF_UNSPEC,
			.ai_socktype = SOCK_STREAM,
			.ai_flags = AI_V4MAPPED | AI_ADDRCONFIG
		};
		struct addrinfo *res;

		if (getaddrinfo(hostname, NULL, &hints, &res) == 0) {
			if (res->ai_addr == NULL) {
				freeaddrinfo(res);
				ami_error(ami, "host %s not valid\n", hostname);
				ami_cleanup(ami);
				goto cleanup;
			}

			switch (res->ai_addr->sa_family) {
			case AF_INET:
				((struct sockaddr_in *)res->ai_addr)->sin_port = htons(port);
				break;
			case AF_INET6:
				((struct sockaddr_in6 *)res->ai_addr)->sin6_port = htons(port);
				break;
			default:
				freeaddrinfo(res);
				ami_error(ami, "address for host %s not valid\n", hostname);
				ami_cleanup(ami);
				goto cleanup;
			}

			if (connect(fd, res->ai_addr, res->ai_addrlen) < 0) {
				freeaddrinfo(res);
				ami_error(ami, "connect failed: %s\n", strerror(errno));
				ami_cleanup(ami);
				goto cleanup;
			}

			freeaddrinfo(res);
		} else {
			ami_error(ami, "host %s not valid\n", hostname);
			ami_cleanup(ami);
			goto cleanup;
		}
	}
	ami->ami_callback = callback;
	ami->disconnected_callback = dis_callback;
	ami->ami_msg_id = 0;
	ami->loggedin = 0;
	ami->tx = ami->rx = 0;

	{
		pthread_mutexattr_t attr;
		pthread_mutexattr_init(&attr);
		pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE);
		pthread_mutex_init(&ami->ami_read_lock, &attr);
		pthread_mutexattr_destroy(&attr);
	}

	{
		pthread_attr_t attr;
		pthread_attr_init(&attr);
		pthread_attr_setstacksize(&attr, 2 * 1024 * 1024);
		ret = pthread_create(&ami->ami_thread, &attr, ami_loop, ami);
		pthread_attr_destroy(&attr);
		if (ret) {
			ami_error(ami, "Unable to create AMI thread: %s\n", strerror(errno));
			ami_cleanup(ami);
			goto cleanup;
		}
	}

	{
		pthread_attr_t attr;
		pthread_attr_init(&attr);
		pthread_attr_setstacksize(&attr, 2 * 1024 * 1024);
		ret = pthread_create(&ami->dispatch_thread, &attr, ami_event_dispatch, ami);
		pthread_attr_destroy(&attr);
		if (ret) {
			ami_error(ami, "Unable to create dispatch thread: %s\n", strerror(errno));
			ami_cleanup(ami);
			goto cleanup;
		}
	}

	pthread_mutex_unlock(&ami->ami_read_lock);

	/* establish the initial per-session debug fd and level */
	ami->debugfd = -1;
	ami->debug_level = 0;
	return ami;

cleanup:
	pthread_mutex_unlock(&ami->ami_read_lock);
	ami_destroy(ami);
	return NULL;
}

void ami_set_callback_data(struct ami_session *ami, void *data)
{
	ami->cb_data = data;
}

void *ami_get_callback_data(struct ami_session *ami)
{
	return ami->cb_data;
}

int ami_disconnect(struct ami_session *ami)
{
	if (!ami) {
		ami_error(ami, "ami_disconnect called with NULL session\n");
		return -1;
	}
	if (ami->ami_socket < 0) {
		return -1;
	}

	if (ami->ami_thread) {
		pthread_cancel(ami->ami_thread);
		pthread_kill(ami->ami_thread, SIGURG);
		pthread_join(ami->ami_thread, NULL);
		ami->ami_thread = 0;
	}
	if (ami->dispatch_thread) {
		pthread_cancel(ami->dispatch_thread);
		pthread_kill(ami->dispatch_thread, SIGURG);
		pthread_join(ami->dispatch_thread, NULL);
		ami->dispatch_thread = 0;
	}

	if (ami->ami_socket >= 0) {
		ami_debug(ami, 2, "Since we killed the AMI connection, manually cleaning up\n");
		ami_cleanup(ami);
	}
	return 0;
}

void ami_destroy(struct ami_session *ami)
{
	pthread_mutex_destroy(&ami->ami_read_lock);
	free(ami);
}

void ami_set_debug(struct ami_session *ami, int fd)
{
	if (ami) {
		ami->debugfd = fd;
	} else {
		ami_initial_debugfd = fd;
	}
}

int ami_debug_level(struct ami_session *ami)
{
	return ami ? ami->debug_level : ami_initial_debug_level;
}

int ami_set_debug_level(struct ami_session *ami, int level)
{
	int old_level = ami ? ami->debug_level : ami_initial_debug_level;
	if (level < 0 || level > 10) {
		return -1;
	}
	if (ami) {
		ami->debug_level = level;
	} else {
		ami_initial_debug_level = level;
	}
	return old_level;
}

static int __attribute__ ((format (printf, 3, 0))) __attribute__ ((format (printf, 4, 5))) __ami_send(struct ami_session *ami, va_list ap, const char *fmt, const char *prefmt, ...)
{
	int res = 0;
	int bytes = 0;
	char *prebuf, *buf = NULL, *fullbuf;
	int prelen, len = 0;
	va_list preap;

	/* Action Name and ID */
	va_start(preap, prefmt);
	prelen = vasprintf(&prebuf, prefmt, preap);
	va_end(preap);

	if (prelen < 0) {
		return -1;
	}

	/* User variadic arguments */
	if (fmt) {
		if ((len = vasprintf(&buf, fmt, ap)) < 0) {
			free(prebuf);
			return -1;
		}
	}

	fullbuf = malloc(prelen + len + sizeof(AMI_EOM) + 1);
	if (!fullbuf) {
		free(prebuf);
		if (buf) {
			free(buf);
		}
		return -1;
	}

	strcpy(fullbuf, prebuf); /* Safe */
	if (buf) {
		strcpy(fullbuf + prelen, buf); /* Safe */
	}

	/* User format strings should not end with \r\n. However, it's conceivable it could happen, and handle it if it does. */
	if (prelen + len > 2 && !strncmp(fullbuf + prelen + len - 2, "\r\n", 2)) {
		ami_warning(ami, "WARNING: User format string ends with \\r\\n. Fixing this, but please don't do this!\n");
		/* We already have a partial finale, so only add half of it and hopefully now it's correct. */
		/* Note: gcc whines about truncation if we copy 2 bytes of AMI_EOM using strncpy. So just hardcode it. */
		strcpy(fullbuf + prelen + len, "\r\n"); /* Safe */
		len = prelen + len + 2;
		/* We should now have the correct ending. However, if there was more than one \r\n, then it's still going to fail. */
	} else { /* Add the full finale */
		strcpy(fullbuf + prelen + len, AMI_EOM); /* Safe */
		len = prelen + len + 4; /* + length of AMI_EOM */
	}

	if (buf) {
		free(buf);
	}
	free(prebuf);

	if (len >= 4 && strncmp(fullbuf + len - 4, AMI_EOM, 4)) {
		/* Shouldn't happen if everything else is correct, but if message wasn't properly terminated, it won't get processed. Fix it to force it to go through. */
		ami_warning(ami, "Yikes! AMI action wasn't properly terminated!\n"); /* This means there's a bug somewhere else. */
	}
	while (len >= 5 && (*(fullbuf + len - 5) == '\r' || *(fullbuf + len - 5) == '\n')) {
		/* Asterisk will stop parsing this message after two CR LF sequences,
		 * and anything afterwards will (fail to) be interpreted as the next message.
		 * This will throw off synchronization so is very bad.
		 * This is user error, but we can correct it by removing the erroneous CR LF's,
		 * or other possibly malformed line endings, including stray LFs, etc. */
		ami_warning(ami, "Too many line endings at end of action. Autocorrecting...\n");
		len--;
		strcpy(fullbuf + len - 4, AMI_EOM); /* Safe */
	}

	ami_debug(ami, 4, "==> AMI Action:\n%s", fullbuf); /* There's already (multiple) new lines at the end, don't add more */
	bytes = write(ami->ami_pipe[1], fullbuf, len);
	if (bytes < 1) {
		ami_warning(ami, "Failed to write to pipe\n");
		res = -1;
	}

	if (!res) {
		ami->tx++;
	}

	free(fullbuf);
	return res;
}

static struct ami_event *ami_parse_event(struct ami_session *ami, char *data)
{
	int i = 0;
	struct ami_event *event;
	char *outer, *inner, *dup, *dup2;
	int newlines = 1; /* If no newlines at all, we still have one field */
	char *pos = data;
	/* Count how many lines there are */
	while ((pos = strchr(pos, '\n'))) {
		newlines++;
		pos++;
	}

	event = calloc(1, sizeof(struct ami_event) + sizeof(struct ami_field[newlines]));
	if (!event) {
		return NULL;
	}

	event->ami = ami;
	event->size = newlines;
	dup = strdup(data);
	dup2 = dup; /* You can NOT use strsep directly on a malloc'd pointer */

	while ((outer = strsep(&dup2, "\n"))) {
		if (!*outer || !*(outer + 1)) {
			ami_warning(ami, "WARNING: Malformed AMI event! (contains empty line)\n");
			/* Don't decrement event->size: we allocated that many fields, and we need to free them all. */
			/* However, by skipping this we ensure any such unused fields are at the end of the struct. */
			continue;
		}
		inner = strsep(&outer, ":");
		if (*inner && inner[1]) { /* Don't do anything with the extra new lines at the end */
			ltrim(inner); /* Eat any leading whitespace */
			rtrim(outer); /* Eat any trailing whitespace */
			event->fields[i].key = strdup(inner);
			if (outer) {
				ltrim(outer); /* Eat any leading whitespace */
				rtrim(outer); /* Eat any trailing whitespace */
				event->fields[i].value = strdup(outer);
				/* We really only need ActionID stored on the first event, because that's how a response extracts its ActionID. */
				/* On subsequent events, we don't need them, but responses do check that they all match. */
				if (!strcmp(event->fields[i].key, "ActionID")) {
					event->actionid = atoi(event->fields[i].value);
				}
			}
		}
		i++;
	}
	free(dup);
	return event;
}

static struct ami_response *ami_parse_response(struct ami_session *ami, char *data)
{
	int i = 0, events = 0;
	struct ami_response *resp;
	char *outer, *dup, *dup2;

	dup = strdup(data);
	dup2 = dup; /* You can NOT use strsep directly on a malloc'd pointer */
	outer = dup2;

	/* Count how many events there are (including initial response fields as an "event" for struct purposes) */
	/* What would we be nice is if strsep accepted multiple consecutive chars for a delimiter, but it doesn't, so improvise... */
	while ((outer = strstr(outer, AMI_EOM))) {
		outer += 4;
		events++;
	}

	resp = calloc(1, sizeof(struct ami_response) + sizeof(struct ami_event[events]));
	if (!resp) {
		goto cleanup;
	}

	resp->size = events;
	outer = dup2; /* reset */

	/* C only lets you have one flexible array member (at the end of a struct). So shove the Response fields into a dummy event at index 0. */

	/* Events are delimited by two new lines */
	while ((outer = strstr(dup2, AMI_EOM))) {
		*outer = '\0';
		resp->events[i] = ami_parse_event(ami, dup2);
		if (i == 0) {
			const char *response;
			/* This "event" contains the fields for the response itself. */
			resp->actionid = resp->events[i]->actionid;
			response = ami_keyvalue(resp->events[i], "Response");
			resp->success = !strcasecmp(response, "Success") ? 1 : 0;
		} else {
			if (resp->events[i]->actionid && resp->actionid != resp->events[i]->actionid) {
				ami_warning(ami, "BUG! Expected ActionID %d but event has %d\n", resp->actionid, resp->events[i]->actionid);
			}
		}
		dup2 = outer;
		dup2 += 4;
		i++;
	}

cleanup:
	free(dup);
	return resp;
}

void ami_event_free(struct ami_event *event)
{
	int i;
	for (i = 0; i < event->size; i++) {
		if (event->fields[i].key) {
			free(event->fields[i].key);
		}
		if (event->fields[i].value) {
			free(event->fields[i].value);
		}
	}
	free(event);
}

void ami_resp_free(struct ami_response *resp)
{
	int i;
	for (i = 0; i < resp->size; i++) {
		if (resp->events[i]) {
			ami_event_free(resp->events[i]);
		}
	}
	free(resp);
}

void ami_dump_event(struct ami_event *event)
{
	int i;
	fprintf(stderr, "*** Event => # Fields: %d\n", event->size);
	for (i = 0; i < event->size; i++) {
		fprintf(stderr, "%-15s : %s\n", event->fields[i].key, event->fields[i].value);
	}
}

void ami_dump_response(struct ami_response *resp)
{
	int i;
	fprintf(stderr, "\n******* RESPONSE *******\n");
	fprintf(stderr, "ActionID: %d (%s) => # Events: %d\n", resp->actionid, resp->success ? "Success" : "Fail", resp->size);
	for (i = 0; i < resp->size; i++) {
		ami_dump_event(resp->events[i]);
	}
}

const char *ami_keyvalue(struct ami_event *event, const char *key)
{
	const char *value = NULL;
	int i;
	for (i = 0; i < event->size; i++) {
		if (!event->fields[i].key) {
			/* Root cause is a poorly written Asterisk module that sent an empty key. We'll already have thrown a warning in this case.
			 * We can't do anything much about it, because we already allocated space for N events, so if there's empty lines, we
			 * won't actually use all N of them.
			 * strcasecmp will crash if key is NULL so skip the comparison, since it's obviously not a match anyways.
			 */
			ami_error(event->ami, "Null key at index %d (searching for %s)\n", i, key);
			continue;
		}
		if (!strcasecmp(key, event->fields[i].key)) {
			value = event->fields[i].value;
			break;
		}
	}
	return value;
}

/*! \brief Separate thread to dispatch AMI events by executing user callback functions
 * so as not to block the main loop thread. This is necessary as if there is recursion
 * (i.e. callback function calls an AMI action), we then deadlock until the response
 * timeout expires because the main thread is blocked on the callback function. Solved
 * by not executing user callback functions in the main thread. */
static void *ami_event_dispatch(void *varg)
{
	struct pollfd fds;
	struct ami_event *event;
	int res;
	char buf[AMI_BUFFER_SIZE];
	struct ami_session *ami;

	ami = varg;

	fds.fd = ami->ami_event_pipe[0];
	fds.events = POLLIN;

	for (;;) {
		res = poll(&fds, 1, -1);
		if (res < 0) {
			if (errno == EINTR) {
				continue;
			}
			ami_debug(ami, 3, "Exiting event dispatcher: %s\n", strerror(errno));
			break;
		}
		if (res) {
			char *start, *end;
			res = read(ami->ami_event_pipe[0], buf, AMI_BUFFER_SIZE - 1);
			if (res < 1) {
				ami_warning(ami, "Failed to read from read pipe (%d): %s\n", res, strerror(errno));
				break;
			}
			/* Be prepared to receive multiple events, or not even a complete one. */
			start = buf;
			do {
				int bytes_used;
				end = memchr(start, '\0', res);
				if (!end) {
					break;
				}
				event = ami_parse_event(ami, start);
				ami->ami_callback(ami, event); /* Provide the user with the original event, user is responsible for freeing */
				bytes_used = end - start + 1;
				res -= bytes_used;
				/* Set ourselves up for the next round */
				start = end + 1; /* If res is still > 0, then start is guaranteed to be valid (initialized memory) */
			} while (res);
			if (res) {
				ami_warning(ami, "Buffer was not null terminated, incomplete?\n");
				/*! \todo XXX BUGBUG Unlikely, but we should really wait for the null terminator, as the event may be incomplete here on partial read. */
				start[res - 1] = '\0';
				event = ami_parse_event(ami, start);
				ami->ami_callback(ami, event); /* Provide the user with the original event, user is responsible for freeing */
			}
		}
	}

	ami_debug(ami, 2, "Event dispatch thread exiting\n");

	return NULL;
}

static void ami_event_handle(struct ami_session *ami, char *data)
{
	if (ami->rx++ == 0) { /* This is the first thing we received (probably Asterisk identifiying itself). */
		if (!strstr(data, "Asterisk")) {
			ami_warning(ami, "Unexpected identification: '%s'\n", data);
		} else {
			/* Assume we're good to go. */
			if (write(ami->ami_read_pipe[1], "0", 2) < 1) { /* Add 1 for null terminator */
				ami_warning(ami, "Couldn't write to read pipe?\n");
			}
			ami_debug(ami, 2, "*** Initialized Asterisk Manager Interface: %s", data); /* No newline, Asterisk ID contains one */
		}
		return;
	}
	if (!strncmp(data, "Response:", 9)) {
		/*
		 * If we got a response, then ami_read_lock must be held by the thread
		 * that sent the action that elicited this.
		 * This also means that when we're here, we expect one and only one
		 * particular response, with its corresponding ActionID, etc.
		 * Nobody else can send an action until that thread releases ami_read_lock.
		 * This ensures that current_response is a valid pointer to the response
		 * until that threads claims it. At that point, it is responsible
		 * for calling ami_resp_free on it when done with it. Not our concern anymore.
		 */
		struct ami_response *resp;
		/* Response to an action, containing 1 or more events */
		ami_debug(ami, 4, "<== AMI Response: %.*s...\n", AMI_RESPONSE_PREVIEW_SIZE, data); /* Only show a preview of the first "chunk", since it could be large... */
		resp = ami_parse_response(ami, data);
		if (!resp) {
			ami_warning(ami, "Failed to parse response?\n");
		} else if (resp->size < 1) {
			ami_error(ami, "Size is %d?\n", resp->size);
			ami_resp_free(resp);
		} else if (resp->actionid != ami->ami_msg_id) {
			/* No need to check that resp->actionid is nonzero. Every response has an ActionID in the response. */
			/* ami_msg_id is the most recently sent action, so it's possible we could still be waiting for
			 * responses that haven't arrived yet, that will arrive after successive actions have already been sent.
			 * In this case, it's a legitimate thing to happen, although it may be a little strange.
			 * What we know should NEVER happen is resp->actionid > ami_msg_id, since no such action would have been
			 * sent yet.
			 */
			if (resp->actionid > ami->ami_msg_id) {
				ami_warning(ami, "Received response with ActionID %d, but we max action is %d?\n", resp->actionid, ami->ami_msg_id);
			} else {
				/* Still, if you DO see this, then maxwaitms was probably not high enough for whatever action was sent.
				 * This is because actions are processed in serial, one at a time, so there can't be any parallel actions
				 * that are waiting for responses. */
				ami_warning(ami, "Received response with ActionID %d (older than max action %d)\n", resp->actionid, ami->ami_msg_id);
			}
		} else {
			char buf[AMI_MAX_ACTIONID_STRLEN];
			snprintf(buf, AMI_MAX_ACTIONID_STRLEN, "%d", resp->actionid);
			/* Remember... consumer is holding ami_read_lock until it gets the response. */
			/* Don't try to lock ami_read_lock until AFTER we write to the pipe, or we'll cause deadlock. */
			if (ami->current_response) {
				/* Could indicate a bug, but not necessarily... perhaps the consumer just forgot about it? */
				ami_warning(ami, "Found a response %p (%d) still active? Somebody's getting his lunch stolen...\n", ami->current_response, ami->current_response->actionid);
				ami->current_response = NULL;
			}
			ami->current_response = resp;
			if (write(ami->ami_read_pipe[1], buf, strlen(buf) + 1) < 1) { /* Add 1 for null terminator */
				ami_warning(ami, "Couldn't write to read pipe?\n");
			}

			/*
			 * So originally, I had it try to acquire ami_read_lock here and then assert that current_response was NULL.
			 * This intuitively makes some sense as we know that the consumer should release the lock once we write to
			 * the pipe, and it will then set current_response to NULL and then release the lock. Then we'll be able
			 * to acquire it and then assert it is actually NULL.
			 *
			 * The problem with this was the occasional race condition. On occasion (and depending on many factors like
			 * how many debug statements are logged and other expensive operations), the thread could release the lock
			 * and then immediately reacquire it as it tries to send another Action before we've had a chance to acquire
			 * the lock. Basically, if for whatever reason, we're not first in line to acquire the lock after we write
			 * to the pipe, then we can have a problem.
			 *
			 * This occurs whenever that thread releases the lock but it gets reacquired before we acquire it.
			 *
			 * You can easily reproduce this, in fact, by putting making the usleep below run. It took a little bit
			 * to figure out exactly what was going on, but once you know what's going on, you can force it to happen.
			 *
			 * The fact is that we don't actually NEED to acquire ami_read_lock. However, if we're not able to acquire
			 * it, then we can't actually verify that current_response SHOULD, in fact, be NULL.
			 * So, we'll trylock instead of lock. Most of the time, we SHOULD be able to acquire the lock, because
			 * it's immediately after the write call. If for some reason we get unscheduled right here and we can't
			 * acquire the lock, then just keep going. Otherwise, what'll happen is we'll block until that lock gets
			 * released. This is a HUGE problem, because the thread that is holding the lock is waiting for us to send
			 * it the response to the action it requested, which we can't do until we acquire and release the lock,
			 * so we can get the response from Asterisk and pass it on.
			 *
			 * TL;DR: Essentially, this would create a deadlock, and if it we didn't have action sending threads time
			 * out after so many milliseconds (suppose, as might be reasonable, we had them wait forever), it would
			 * in fact be an actual legit deadlock and that would be very, very bad!
			 *
			 * On the other hand, if WE acquire the lock first (as we should be able to 99% of the time), we can
			 * check that the world hasn't fallen apart, and then release it immediately. It's only when somebody
			 * else acquires it first, due to a scheduling anomaly, that deadlock would ensue if we tried to
			 * unconditionally acquire the lock.
			 *
			 * UPDATE: Actually, this scheduling phenomenon can be more frequent than I initially assumed.
			 * It can so happen that other threads have a very decent shot at acquiring this lock before we can.
			 * So if we can't acquire the lock, don't panic even then, it's not a problem either way. That said,
			 * if we are able to acquire it at some point, we will. Consumers should neither know nor care about this.
			 */

#if 0
			usleep(10000);
#endif

#if 0
			/* Wait for the consumer to finish using the event before we continue and potentially serve another event... */
			pthread_mutex_lock(&ami->ami_read_lock);
			/* Okay, at this point current_response should be NULL. (We're the only thread serving up responses) */
			if (ami->current_response) {
				ami_error(ami, "BUG! current_response was %p (%d) immediately after lock acquired?\n", ami->current_response, ami->current_response->actionid);
			}
			pthread_mutex_unlock(&ami->ami_read_lock);
#else
			if (!pthread_mutex_trylock(&ami->ami_read_lock)) {
				if (ami->current_response) {
					/* On one occasion, I observed this bug arising because Asterisk was sending an AMI error
					 * but then sending a successful response afterwards, rather than bailing early as it should have been.
					 * So this could indicate something is wrong with the Asterisk response. */
					ami_error(ami, "BUG! current_response was %p (%d) immediately after lock acquired?\n", ami->current_response, ami->current_response->actionid);
				}
				pthread_mutex_unlock(&ami->ami_read_lock);
			}
#if EXTRA_DEBUG
			else {
				ami_debug(ami, 1, "Could not acquire ami_read_lock just for fun, another thread beat us to it...\n");
			}
#endif
#endif
		}
	} else {
		/* A single, unsolicited event (not in response to an action) */
		ami_debug(ami, 4, "<== AMI Event: %s\n", data); /* Show the whole thing, it's probably not THAT big... */
		if (ami->ami_callback) {
			ssize_t bytes;
			rtrim(data); /* ami_parse_event expects NO trailing newlines at the end. */
			bytes = write(ami->ami_event_pipe[1], data, strlen(data) + 1); /* Include null terminator. */
			if (bytes < 1) {
				ami_warning(ami, "Failed to write to pipe\n");
			}
		}
		return;
	}
}

static int ami_wait_for_response(struct ami_session *ami, int msgid)
{
	int res;
	struct pollfd fds;

	if (ami->ami_read_pipe[0] < 0) {
		return -1;
	}

	fds.fd = ami->ami_read_pipe[0];
	fds.events = POLLIN;

	for (;;) {
		res = poll(&fds, 1, maxwaitms);
		if (res < 0) {
			if (errno != EINTR) {
				ami_warning(ami, "poll returned error: %s\n", strerror(errno));
			} else {
				ami_debug(ami, 1, "poll returned something else: %s\n", strerror(errno));
			}
			return -1;
		} else if (!res) { /* Nothing happened */
			ami_warning(ami, "Didn't receive any AMI response (for %d) within %d ms?\n", msgid, maxwaitms);
			if (ami->current_response) {
				/* Chances of this happening are almost nil, but it could happen... maybe? */
				ami_debug(ami, 1, "Okay, weird, we must have missed it before...\n");
				return 0;
			}
			return -1;
		} else if (fds.revents) {
			int eventnum;
			char buf[AMI_MAX_ACTIONID_STRLEN];
			if (read(ami->ami_read_pipe[0], buf, AMI_MAX_ACTIONID_STRLEN) < 1) {
				ami_warning(ami, "read pipe failed?\n");
				return -1;
			}
			eventnum = atoi(buf);
			if (msgid != eventnum) {
				ami_warning(ami, "Strange... got event %d, not %d\n", eventnum, msgid);
				/* If it's not our event, it's not our turn yet, wait again and don't process it. */
				continue;
			}
			return 0;
		} else {
			ami_warning(ami, "How'd I get here?\n");
			return -1;
		}
	}
}

static int __attribute__ ((format (printf, 3, 4))) ami_send(struct ami_session *ami, const char *action, const char *fmt, ...)
{
	int res;

	va_list ap;
	va_start(ap, fmt);
	/* If we don't have a user-supplied format string, don't add \r\n after ActionID or we'll get 3 sets in a row and cause Asterisk to whine. */
	res = __ami_send(ami, ap, fmt, *fmt ? "Action:%s\r\nActionID:%d\r\n" : "Action:%s\r\nActionID:%d", action, ++ami->ami_msg_id);
	va_end(ap);

	return res;
}

struct ami_response * __attribute__ ((format (printf, 3, 4))) ami_action(struct ami_session *ami, const char *action, const char *fmt, ...)
{
	struct ami_response *resp = NULL;
	/* Remember: no trailing \r\n in fmt !*/
	int res, actionid;
	va_list ap;

	if (ami->ami_socket < 0) {
		/* Connection got shutdown */
		ami_error(ami, "Can't send AMI action without active socket\n");
		return NULL;
	}
	if (!ami->loggedin) {
		/* Silly you! You can't use AMI if you're not logged in... */
		ami_error(ami, "Requested AMI action but not yet logged in?\n");
		return NULL;
	}

	/* Nobody sends anything else until we get our response. */
	pthread_mutex_lock(&ami->ami_read_lock);

	va_start(ap, fmt);
	/* If we don't have a user-supplied format string, don't add \r\n after ActionID or we'll get 3 sets in a row and cause Asterisk to whine. */
	res = __ami_send(ami, ap, fmt, fmt && *fmt ? "Action:%s\r\nActionID:%d\r\n" : "Action:%s\r\nActionID:%d", action, ++ami->ami_msg_id);
	va_end(ap);

	actionid = ami->ami_msg_id; /* This is the ActionID we expect in our response */

	if (res) {
		ami_warning(ami, "Failed to send AMI action\n");
		pthread_mutex_unlock(&ami->ami_read_lock);
		return NULL; /* Failed to send */
	}

	/* Now wait until we (hopefully) get a response... */
	res = ami_wait_for_response(ami, actionid);
	resp = ami->current_response;
	ami->current_response = NULL; /* All right, now resp is somebody's else problem, we're not responsible for freeing it... */
	pthread_mutex_unlock(&ami->ami_read_lock);
	if (!res) {
		if (!resp) {
			ami_error(ami, "BUG! Told we got a response, but can't find it?\n");
		} else {
			if (resp->actionid != actionid) {
				/*! \note If we ever make it so multiple AMI responses can go out at once, this may need to be revisited... */
				ami_error(ami, "BUG! Expected ActionID %d in response, but got %d\n", actionid, resp->actionid);
			} else if (!resp->success && ami->return_null_on_error) {
				/* We got a response, and it's telling us that we failed. */
				const char *error = ami_keyvalue(resp->events[0], "Message");
				/* Actions can fail due to user error, so this isn't our fault. */
				ami_debug(ami, 2, "AMI action %d failed: %s\n", resp->actionid, error);
				ami_resp_free(resp); /* If we're not returning it to the user, free it now */
				resp = NULL; /* Try harder next time... */
			}
		}
	}

	return resp;
}

int ami_action_login(struct ami_session *ami, const char *username, const char *password)
{
	struct ami_response *resp;
	int res;

	if (ami->ami_socket < 0) {
		/* Chance of us getting booted between when established the connection
		 * and now are basically nil, but check anyways, just in case.
		 */
		ami_warning(ami, "AMI socket closed before we could try to log in\n");
		return -1;
	}

	/* Nobody sends anything else until we get our response. */
	pthread_mutex_lock(&ami->ami_read_lock);
	/* Sometimes, if we're too eager, we can try to log in before the ID and that fails. */
	/* So, wait until Asterisk IDs itself before we send login. */
	res = ami_wait_for_response(ami, ami->ami_msg_id);
	if (res) { /* Asterisk didn't ID itself? Abort. */
		pthread_mutex_unlock(&ami->ami_read_lock);
		ami_warning(ami, "Asterisk did not identify itself\n");
		return -1;
	}
	/* Remember: no trailing \r\n !*/
	if (ami_send(ami, "Login", "Username:%s\r\nSecret:%s", username, password)) {
		pthread_mutex_unlock(&ami->ami_read_lock);
		ami_warning(ami, "Failed to send AMI action\n");
		return -1; /* Failed to send */
	}
	/* Now wait until we (hopefully) get a response... */
	res = ami_wait_for_response(ami, ami->ami_msg_id);
	resp = ami->current_response;
	ami->current_response = NULL; /* we're done with this guy... */
	if (!res) {
		if (!resp) {
			ami_error(ami, "BUG! Told we got a response, but can't find it?\n");
		} else {
			if (!resp->success) {
				/* We got a response, and it's telling us that we failed. */
				res = -1; /* Try harder next time... */
			} else {
				ami->loggedin = 1;
			}
			ami_resp_free(resp); /* We don't need to do anything more with this. */
		}
	}
	/* Unlike ami_action, we don't release read_lock until AFTER we process. */
	pthread_mutex_unlock(&ami->ami_read_lock);

	return res;
}

int ami_auto_detect_ami_pass(const char *amiusername, char *buf, size_t buflen)
{
	FILE *fp;
	char *line = NULL;
	long int readres;
	size_t len;
	int found = 0, right_section = 0;

	char searchsection[64]; /* Use fixed size instead of strlen(amiusername) + 3, to avoid stack protector warnings */
	snprintf(searchsection, sizeof(searchsection), "[%s]", amiusername);

	fp = fopen("/etc/asterisk/manager.conf", "r");
	if (!fp) {
		return -1;
	}

	while ((readres = getline(&line, &len, fp)) != -1) {
		if (strstr(line, searchsection)) {
			right_section = 1;
		} else if (!strncmp(line, "[", 1)) {
			right_section = 0;
		} else if (right_section) {
			if (!strncmp(line, "secret", 6)) {
				char *secret = strchr(line, '='); /* Get the value for the key */
				if (!secret) {
					continue;
				}
				/* Skip any leading whitespace */
				secret++;
				while (*secret && isspace(*secret)) {
					secret++;
				}
				strncpy(buf, secret, buflen);
				secret = buf;
				/* Skip any trailing whitespace */
				while (*secret) {
					if (isspace(*secret) || *secret == '\r' || *secret == '\n' || *secret == ';') {
						*secret = '\0';
						break;
					}
					secret++;
				}
				found = 1;
				break;
			}
		}
	}
	fclose(fp);
	if (line) {
		free(line);
	}
	return found ? 0 : -1;
}

void ami_set_discard_on_failure(struct ami_session *ami, int discard)
{
	ami->return_null_on_error = discard ? 1 : 0;
}

int ami_action_response_result(struct ami_session *ami, struct ami_response *resp)
{
	int res = -1;

	if (!resp) {
		/* If user does something like ami_action_response_result(ami_action(...)) then we could end up here. */
		ami_debug(ami, 2, "No response to AMI action\n");
		return -1;
	}
	if (resp->size != 1) {
		ami_debug(ami, 1, "AMI action response returned %d events?\n", resp->size);
	} else {
		res = resp->success ? 0 : -1;
		if (res) {
			const char *error = ami_keyvalue(resp->events[0], "Message");
			/* Actions can fail due to user error, so this isn't our fault. */
			ami_debug(ami, 2, "AMI action %d failed: %s\n", resp->actionid, error);
		}
	}

	ami_resp_free(resp);
	return res;
}

char *ami_action_getvar(struct ami_session *ami, const char *variable, const char *channel)
{
	struct ami_response *resp;
	const char *varval;
	char *varvaldup = NULL;

	if (channel) {
		resp = ami_action(ami, "Getvar", "Variable:%s\r\nChannel:%s", variable, channel);
	} else {
		resp = ami_action(ami, "Getvar", "Variable:%s", variable);
	}
	if (!resp) {
		return NULL;
	}
	if (resp->size != 1) {
		ami_warning(ami, "AMI action Getvar response returned %d events?\n", resp->size);
		goto cleanup;
	}

	varval = ami_keyvalue(resp->events[0], "Value");
	if (!varval || !*varval) {
		goto cleanup; /* Values are trimmed, so if it starts with NULL, there's nothing there */
	}

	varvaldup = strdup(varval);

cleanup:
	ami_resp_free(resp);
	return varvaldup;
}

int ami_action_getvar_buf(struct ami_session *ami, const char *variable, const char *channel, char *buf, size_t len)
{
	struct ami_response *resp;
	const char *varval;
	int res = -1;

	*buf = '\0';

	if (channel) {
		resp = ami_action(ami, "Getvar", "Variable:%s\r\nChannel:%s", variable, channel);
	} else {
		resp = ami_action(ami, "Getvar", "Variable:%s", variable);
	}
	if (!resp) {
		return res;
	}
	if (resp->size != 1) {
		ami_warning(ami, "AMI action Getvar response returned %d events?\n", resp->size);
		goto cleanup;
	}

	varval = ami_keyvalue(resp->events[0], "Value");
	if (!varval || !*varval) {
		goto cleanup; /* Values are trimmed, so if it starts with NULL, there's nothing there */
	}

	strncpy(buf, varval, len);
	res = 0;

cleanup:
	ami_resp_free(resp);
	return res;
}

int ami_action_setvar(struct ami_session *ami, const char *variable, const char *value, const char *channel)
{
	struct ami_response *resp;

	if (channel) {
		resp = ami_action(ami, "Setvar", "Variable:%s\r\nValue:%s\r\nChannel:%s", variable, value, channel);
	} else {
		resp = ami_action(ami, "Setvar", "Variable:%s\r\nValue:%s", variable, value);
	}
	return ami_action_response_result(ami, resp);
}

int ami_action_originate_exten(struct ami_session *ami, const char *dest, const char *context, const char *exten, const char *priority, const char *callerid)
{
	struct ami_response *resp;

	if (strlen_zero(context)) {
		ami_warning(ami, "Missing context\n");
		return -1;
	}
	if (strlen_zero(exten)) {
		ami_warning(ami, "Missing exten\n");
		return -1;
	}
	if (strlen_zero(priority)) {
		ami_warning(ami, "Missing priority\n");
		return -1;
	}

	if (callerid) {
		resp = ami_action(ami, "Originate", "Channel:%s\r\nContext:%s\r\nExten:%s\r\nPriority:%s\r\nCallerID:%s", dest, context, exten, priority, callerid);
	} else {
		resp = ami_action(ami, "Originate", "Channel:%s\r\nContext:%s\r\nExten:%s\r\nPriority:%s", dest, context, exten, priority);
	}
	return ami_action_response_result(ami, resp);
}

int ami_action_redirect(struct ami_session *ami, const char *channel, const char *context, const char *exten, const char *priority)
{
	struct ami_response *resp;

	if (strlen_zero(context)) {
		ami_warning(ami, "Missing context\n");
		return -1;
	}
	if (strlen_zero(exten)) {
		ami_warning(ami, "Missing exten\n");
		return -1;
	}
	if (strlen_zero(priority)) {
		ami_warning(ami, "Missing priority\n");
		return -1;
	}

	resp = ami_action(ami, "Redirect", "Channel:%s\r\nContext:%s\r\nExten:%s\r\nPriority:%s", channel, context, exten, priority);
	return ami_action_response_result(ami, resp);
}

int ami_action_reload(struct ami_session *ami, const char *module)
{
	struct ami_response *resp;

	if (strlen_zero(module)) {
		ami_warning(ami, "Missing module\n");
		return -1;
	}

	/* In ami_wait_for_response, we wait maxwaitms maximum for a response.
	 * This is done to prevent hanging if we never receive a response.
	 * However, Reloads can take a legitimately long time to process, especially if we are reloading more than one module.
	 * So, we need to be more patient - this is kind of a hack, but temporarily override maxwaitms and restore
	 * the old value when done.
	 * This is safe to do, since we may have a longer wait time for actions that arrive during this time, which is okay.
	 * If we get another reload while we're in one, we won't override it to avoid doing so twice, to ensure
	 * we always properly restore the original value.
	 *
	 * This is not merely done to avoid annoying logs... since we bail out if we don't receive a response in the threshold,
	 * we'll:
	 * a) Fail to return a response to the reload, which effectively returns an error for a reload that may have succeeded.
	 * b) Not fetch the response, which means when it does finish and arrive, somebody else will see it, which is not
	 *    what we wanted either.
	 *
	 * So we need to always remember to override maxwaitms to the maximum reasonable value for events that may
	 * take longer than normal, such as Reload.
	 */

	if (maxwaitms == AMI_MAX_WAIT_TIME) {
		maxwaitms = 7500; /* 7.5 seconds ought to be enough for any module to reload. */
	}

	resp = ami_action(ami, "Reload", "Module:%s", module);

	if (maxwaitms != AMI_MAX_WAIT_TIME) {
		maxwaitms = AMI_MAX_WAIT_TIME;
	}
	return ami_action_response_result(ami, resp);
}
