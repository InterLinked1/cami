/*
 * CAMI -- C Asterisk Manager Interface
 *
 * Copyright (C) 2022, Naveen Albert
 *
 * Naveen Albert <asterisk@phreaknet.org>
 *
 * This program is free software, distributed under the terms of
 * the GNU General Public License Version 2.
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
#include <alloca.h>
#include <sys/time.h>	/* use gettimeofday */

#include "include/cami.h"

/*! \brief Default Asterisk Manager Interface port is 5038 */
#define AMI_PORT 5038
/*! \brief This is the finale to any message exchange. */
#define AMI_EOM "\r\n\r\n"

#define AMI_MAX_ACTIONID_STRLEN 9
#define AMI_RESPONSE_PREVIEW_SIZE 32
#define OUTBOUND_BUFFER_SIZE 2048

/*! \brief Allows using variadic arguments internally without going through ami_action first */
#define ami_send(action, fmt, ...) __ami_send("Action:%s\r\nActionID:%d\r\n" fmt AMI_EOM, action, ++ami_msg_id, __VA_ARGS__)

/*! \brief Simple logger, with second:millisecond, lineno display */
#define ami_debug(fmt, ...) { \
	struct timeval tv; \
	gettimeofday(&tv, NULL); \
	if (debugfd != -1) dprintf(debugfd, "%llu:%03lu : %d : " fmt, (((long long)tv.tv_sec)), (tv.tv_usec/1000), __LINE__, ## __VA_ARGS__); \
}

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

static pthread_t ami_thread;
static int ami_socket = -1;
static int debugfd = -1;
static int ami_pipe[2];	/* Pipe for sending actions to Asterisk */
static int ami_read_pipe[2];	/* Pipe for reading action responses from Asterisk */
static void (*ami_callback)(struct ami_event *event);
static void (*disconnected_callback)(void);

static pthread_mutex_t ami_read_lock;
/* Reading is protected by the ami_read_lock */
static struct ami_response *current_response = NULL;

static int loggedin;
static int tx;
static int rx;
static int ami_msg_id;

/* Forward declaration */
static void ami_event_handle(char *data);

static void ami_cleanup(void)
{
	close(ami_socket);
	close(ami_pipe[0]);
	close(ami_pipe[1]);
	close(ami_read_pipe[0]);
	close(ami_read_pipe[1]);
	ami_socket = -1;
	loggedin = 0;
	tx = rx = 0;
	if (current_response) {
		ami_resp_free(current_response);
		current_response = NULL;
	}
}

static void *ami_loop(void *vargp)
{
	int res;
	/* It's incoming data (from Asterisk) that could be very large. Outgoing data (to Asterisk) is unlikely to be particularly large. */
	char inbuf[AMI_BUFFER_SIZE];
	char outbuf[OUTBOUND_BUFFER_SIZE];
	struct pollfd fds[2];

	if (ami_socket < 0) {
		return NULL;
	}

	fds[0].fd = ami_socket;
	fds[0].events = POLLIN;
	fds[1].fd = ami_pipe[0];
	fds[1].events = POLLIN;

	for (;;) {
		res = poll(fds, 2, -1);
		pthread_testcancel();
		if (res < 0) {
			if (errno != EINTR) {
				ami_debug("poll returned error: %s\n", strerror(errno));
			}
			continue;
		}
		/* Data from AMI to deliver to consumer? */
		if (fds[0].revents) {
			res = recv(ami_socket, inbuf, AMI_BUFFER_SIZE - 2, 0);
			if (res < 1) {
				break;
			}
			/* This prevents part of the last response from persisting in msg if that one was longer. */
			/* We could memset(inbuf, '\0', AMI_BUFFER_SIZE), but even better: */
			inbuf[res] = '\0'; /* Won't be out of bounds, since we only read max AMI_BUFFER_SIZE - 2 */
			ami_event_handle(inbuf);
		}
		/* Data from consumer to deliver to AMI? */
		if (fds[1].revents) {
			/* Copy data on the pipe into the buffer */
			res = read(ami_pipe[0], outbuf, sizeof(outbuf));
			if (res < 1) {
				ami_debug("read returned %d\n", res);
				break;
			}
			res = write(ami_socket, outbuf, res);
			if (res < 1) {
				ami_debug("write returned %d\n", res);
				break;
			}
		}
	}
	ami_cleanup();
	if (disconnected_callback) {
		disconnected_callback(); /* let the caller know we're being forced to exit (e.g. by Asterisk) */
	}
	return NULL;
}

int ami_connect(const char *hostname, int port, void (*callback)(struct ami_event *event), void (*dis_callback)(void))
{
	int fd;
	struct sockaddr_in saddr;

	if (ami_socket >= 0) {
		/* Should pretty much NEVER happen on a clean cleanup */
		ami_debug("Hmm... socket already registered?\n");
		/* Maybe we just exited and we got started up again before cleanup could finish. */
		usleep(100); /* I dunno how many CPU cycles "return NULL" takes, but this oughta be plenty... */
		if (ami_socket >= 0) {
			ami_debug("Socket still registered...\n");
			/*
			 * If we wanted to be really mean, we could return -1 now
			 * But instead we'll just continue and overwrite everything.
			 * It'll be okay... it doesn't *really* matter...
			 * It just means that somebody probably called ami_connect twice
			 * without disconnecting inbetween...
			 *
			 * Just kidding!
			 */
			return -1;
		}
	}

	memset(&saddr, 0, sizeof(saddr));
	if (!port) {
		port = AMI_PORT;
	}

	/* If we can't make a pipe, forget about the socket. */
	if (socketpair(AF_LOCAL, SOCK_STREAM, 0, ami_pipe)) {
		ami_debug("Unable to create pipe: %s\n", strerror(errno));
		return -1;
	}
	if (socketpair(AF_LOCAL, SOCK_STREAM, 0, ami_read_pipe)) {
		ami_debug("Unable to create pipe: %s\n", strerror(errno));
		return -1;
	}

	fd = socket(AF_INET, SOCK_STREAM, 0);
	if (fd < 0) {
		ami_debug("%s\n", strerror(errno));
		return -1;
	}
	inet_pton(AF_INET, hostname, &(saddr.sin_addr));
	saddr.sin_family = AF_INET;
	saddr.sin_port = htons(port); /* use network order */
	if (connect(fd, (struct sockaddr *) &saddr, sizeof(saddr)) < 0) {
		ami_debug("%s\n", strerror(errno));
		return -1;
	}
	ami_socket = fd;
	ami_callback = callback;
	disconnected_callback = dis_callback;
	ami_msg_id = 0;
	loggedin = 0;
	tx = rx = 0;

	{
		pthread_mutexattr_t attr;
		pthread_mutexattr_init(&attr);
		pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE_NP);
		pthread_mutex_init(&ami_read_lock, &attr);
		pthread_mutexattr_destroy(&attr);
	}

	pthread_create(&ami_thread, NULL, ami_loop, NULL);

	return 0;
}

int ami_disconnect(void)
{
	if (ami_socket < 0) {
		return -1;
	}
	pthread_cancel(ami_thread);
	pthread_kill(ami_thread, SIGURG);
	pthread_join(ami_thread, NULL);
	if (ami_socket >= 0) {
		ami_debug("Since we killed the AMI connection, manually cleaning up\n");
		ami_cleanup();
	}
	return 0;
}

void ami_set_debug(int fd)
{
	debugfd = fd;
}

/*! \note I don't know why this causes gcc to whine... but this function DOES work correctly... */
#pragma GCC diagnostic ignored "-Wsuggest-attribute=format"
static int __ami_send(const char *fmt, ...)
{
	int res = 0;
	char *buf;
	int len;
	va_list ap;

	va_start(ap, fmt);
	if ((len = vasprintf(&buf, fmt, ap)) < 0) {
		va_end(ap);
		return -1;
	}
	va_end(ap);
	ami_debug("==> AMI Action:\n%s", buf); /* There's already (multiple) new lines at the end, don't add more */
	if (write(ami_pipe[1], buf, len) < 1) {
		ami_debug("Failed to write to pipe\n");
		res = -1;
	}
	if (!res) {
		tx++;
	}
	free(buf);
	return res;
}
#pragma GCC diagnostic pop

#ifdef AMI_EXTRA_DEBUG
/*! \brief Replace carriage returns and newlines with R and N for (clearer) visible debugging */
static void debug_string(const char *str)
{
	char *s, *dup = strdup(str);
	if (!dup) {
		return;
	}
	s = dup;
	while (*s) {
		if (*s == '\r') {
			*s = 'R';
		} else if (*s == '\n') {
			*s = 'N';
		}
		s++;
	}
	ami_debug("Debugging string: '%s'\n", dup);
	free(dup);
}
#endif

static struct ami_event *ami_parse_event(char *data)
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

	event->size = newlines;
	dup = strdup(data);
	dup2 = dup; /* You can NOT use strsep directly on a malloc'd pointer */

	while ((outer = strsep(&dup2, "\n"))) {
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

static struct ami_response *ami_parse_response(char *data)
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
		*outer = '\0';;
		resp->events[i] = ami_parse_event(dup2);
		if (i == 0) {
			const char *response;
			/* This "event" contains the fields for the response itself. */
			resp->actionid = resp->events[i]->actionid;
			response = ami_keyvalue(resp->events[i], "Response");
			resp->success = !strcasecmp(response, "Success") ? 1 : 0;
		} else {
			if (resp->events[i]->actionid && resp->actionid != resp->events[i]->actionid) {
				ami_debug("BUG! Expected ActionID %d but event has %d\n", resp->actionid, resp->events[i]->actionid);
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
		if (!strcasecmp(key, event->fields[i].key)) {
			value = event->fields[i].value;
			break;
		}
	}
	return value;
}

static void ami_event_handle(char *data)
{
	if (rx++ == 0) { /* This is the first thing we received (probably Asterisk identifiying itself). */
		ami_debug("*** Initialized Asterisk Manager Interface ***\n");
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
		ami_debug("<== AMI Response: %.*s...\n", AMI_RESPONSE_PREVIEW_SIZE, data); /* Only show a preview of the first "chunk", since it could be large... */
		resp = ami_parse_response(data);
		if (!resp) {
			ami_debug("Failed to parse response?\n");
		} else if (resp->size < 1) {
			ami_debug("Size is %d?\n", resp->size);
			ami_resp_free(resp);
		} else if (resp->actionid != ami_msg_id) {
			/* No need to check that resp->actionid is nonzero. Every response has an ActionID in the response. */
			ami_debug("Received response with ActionID %d, but we expected %d\n", resp->actionid, ami_msg_id);
		} else {
			char buf[AMI_MAX_ACTIONID_STRLEN];
			snprintf(buf, AMI_MAX_ACTIONID_STRLEN, "%d", resp->actionid);
			/* Remember... consumer is holding ami_read_lock until it gets the response. */
			/* Don't try to lock ami_read_lock until AFTER we write to the pipe, or we'll cause deadlock. */
			if (current_response) {
				/* Could indicate a bug, but not necessarily... perhaps the consumer just forgot about it? */
				ami_debug("Found a response still active? Somebody's getting his lunch stolen...\n");
				current_response = NULL;
			}
			current_response = resp;
			if (write(ami_read_pipe[1], buf, strlen(buf) + 1) < 1) { /* Add 1 for null terminator */
				ami_debug("Couldn't write to read pipe?\n");
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
			pthread_mutex_lock(&ami_read_lock);
			/* Okay, at this point current_response should be NULL. (We're the only thread serving up responses) */
			if (current_response) {
				ami_debug("BUG! current_response was %p immediately after lock acquired?\n", current_response);
			}
			pthread_mutex_unlock(&ami_read_lock);
#else
			if (!pthread_mutex_trylock(&ami_read_lock)) {
				if (current_response) {
					ami_debug("BUG! current_response was %p immediately after lock acquired?\n", current_response);
				}
				pthread_mutex_unlock(&ami_read_lock);
			}
#if EXTRA_DEBUG
			else {
				ami_debug("Could not acquire ami_read_lock just for fun, another thread beat us to it...\n");
			}
#endif
#endif
		}
	} else {
		struct ami_event *event;
		/* A single, unsolicited event (not in response to an action) */
		ami_debug("<== AMI Event: %s\n", data); /* Show the whole thing, it's probably not THAT big... */
		if (ami_callback) {
			rtrim(data); /* ami_parse_event expects NO trailing newlines at the end. */
			event = ami_parse_event(data);
			/* Provide the user with the original event, user is responsible for freeing */
			ami_callback(event);
		}
		return;
	}
}

static int ami_wait_for_response(int msgid)
{
	int res;
	struct pollfd fds;

	if (ami_read_pipe[0] < 0) {
		return -1;
	}

	fds.fd = ami_read_pipe[0];
	fds.events = POLLIN;

	res = poll(&fds, 1, AMI_MAX_WAIT_TIME);
	if (res < 0) {
		if (errno != EINTR) {
			ami_debug("poll returned error: %s\n", strerror(errno));
		} else {
			ami_debug("poll returned something else: %s\n", strerror(errno));
		}
		return -1;
	} else if (!res) { /* Nothing happened */
		ami_debug("Didn't receive any AMI response within %d ms?\n", AMI_MAX_WAIT_TIME);
		if (current_response) {
			/* Chances of this happening are almost nil, but it could happen... maybe? */
			ami_debug("Okay, weird, we must have missed it before...\n");
			return 0;
		}
		return -1;
	} else if (fds.revents) {
		int eventnum;
		char buf[AMI_MAX_ACTIONID_STRLEN];
		if (read(ami_read_pipe[0], buf, AMI_MAX_ACTIONID_STRLEN) < 1) {
			ami_debug("read pipe failed?\n");
			return -1;
		}
		eventnum = atoi(buf);
		if (msgid != eventnum) {
			ami_debug("Strange... got event %d, not %d\n", eventnum, msgid);
		}
		return 0;
	} else {
		ami_debug("How'd I get here?\n");
		return -1;
	}
}

struct ami_response *ami_action(const char *action, const char *fmt, ...)
{
	struct ami_response *resp = NULL;
	/* Remember: no trailing \r\n !*/
	int res, len, actionid;
	char *buf, *back, *fmt2;
	va_list ap;

	if (ami_socket < 0) {
		/* Connection got shutdown */
		ami_debug("Can't send AMI action without active socket\n");
		return NULL;
	}
	if (!loggedin) {
		/* Silly you! You can't use AMI if you're not logged in... */
		ami_debug("Requested AMI action but not yet logged in?\n");
		return NULL;
	}

	/* Eliminate any trailing spacing at the end of fmt */
	fmt2 = strdup(fmt);
	if (!fmt2) {
		return NULL;
	}
	back = fmt2 + strlen(fmt2);
	while (back != fmt2 && isspace(*--back));
	if (*fmt2) {
		*(back + 1) = '\0';
	}

	len = strlen(fmt) + strlen(action) + strlen(fmt) + 15;
	buf = malloc(len);
	if (!buf) {
		free(fmt2);
		return NULL;
	}

	/* If we don't have a user-supplied format string, don't add \r\n after ActionID or we'll get 3 sets in a row and cause Asterisk to whine. */
	snprintf(buf, len, "%s%s%s", *fmt2 ? "Action:%s\r\nActionID:%d\r\n" : "Action:%s\r\nActionID:%d", fmt2, AMI_EOM); /* Make our full format string */

	/* Nobody sends anything else until we get our response. */
	pthread_mutex_lock(&ami_read_lock);

	va_start(ap, fmt);
	res = __ami_send(buf, action, ++ami_msg_id);
	va_end(ap);

	actionid = ami_msg_id; /* This is the ActionID we expect in our response */
	free(buf);
	free(fmt2);

	if (res) {
		ami_debug("Failed to send AMI action\n");
		pthread_mutex_unlock(&ami_read_lock);
		return NULL; /* Failed to send */
	}

	/* Now wait until we (hopefully) get a response... */
	res = ami_wait_for_response(actionid);
	resp = current_response;
	current_response = NULL; /* All right, now resp is somebody's else problem, we're not responsible for freeing it... */
	pthread_mutex_unlock(&ami_read_lock);
	if (!res) {
		if (!resp) {
			ami_debug("BUG! Told we got a response, but can't find it?\n");
		} else {
			if (resp->actionid != actionid) {
				/*! \note If we ever make it so multiple AMI responses can go out at once, this may need to be revisited... */
				ami_debug("BUG! Expected ActionID %d in response, but got %d\n", actionid, current_response->actionid);
			} else if (!resp->success) {
				/* We got a response, and it's telling us that we failed. */
				ami_resp_free(resp); /* If we're not returning it to the user, free it now */
				resp = NULL; /* Try harder next time... */
			}
		}
	}

	return resp;
}

int ami_action_login(const char *username, const char *password)
{
	struct ami_response *resp;
	int res;

	if (ami_socket < 0) {
		/* Chance of us getting booted between when established the connection
		 * and now are basically nil, but check anyways, just in case.
		 */
		ami_debug("AMI socket closed before we could try to log in\n");
		return -1;
	}

	/* Nobody sends anything else until we get our response. */
	pthread_mutex_lock(&ami_read_lock);
	/* Remember: no trailing \r\n !*/
	if (ami_send("Login", "Username:%s\r\nSecret:%s", username, password)) {
		ami_debug("Failed to send AMI action\n");
		pthread_mutex_unlock(&ami_read_lock);
		return -1; /* Failed to send */
	}
	/* Now wait until we (hopefully) get a response... */
	res = ami_wait_for_response(ami_msg_id);
	resp = current_response;
	current_response = NULL; /* we're done with this guy... */
	pthread_mutex_unlock(&ami_read_lock);
	if (!res) {
		if (!resp) {
			ami_debug("BUG! Told we got a response, but can't find it?\n");
		} else {
			if (!resp->success) {
				/* We got a response, and it's telling us that we failed. */
				res = -1; /* Try harder next time... */
			} else {
				loggedin = 1;
			}
			ami_resp_free(resp); /* We don't need to do anything more with this. */
		}
	}

	return res;
}
