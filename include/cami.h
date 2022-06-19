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

/* Max wait time in ms. Don't be tempted to make this too big, as this blocks all AMI traffic. Most of the time, it shouldn't really matter though. */
#define AMI_MAX_WAIT_TIME 500

/* Currently, it is expected that any single AMI response fit within a single buffer, so responses larger than this may be truncated and corrupted. */
#define AMI_BUFFER_SIZE 1048576

struct ami_field {
	char *key;		/*!< AMI field key */
	char *value;	/*!< AMI field value */
};

struct ami_event {
	int size;		/*!< Number of fields in event */
	int actionid;	/*!< Action ID (internal) */
	struct ami_field fields[];	/*!< Fields */
};

struct ami_response {
	int success:1;	/*!< Response indicates success? */
	int size;		/*!< Number of events, including the "event" at index 0 containing the fields for the response itself */
	int actionid;	/*!< ActionID for response */
	/* Sadly we cannot have something like struct ami_field fields[] here, because you can only have one flexible array member */
	struct ami_event *events[];	/*!< Events */
};

/*! \brief Enable debug logging */
/*! \param fd File descriptor to which optional debug log messages should be delivered. Default is off (-1) */
/*! \note This is not recommended for use in production, but may be helpful in a dev environment. */
void ami_set_debug(int fd);

/*! \brief Initialize an AMI connection with Asterisk */
/*! \param hostname Hostname (use 127.0.0.1 for localhost) */
/*! \param port Port number. Use 0 for the default port (5038) */
/*! \param callback Callback function for AMI events (not including responses to actions). */
/*! \param dis_callback Callback function if Asterisk disconnects our AMI connection. NOT invoked when ami_disconnect is called. This function is blocking so don't do anything too crazy inside. */
/*! \retval 0 on success, -1 if failure */
int ami_connect(const char *hostname, int port, void (*callback)(struct ami_event *event), void (*dis_callback)(void));

/*! \brief Close an existing AMI connection */
int ami_disconnect(void);

/*! \brief Print out the contents of an ami_event to stderr */
/*! \param event An AMI event */
void ami_dump_event(struct ami_event *event);

/*! \brief Print out the contents of an ami_response to stderr */
/*! \param resp An AMI response */
void ami_dump_response(struct ami_response *resp);

/*! \brief Retrieve the value of a specified key in an AMI event */
/*! \param event An AMI event */
/*! \brief key The name of the key of interest */
/*! \retval Key value if found or NULL if not found */
/*! \note You should strdup the return value if needed beyond the lifetime of event, or if you are going to modify it. */
const char *ami_keyvalue(struct ami_event *event, const char *key);

/*! \brief Free an AMI event */
/*! \param event AMI event */
/*! \note You must use this to free an AMI event! Do not use free, or you will create a memory leak! */
void ami_event_free(struct ami_event *event);

/*! \brief Free an AMI response */
/*! \param resp AMI response */
/*! \note You must use this to free an AMI response! Do not use free, or you will create a memory leak! */
/*! \note This function will automatically free any events encapsulated in it (no need to call ami_event_free for responses) */
void ami_resp_free(struct ami_response *resp);

/*! \brief Log in to an AMI session */
/*! \param username Asterisk AMI user username */
/*! \param password Asterisk AMI user secret */
/*! \retval 0 on success, -1 on failure */
/*! \note Assuming ami_connect was successful, this should be the first thing you call before doing anything else. */
int ami_action_login(const char *username, const char *password);

/*! \brief Request a custom AMI action */
/*! \action Name of AMI action (as defined by Asterisk) */
/*! \fmt Format string containing any action-specified AMI parameters, followed by your arguments (just like printf). Do NOT end with newlines. */
/*! \note Do NOT include any kind of ActionID. This is handled internally. */
struct ami_response *ami_action(const char *action, const char *fmt, ...);
