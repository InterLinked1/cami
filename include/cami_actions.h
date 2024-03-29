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
 * \brief C Asterisk Manager Interface AMI Actions
 *
 * \author Naveen Albert <asterisk@phreaknet.org>
 */

/*
 * For convenience, macros for some official Asterisk AMI
 * actions are included here.
 * You can also use the ami_action function directly to send
 * any arbitrary Action desired. These macros are purely for
 * convenience.
 *
 * Remember, do NOT add a trailing return and newline!
 */

/*! \todo Add more of these over time... */

/*!
 * \brief List all current channels
 * \param ami
 */
#define ami_action_show_channels(ami) ami_action(ami, "CoreShowChannels", "")

/*!
 * \brief Attended transfer
 * \param ami
 * \param chan Channel name
 * \param exten Extension
 * \param context Context
 */
#define ami_action_axfer(ami, chan, exten, context) ami_action(ami, "Atxfer", "Channel:%s\r\nExten:%s\r\nContext:%s", chan, exten, context)

/*!
 * \brief Cancel an attended transfer
 * \param ami
 * \param chan Channel name
 */
#define ami_action_cancel_axfer(ami, chan) ami_action(ami, "CancelAtxfer", "Channel:%s", chan)
