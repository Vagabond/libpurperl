/*
 * libpurperl
 *
 * libpurperl is developed by Andrew Thompson <andrew@hijacked.us> but it
 * also includes code from the nullclient distributed as part of the libpurple
 * distribution. See the COPYRIGHT file in the pidgin source distribtion for
 * other contributor information.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02111-1301  USA
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <glib.h>
#include <purple.h>

#define PURPLE_GLIB_READ_COND  (G_IO_IN | G_IO_HUP | G_IO_ERR)
#define PURPLE_GLIB_WRITE_COND (G_IO_OUT | G_IO_HUP | G_IO_ERR | G_IO_NVAL)

#define UI_NAME "libpurperl"

GMainLoop *mainloop;
PurpleAccount *account = NULL;


typedef struct _PurpleGLibIOClosure {
	PurpleInputFunction function;
	guint result;
	gpointer data;
} PurpleGLibIOClosure;

static void purple_glib_io_destroy(gpointer data)
{
	g_free(data);
}

static void port_write(const char *message) {
	uint16_t len;

	len = htons(strlen(message));
	write(1, &len, sizeof(uint16_t));
	write(1, message, strlen(message));
}

static gboolean purple_glib_io_invoke(GIOChannel *source, GIOCondition condition, gpointer data)
{
	PurpleGLibIOClosure *closure = data;
	PurpleInputCondition purple_cond = 0;

	if (condition & PURPLE_GLIB_READ_COND)
		purple_cond |= PURPLE_INPUT_READ;
	if (condition & PURPLE_GLIB_WRITE_COND)
		purple_cond |= PURPLE_INPUT_WRITE;

	closure->function(closure->data, g_io_channel_unix_get_fd(source),
			  purple_cond);

	return TRUE;
}

static guint glib_input_add(gint fd, PurpleInputCondition condition, PurpleInputFunction function,
							   gpointer data)
{
	PurpleGLibIOClosure *closure = g_new0(PurpleGLibIOClosure, 1);
	GIOChannel *channel;
	GIOCondition cond = 0;

	closure->function = function;
	closure->data = data;

	if (condition & PURPLE_INPUT_READ)
		cond |= PURPLE_GLIB_READ_COND;
	if (condition & PURPLE_INPUT_WRITE)
		cond |= PURPLE_GLIB_WRITE_COND;

	channel = g_io_channel_unix_new(fd);
	closure->result = g_io_add_watch_full(channel, G_PRIORITY_DEFAULT, cond,
					      purple_glib_io_invoke, closure, purple_glib_io_destroy);

	g_io_channel_unref(channel);
	return closure->result;
}

static PurpleEventLoopUiOps glib_eventloops = 
{
	g_timeout_add,
	g_source_remove,
	glib_input_add,
	g_source_remove,
	NULL,
#if GLIB_CHECK_VERSION(2,14,0)
	g_timeout_add_seconds,
#else
	NULL,
#endif

	/* padding */
	NULL,
	NULL,
	NULL
};

static void
null_write_conv(PurpleConversation *conv, const char *who, const char *alias,
			const char *message, PurpleMessageFlags flags, time_t mtime)
{
	const char *name;
	char *msg;
	if (alias && *alias)
		name = alias;
	else if (who && *who)
		name = who;
	else
		name = NULL;

	asprintf(&msg, "(%s) %s %s: %s\n", purple_conversation_get_name(conv),
			purple_utf8_strftime("(%H:%M:%S)", localtime(&mtime)),
			name, message);
	port_write(msg);
	free(msg);
}

static PurpleConversationUiOps null_conv_uiops = 
{
	NULL,                      /* create_conversation  */
	NULL,                      /* destroy_conversation */
	NULL,                      /* write_chat           */
	NULL,                      /* write_im             */
	null_write_conv,           /* write_conv           */
	NULL,                      /* chat_add_users       */
	NULL,                      /* chat_rename_user     */
	NULL,                      /* chat_remove_users    */
	NULL,                      /* chat_update_user     */
	NULL,                      /* present              */
	NULL,                      /* has_focus            */
	NULL,                      /* custom_smiley_add    */
	NULL,                      /* custom_smiley_write  */
	NULL,                      /* custom_smiley_close  */
	NULL,                      /* send_confirm         */
	NULL,
	NULL,
	NULL,
	NULL
};

static void
null_ui_init(void)
{
	/**
	 * This should initialize the UI components for all the modules. Here we
	 * just initialize the UI for conversations.
	 */
	purple_conversations_set_ui_ops(&null_conv_uiops);
}

static PurpleCoreUiOps null_core_uiops = 
{
	NULL,
	NULL,
	null_ui_init,
	NULL,

	/* padding */
	NULL,
	NULL,
	NULL,
	NULL
};

static void
init_libpurple(void)
{
	/* Set a custom user directory (optional) */
	/*purple_util_set_user_dir(CUSTOM_USER_DIRECTORY);*/

	/* We do not want any debugging for now to keep the noise to a minimum. */
	purple_debug_set_enabled(FALSE);

	/* Set the core-uiops, which is used to
	 * 	- initialize the ui specific preferences.
	 * 	- initialize the debug ui.
	 * 	- initialize the ui components for all the modules.
	 * 	- uninitialize the ui components for all the modules when the core terminates.
	 */
	purple_core_set_ui_ops(&null_core_uiops);

	/* Set the uiops for the eventloop. If your client is glib-based, you can safely
	 * copy this verbatim. */
	purple_eventloop_set_ui_ops(&glib_eventloops);

	/* Set path to search for plugins. The core (libpurple) takes care of loading the
	 * core-plugins, which includes the protocol-plugins. So it is not essential to add
	 * any path here, but it might be desired, especially for ui-specific plugins. */
	/*purple_plugins_add_search_path(CUSTOM_PLUGIN_PATH);*/

	/* Now that all the essential stuff has been set, let's try to init the core. It's
	 * necessary to provide a non-NULL name for the current ui to the core. This name
	 * is used by stuff that depends on this ui, for example the ui-specific plugins. */
	if (!purple_core_init(UI_NAME)) {
		/* Initializing the core failed. Terminate. */
		port_write("-ERR libpurple initialization failed. Dumping core.");
		abort();
	}

	/* Create and load the buddylist. */
	purple_set_blist(purple_blist_new());
	purple_blist_load();

	/* Load the preferences. */
	purple_prefs_load();

	/* Load the desired plugins. The client should save the list of loaded plugins in
	 * the preferences using purple_plugins_save_loaded(PLUGIN_SAVE_PREF) */
	/*purple_plugins_load_saved(PLUGIN_SAVE_PREF);*/

	/* Load the pounces. */
	purple_pounces_load();
}



static void
signed_on(PurpleConnection *gc, gpointer null)
{
	PurpleAccount *account = purple_connection_get_account(gc);
	char *msg;
	asprintf(&msg, "+OK Account connected: %s %s\n", account->username, account->protocol_id);
	port_write(msg);
	free(msg);
}

static void
connection_error(PurpleConnection *gc, gpointer null)
{
	port_write("-ERR Login failed");
}

static void
connect_to_signals(void)
{
	static int handle;
	purple_signal_connect(purple_connections_get_handle(), "signed-on", &handle,
				PURPLE_CALLBACK(signed_on), NULL);
	purple_signal_connect(purple_connections_get_handle(), "connection-error", &handle,
				PURPLE_CALLBACK(connection_error), NULL);
}

void handle_message(char *message) {
	char *x;

	if ((x = strchr(message, ' '))) {
		*x = 0;
		x++;
		if (!strcasecmp(message, "login")) {
			char *username = x;
			char *password;
			char *protocol;

			if (account && purple_account_is_disconnected(account)) {
				purple_account_destroy(account);
			} else if (account) {
				port_write("-ERR Already connected");
				return;
			}
			account = NULL;

			if ((password = strchr(username, ' ')) && (protocol = strchr(password + 1, ' '))) {
				/*int protocolid;*/
				PurpleSavedStatus *status;
				*password = 0;
				password++;
				*protocol = 0;
				protocol++;

				account = purple_account_new(username, protocol);
				purple_account_set_password(account, password);
				purple_account_set_enabled(account, UI_NAME, TRUE);
				status = purple_savedstatus_new(NULL, PURPLE_STATUS_AVAILABLE);
				purple_savedstatus_activate(status);
				if (purple_account_is_disconnected(account))  {
					port_write("-ERR Login failed");
				}
			} else {
				port_write("-ERR Syntax: login <username> <password> <protocol ID>");
			}
		} else if (!strcasecmp(message, "message")) {
			char *messageto = x;
			char *message;
			if ((message = strchr(messageto, ' '))) {
				PurpleConversation *conv;
				PurpleConvIm       *im;

				*message = 0;
				message++;
				conv = purple_find_conversation_with_account(PURPLE_CONV_TYPE_IM, messageto, account);

				/* If not, create a new one */
				if (conv == NULL)
					conv = purple_conversation_new(PURPLE_CONV_TYPE_IM, account, messageto);

				/* Get the IM specific data */
				im = purple_conversation_get_im_data(conv);

				if (im) {
					purple_conv_im_send(im, message);
					port_write("+OK Message sent");
					return;
				}

				port_write("-ERR Failed to send message");

			} else {
				port_write("-ERR Syntax: message <username> <message>");
			}
		} else {
			char *errormsg;
			asprintf(&errormsg, "-ERR Unrecognized verb '%s'", message);
			port_write(errormsg);
			free(errormsg);
		}
	} else {
		if (!strcasecmp(message, "logout")) {
			if (account && !purple_account_is_disconnected(account)) {
				purple_account_disconnect(account);
				purple_account_destroy(account);
				account = NULL;
				port_write("+OK Logged out");
			} else {
				port_write("+ERR Not logged in");
			}
		} else {
			char *errormsg;
			asprintf(&errormsg, "-ERR Unrecognized verb '%s'", message);
			port_write(errormsg);
			free(errormsg);
		}
	}
}

gboolean socket_data(GIOChannel *source, GIOCondition condition, gpointer data) {
	uint16_t len;
	uint16_t inlen;
	char *inbuf;

	if (condition == G_IO_IN) {

		read(0, &len, 2);

		inlen = ntohs(len);
		inbuf = malloc(inlen + 1);

		memset(inbuf, 0, inlen+1);

		read(0, inbuf, inlen);

		handle_message(inbuf);

		/*write(1, &len, sizeof(uint16_t));*/
		/*write(1, inbuf, strlen(inbuf));*/
		free(inbuf);
	} else {
		g_main_loop_quit((GMainLoop*) data);
		return FALSE;
	}

	return TRUE;
}

int main(int argc, char** argv) {
	GIOChannel *chan = g_io_channel_unix_new(0);
	
	mainloop = g_main_loop_new (NULL, FALSE);

	signal(SIGCHLD, SIG_IGN);

	init_libpurple();

	port_write("libpurple initialized");

	g_io_add_watch(chan, G_IO_IN | G_IO_HUP | G_IO_ERR, socket_data, mainloop);

	connect_to_signals();

	g_main_loop_run (mainloop);

	return 0;
}
