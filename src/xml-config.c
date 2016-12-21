/*
 * Copyright (C) 2016 Nikos Mavrogiannopoulos
 *
 * This file is part of ocserv.
 *
 * ocserv is free software: you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 2 of the License, or
 * (at your option) any later version.
 *
 * ocserv is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <config.h>

#include <gnutls/gnutls.h>
#include <vpn.h>
#include <main.h>
#include <common.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <worker.h>
#include "xml-config.h"

/* This loads the XML configuration file. This should be called
 * prior to privileges are dropped. */
void load_xml_config(main_server_st *s, void *pool, AuthCookieReplyMsg *msg)
{
	int fd;
	int ret;
	struct stat st;
	const char *config_file = msg->config->xml_config_file;

	if (config_file == NULL) {
		return;
	}

	fd = open(config_file, O_RDONLY);
	if (fd == -1) {
		mslog(s, NULL, LOG_INFO, "Cannot open XML config %s", config_file);
		return;
	}

	ret = fstat(fd, &st);
	if (ret == -1 || st.st_size == 0) {
		mslog(s, NULL, LOG_INFO, "cannot obtain config file info '%s'", config_file);
		goto cleanup;
	}

	msg->xml_config_contents.data = talloc_size(pool, st.st_size);
	if (msg->xml_config_contents.data == NULL) {
		msg->xml_config_contents.len = 0;
		goto cleanup;
	}

	msg->xml_config_contents.len = st.st_size;

	ret = force_read(fd, msg->xml_config_contents.data, st.st_size);
	if (ret < 0 || ret != st.st_size) {
		mslog(s, NULL, LOG_INFO, "cannot read config file '%s'", config_file);
		msg->xml_config_contents.data = NULL;
		msg->xml_config_contents.len = 0;
		goto cleanup;
	}

	msg->has_xml_config_contents = 1;

 cleanup:
	close(fd);
	return;
}
