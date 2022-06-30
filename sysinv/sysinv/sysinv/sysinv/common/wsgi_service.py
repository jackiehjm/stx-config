# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

# Copyright (c) 2017 Wind River Systems, Inc.
#

import socket
from netaddr import IPAddress

from oslo_config import cfg
from oslo_log import log
from oslo_service import service
from oslo_service import wsgi
from sysinv._i18n import _
from sysinv.api import app
from sysinv.common import exception


CONF = cfg.CONF
LOG = log.getLogger(__name__)


class WSGIService(service.ServiceBase):
    """Provides ability to launch sysinv-api from wsgi app."""

    def __init__(self, name, host, port, workers, use_ssl=False):
        """Initialize, but do not start the WSGI server.

        :param name: The name of the WSGI server given to the loader.
        :param use_ssl: Wraps the socket in an SSL context if True.
        :returns: None
        """
        self.name = name
        self.app = app.VersionSelectorApplication()
        self.workers = workers
        if self.workers and self.workers < 1:
            raise exception.ConfigInvalid(
                _("api_workers value of %d is invalid, "
                  "must be greater than 0.") % self.workers)

        socket_family = None
        if IPAddress(host).version == 4:
            socket_family = socket.AF_INET
        elif IPAddress(host).version == 6:
            socket_family = socket.AF_INET6

        # If not defined, pool_size will default to 100. In order
        # to increase the amount of threads handling multiple parallel
        # requests to the wsgi application this parameter should be
        # increased.
        self.server = wsgi.Server(CONF, name, self.app,
                                  host=host,
                                  port=port,
                                  socket_family=socket_family,
                                  use_ssl=use_ssl,
                                  pool_size=250)

    def start(self):
        """Start serving this service using loaded configuration.

        :returns: None
        """
        self.server.start()

    def stop(self):
        """Stop serving this API.

        :returns: None
        """
        self.server.stop()

    def wait(self):
        """Wait for the service to stop serving this API.

        :returns: None
        """
        self.server.wait()

    def reset(self):
        """Reset server greenpool size to default.

        :returns: None
        """
        self.server.reset()
