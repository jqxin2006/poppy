# coding= utf-8

# Copyright (c) 2014 Rackspace, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import uuid
import ddt
from nose.plugins import attrib
from tests.api import providers


@ddt.ddt
class TestDOSCreateFlavor(providers.TestProviderBase):

    """Security Tests for Denial of Service vulnerablities
        for creating Flavor."""

    def setUp(self):
        """
        Setup for the tests
        """
        super(TestDOSCreateFlavor, self).setUp()
        self.reset_defaults()
        self.MAX_ATTEMPTS = 30

    def reset_defaults(self):
        """
        Reset provider_list, limit_list
        and flavor_id to its default values.
        """
        self.provider_list = [{"provider": "fastly",
                               "links": [{"href": "www.watermelon.com",
                                          "rel": "provider_url"}]}]
        self.limits_list = [{"origins": {"min": 1, "max": 5}},
                            {"domains": {"min": 1, "max": 5}},
                            {"caching": {"min": 3600,
                                         "max": 604800, "incr": 300}}]
        self.flavor_id = str(uuid.uuid1())

    def check_one_request(self):
        """
        Check the response of one request to see whether request can
        kill the application.
        """
        resp = self.client.create_flavor(flavor_id=self.flavor_id,
                                         provider_list=self.provider_list,
                                         limits=self.limits_list)
        # delete the flavor
        self.assertTrue(resp.status_code < 503)

        self.client.delete_flavor(flavor_id=self.flavor_id)

    @attrib.attr('security')
    def test_dos_create_flavor_provider_list(self):
        """
        Check whether it is possible to kill the application by
        creating a service with huge list of providers.
        """
        # create a huge list of providers
        self.reset_defaults()
        for k in range(1, 30000):
            self.provider_list.append({"provider": "w.t%s.com" % k})

        # send 10 requests
        for k in range(1, self.MAX_ATTEMPTS):
            self.check_one_request()

    @attrib.attr('security')
    def test_dos_create_flavor_provider_list_links(self):
        """
        Check whether it is possible to kill the application by
        creating a flavor with a huge list links within provider list.
        """
        # create a huge list of links
        self.reset_defaults()
        for k in range(1, 15000):
            self.provider_list[0]["links"].append(
                {"href": "i%s" % k,
                 "rel": "/index.htm"})

        # send 10 requests
        for k in range(1, self.MAX_ATTEMPTS):
            self.check_one_request()

    @attrib.attr('security')
    def test_dos_create_flavor_limits_list(self):
        """
        Check whether it is possible to kill the application by
        creating a flavor with huge list of origins.
        """
        # create a huge list of origins
        self.reset_defaults()
        self.limits_list.append({"domains": {"min": 1, "max": 5}})
        self.limits_list.append({"caching": {"min": 3600,
                                             "max": 604800, "incr": 300}})
        for k in range(1, 9000):
            self.limits_list.append({"origins": {"min": "%s" % k, "max": 5}})

        # send 10 requests
        for k in range(1, self.MAX_ATTEMPTS):
            self.check_one_request()

    def tearDown(self):
        self.client.delete_flavor(flavor_id=self.flavor_id)
        super(TestDOSCreateFlavor, self).tearDown()
