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
import re
from nose.plugins import attrib
from tests.api import providers


@ddt.ddt
class TestTransportFlavors(providers.TestProviderBase):

    """Security Tests for transport layer security vulnerablities
        for flavor calls."""

    def setUp(self):
        """
        Setup for the tests
        """
        super(TestTransportFlavors, self).setUp()
        self.reset_defaults()

    def reset_defaults(self):
        """
        Reset provider_list, limit_list
        and flavor_id to their default values.
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
        Create one flavor and check whether it has been
        sucessfully created.
        """
        resp = self.client.create_flavor(flavor_id=self.flavor_id,
                                         provider_list=self.provider_list,
                                         limits=self.limits_list)
        self.assertTrue(resp.status_code == 202)

    @attrib.attr('security')
    def test_transport_check_https(self):
        """
        Check whether https is used for all links returned from get_service
        calls. If https is not used in any link, the test fails.
        """
        self.reset_defaults()
        self.flavor_id = str(uuid.uuid1())
        # create one flavor
        self.check_one_request()
        resp = self.client.list_flavors()
        # make sure that http:// is not used anywhere
        self.assertTrue(re.search("http://", resp.text) is None)

    def tearDown(self):
        self.client.delete_flavor(flavor_id=self.flavor_id)
        super(TestTransportFlavors, self).tearDown()
