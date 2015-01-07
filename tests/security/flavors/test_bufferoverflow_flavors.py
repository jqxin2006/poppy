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
class TestBufferOverflowCreateFlavor(providers.TestProviderBase):

    """Security Tests for Buffer Overflow vulnerablities
        for creating Flavor."""

    def setUp(self):
        """
        Setup for the tests
        """
        super(TestBufferOverflowCreateFlavor, self).setUp()
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
        Check the response of one request to see whether the application
        is vulnerable to buffer overflow.
        """
        resp = self.client.create_flavor(flavor_id=self.flavor_id,
                                         provider_list=self.provider_list,
                                         limits=self.limits_list)
        # delete the flavor
        self.assertTrue(resp.status_code < 503)
        self.client.delete_flavor(flavor_id=self.flavor_id)

    @attrib.attr('security')
    @ddt.file_data('../services/bufferoverflow.json')
    def test_bufferoverflow_flavor_id(self, test_data):

        self.flavor_id = "A" * test_data['buffer_length']
        self.check_one_request()
        self.reset_defaults()

    @attrib.attr('security')
    @ddt.file_data('../services/bufferoverflow.json')
    def test_sql_provider(self, test_data):

        test_string = "A" * test_data['buffer_length']
        for key in self.provider_list[0]:
            self.flavor_id = str(uuid.uuid1())
            # to do. This is currently tied with existing examples.
            if isinstance(self.provider_list[0][key], (list)):
                for the_key in self.provider_list[0][key][0]:
                    self.provider_list[0][key][0][the_key] = test_string
                    self.check_one_request()
                    self.reset_defaults()
            else:
                self.provider_list[0][key] = test_string
                self.check_one_request()
                self.reset_defaults()

    @attrib.attr('security')
    @ddt.file_data('../services/bufferoverflow.json')
    def test_sql_limits(self, test_data):

        test_string = "A" * test_data['buffer_length']
        for i in range(len(self.limits_list)):
            for key in self.limits_list[i]:
                self.flavor_id = str(uuid.uuid1())
                # to do. This is currently tied with existing examples.
                if isinstance(self.limits_list[i][key], (dict)):
                    for the_key in self.limits_list[i][key]:
                        self.limits_list[i][key][the_key] = test_string
                        self.check_one_request()
                        self.reset_defaults()
                else:
                    self.limits_list[i][key] = test_string
                    self.check_one_request()
                    self.reset_defaults()

    def tearDown(self):
        self.client.delete_flavor(flavor_id=self.flavor_id)
        super(TestBufferOverflowCreateFlavor, self).tearDown()
