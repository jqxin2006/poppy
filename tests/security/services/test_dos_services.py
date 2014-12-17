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
class TestDOSCreateService(providers.TestProviderBase):

    """Security Tests for Denail of Service vulnerablities
        for creating Service."""

    def setUp(self):
        """
        Setup for the tests
        """
        super(TestDOSCreateService, self).setUp()
        self.domain_list = [{"domain": "mywebsite.com"}]
        self.origin_list = [{"origin": "mywebsite1.com",
                             "port": 443,
                             "ssl": False}]
        self.caching_list = [{"name": "default", "ttl": 3600},
                             {"name": "home",
                              "ttl": 1200,
                              "rules": [{"name": "index",
                                         "request_url": "/index.htm"}]}]
        self.service_name = str(uuid.uuid1())
        self.flavor_id = self.test_config.default_flavor

        if self.test_config.generate_flavors:
            # create the flavor
            self.flavor_id = str(uuid.uuid1())
            self.client.create_flavor(flavor_id=self.flavor_id,
                                      provider_list=[{
                                          "provider": "fastly",
                                          "links": [{"href": "www.fastly.com",
                                                     "rel": "provider_url"}]}])

    def reset_defaults(self):
        """
        Reset domain_list, origin_list, caching_list, service_name
        and flavor_id to its default value.
        """
        self.domain_list = [{"domain": "mywebsite.com"}]
        self.origin_list = [{"origin": "mywebsite1.com",
                             "port": 443,
                             "ssl": False}]
        self.caching_list = [{"name": "default", "ttl": 3600},
                             {"name": "home",
                              "ttl": 1200,
                              "rules": [{"name": "index",
                                         "request_url": "/index.htm"}]}]
        self.service_name = str(uuid.uuid1())
        self.flavor_id = self.test_config.default_flavor

    def check_one_request(self):
        """
        Check the response of one request to see whether one request can
        kill the application.
        """
        resp = self.client.create_service(service_name=self.service_name,
                                          domain_list=self.domain_list,
                                          origin_list=self.origin_list,
                                          caching_list=self.caching_list,
                                          flavor_id=self.flavor_id)
        # delete the service
        self.assertTrue(resp.status_code < 503)

        self.client.delete_service(service_name=self.service_name)

    @attrib.attr('security')
    def test_dos_create_service_domain_list(self):
        """
        Check whether it is possible to kill the application by
        creating a service with huge list of domains.
        """
        # create a huge list of domain
        self.reset_defaults()
        for k in range(1, 30000):
            self.domain_list.append({"domain": "w.t%s.com" % k})

        # send 10 requests
        for k in range(1, 10):
            self.check_one_request()

    @attrib.attr('security')
    def test_dos_create_service_origin_list(self):
        """
        Check whether it is possible to kill the application by
        creating a service with huge list of origins.
        """
        # create a huge list of domain
        self.reset_defaults()
        for k in range(1, 9000):
            self.origin_list.append({"origin": "m%s.com" % k,
                                     "port": 443,
                                     "ssl": False,
                                     "rules": [{"request_url": "/i.htm",
                                                "name": "i"}]})

        # send 10 requests
        for k in range(1, 10):
            self.check_one_request()

    @attrib.attr('security')
    def test_dos_create_service_caching_list(self):
        """
        Check whether it is possible to kill the application by
        creating a service with huge list of caching.
        """
        # create a huge list of domain
        self.reset_defaults()
        for k in range(1, 15000):
            self.caching_list.append({"name": "d%s" % k, "ttl": 3600})

        # send 10 requests
        for k in range(1, 10):
            self.check_one_request()

    @attrib.attr('security')
    def test_dos_create_service_caching_list_rules(self):
        """
        Check whether it is possible to kill the application by
        creating a service with huge list rules within caching list.
        """
        # create a huge list of domain
        self.reset_defaults()
        for k in range(1, 15000):
            self.caching_list[1]["rules"].append(
                {"name": "i%s" % k,
                 "request_url": "/index.htm"})

        # send 10 requests
        for k in range(1, 10):
            self.check_one_request()

    def tearDown(self):
        self.client.delete_service(service_name=self.service_name)

        if self.test_config.generate_flavors:
            self.client.delete_flavor(flavor_id=self.flavor_id)

        super(TestDOSCreateService, self).tearDown()
