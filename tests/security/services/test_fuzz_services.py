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
class TestFuzzService(providers.TestProviderBase):

    """Security Tests for fuzzing creating Services and other functions."""

    def setUp(self):
        """
        Setup for the tests
        """
        super(TestFuzzService, self).setUp()
        self.domain_list = [{"domain": "mywebsite.com"}]
        self.origin_list = [{"origin": "mywebsite1.com",
                             "port": 443,
                             "ssl": False}]
        self.caching_list = [{"name": "default", "ttl": 3600},
                             {"name": "home",
                              "ttl": 1200,
                              "rules": [{"name": "index",
                                         "request_url": "/index.htm"}]}]
        self.restrictions_list = [
            {
                u"name": u"website only",
                u"rules": [
                    {
                        u"name": "mywebsite.com",
                        u"referrer": "mywebsite.com"
                    }
                ]
            }
        ]
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
        self.restrictions_list = [
            {
                u"name": u"website only",
                u"rules": [
                    {
                        u"name": "mywebsite.com",
                        u"referrer": "mywebsite.com"
                    }
                ]
            }
        ]

    def check_one_request(self):
        """
        Check the response of one request to see whether the application
        generates any 500 errors.
        """
        resp = self.client.create_service(
            service_name=self.service_name,
            domain_list=self.domain_list,
            origin_list=self.origin_list,
            caching_list=self.caching_list,
            restrictions_list=self.restrictions_list,
            flavor_id=self.flavor_id)
        if 'location' in resp.headers:
            self.service_url = resp.headers['location']
        else:
            self.service_url = ''
        
        # delete the service
        self.assertTrue(resp.status_code < 500)
        if self.service_url != '':
            self.client.delete_service(location=self.service_url)

    @attrib.attr('fuzz')
    @ddt.file_data('data_fuzz.json')
    def test_fuzz_create_service(self, test_data):
        """
        Fuzz the create service calls to see whether 500 errors are generated.
        """
        test_string = test_data["fuzz_string"]
        #check domain list values
        for key in self.domain_list[0]:
            self.service_name = str(uuid.uuid1())
            self.domain_list[0][key] = test_string
            self.check_one_request()
            self.reset_defaults()
        #check origin list values
        for key in self.origin_list[0]:
            self.service_name = str(uuid.uuid1())
            self.origin_list[0][key] = test_string
            self.check_one_request()
            self.reset_defaults()
        #check the caching list values
        for key in self.caching_list[1]:
            self.service_name = str(uuid.uuid1())
            # to do. This is currently tied with existing examples.
            if isinstance(self.caching_list[1][key], (list)):
                for the_key in self.caching_list[1][key][0]:
                    self.caching_list[1][key][0][the_key] = test_string
                    self.check_one_request()
                    self.reset_defaults()
            else:
                self.caching_list[1][key] = test_string
                self.check_one_request()
                self.reset_defaults()
        # check the restriction list values
        for key in self.restrictions_list[0]:
            self.service_name = str(uuid.uuid1())
            # to do. This is currently tied with existing examples.
            if isinstance(self.restrictions_list[0][key], (list)):
                for the_key in self.restrictions_list[0][key][0]:
                    self.restrictions_list[0][key][0][the_key] = test_string
                    self.check_one_request()
                    self.reset_defaults()
            else:
                self.restrictions_list[0][key] = test_string
                self.check_one_request()
                self.reset_defaults()

        #check the service name
        self.service_name = test_string
        self.check_one_request()
        self.reset_defaults()

        #check the flavor_id
        self.flavor_id = test_string
        self.check_one_request()
        self.reset_defaults()

    def tearDown(self):
        if self.service_url != '':
            self.client.delete_service(location=self.service_url)

        if self.test_config.generate_flavors:
            self.client.delete_flavor(flavor_id=self.flavor_id)

        super(TestFuzzService, self).tearDown()
