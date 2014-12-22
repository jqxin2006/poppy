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
from tests.api import base
from tests.api import providers


@ddt.ddt
class TestXSSCreateService(providers.TestProviderBase):

    """Security Tests for XSS input in all fields of Create Service."""

    def setUp(self):
        """
        Setup for the tests
        """
        super(TestXSSCreateService, self).setUp()
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
        self.MAX_ATTEMPTS = 30

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

    """
    TODO: 
    *Add checks to remaining fields
    *GET created service and compare REQUEST and RESPONSE
    to check for escaping, URL encoding, etc.?
    """

    def check_one_request(self):
        """
        Check the response of one request to check for XSS input validation.
        """
        resp = self.client.create_service(service_name=self.service_name,
                                          domain_list=self.domain_list,
                                          origin_list=self.origin_list,
                                          caching_list=self.caching_list,
                                          flavor_id=self.flavor_id)
        self.assertNotEqual(resp.status_code, 200)
        
        # delete the service
        # self.client.delete_service(service_name=self.service_name)

    @attrib.attr('xss')
    @ddt.file_data('data_xss.json')
    def test_fuzz_create_service_domain_list(self, test_data):
        """
        Check whether it is possible to inject XSS in the application
        in the domain key.
        """
        # inject xss from data file into domain value
        self.reset_defaults()
        for k in test_data:
            self.domain_list = [{"domain": test_data['xss_string']}]
            self.service_name = str(uuid.uuid1())
            self.check_one_request()
    
    @attrib.attr('xss')
    @ddt.file_data('data_xss.json')
    def test_fuzz_create_service_origin_list(self, test_data):
        """
        Check whether it is possible to inject XSS in the application
        in the origin key.
        """
        # inject xss from data file into origin value
        self.reset_defaults()
        for k in test_data:
            self.origin_list = [{"origin": test_data['xss_string'],
                                "port": 443,
                                "ssl": False,
                                "rules": [{"request_url": "/x.htm",
                                            "name": "x"}]}]
            self.service_name = str(uuid.uuid1())
            self.check_one_request()
    
    @attrib.attr('xss')
    @ddt.file_data('data_xss.json')
    def test_fuzz_create_service_caching_list(self, test_data):
        """
        Check whether it is possible to inject XSS in the application
        in the caching key.
        """
        # inject xss from data file into caching values
        self.reset_defaults()
        for k in test_data:
            self.caching_list = [{"name": test_data['xss_string'],
                                    "ttl": 3600,
                                    "rules": [{"request_url": "/x.htm",
                                                "name": "caching-test"}]}]
            self.service_name = str(uuid.uuid1())
            self.check_one_request()
    
    @attrib.attr('xss')
    @ddt.file_data('data_xss.json')
    def test_fuzz_create_service_caching_list_rules(self, test_data):
        """
        Check whether it is possible to inject XSS in the application
        in the caching rules key.
        """
        # inject xss from data file into caching rules values
        self.reset_defaults()
        for k in test_data:
            self.caching_list[1]["rules"] = [{"name": test_data['xss_string'],
                                            "request_url": "/caching_rules_name_test.htm"}]
            self.service_name = str(uuid.uuid1())
            self.check_one_request()
    
    def tearDown(self):
        self.client.delete_service(service_name=self.service_name)

        if self.test_config.generate_flavors:
            self.client.delete_flavor(flavor_id=self.flavor_id)

        super(TestXSSCreateService, self).tearDown()


@ddt.ddt
class TestXSSListServices(base.TestBase):
    """Tests for List Services."""

    def _create_test_service(self):
        service_name = str(uuid.uuid1())

        self.domain_list = [{"domain": str(uuid.uuid1()) + '.com'}]

        self.origin_list = [{"origin": str(uuid.uuid1()) + '.com',
                             "port": 443, "ssl": False}]

        self.caching_list = [{"name": "default", "ttl": 3600},
                             {"name": "home", "ttl": 1200,
                              "rules": [{"name": "index",
                                         "request_url": "/index.htm"}]}]

        self.client.create_service(service_name=service_name,
                                   domain_list=self.domain_list,
                                   origin_list=self.origin_list,
                                   caching_list=self.caching_list,
                                   flavor_id=self.flavor_id)
        return service_name

    def setUp(self):
        super(TestXSSListServices, self).setUp()
        self.service_list = []
        if self.test_config.generate_flavors:
            self.flavor_id = str(uuid.uuid1())
            self.client.create_flavor(
                flavor_id=self.flavor_id,
                provider_list=[{"provider": "fastly",
                                "links": [{"href": "www.fastly.com",
                                           "rel": "provider_url"}]}])
        else:
            self.flavor_id = self.test_config.default_flavor

    @attrib.attr('xss')
    @ddt.file_data('data_xss.json')
    def test_list_services_xss_limits(self, test_data):
        """
        Test whether is possible to inject XSS in limit parameter
        """
        url_param = {'limit': test_data['xss_string']}
        resp = self.client.list_services(param=url_param)
        self.assertEqual(resp.status_code, 400)

    @attrib.attr('xss')
    @ddt.file_data('data_xss.json')
    def test_list_services_xss_marker(self, test_data):
        url_param = {'marker': test_data['xss_string']}
        resp = self.client.list_services(param=url_param)
        self.assertEqual(resp.status_code, 200)

    def tearDown(self):
        for service in self.service_list:
            self.client.delete_service(service_name=service)

        if self.test_config.generate_flavors:
            self.client.delete_flavor(flavor_id=self.flavor_id)

        super(TestXSSListServices, self).tearDown()

