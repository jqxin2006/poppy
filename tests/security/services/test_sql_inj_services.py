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
from tests.api.utils.schema import services


@ddt.ddt
class TestFuzzCreateService(providers.TestProviderBase):

    """Security Tests for Fuzzing Create Service."""

    def setUp(self):
        super(TestFuzzCreateService, self).setUp()
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

    @attrib.attr('fuzz2')
    @ddt.file_data('data_sql_inj.json')
    def test_fuzz_create_service2(self, test_data):

        domain_list = [{"domain": "mywebsite.com"},
                        {"domain": "blog.mywebsite.com"}]
        origin_list = [{"origin": "mywebsite1.com",
                         "port": 443,
                         "ssl": False}]
        caching_list = [{"name": "default", "ttl": 3600},
                         {"name": "home",
                          "ttl": 1200,
                          "rules": [{"name" : "index",
                                     "request_url" : "/index.htm"}]}]
        self.service_name = test_data['sql_inj_string']
        flavor_id = self.flavor_id

        resp = self.client.create_service(service_name=self.service_name,
                                          domain_list=domain_list,
                                          origin_list=origin_list,
                                          caching_list=caching_list,
                                          flavor_id=flavor_id)
        self.assertNotEqual(resp.status_code, 500)


    def tearDown(self):
        self.client.delete_service(service_name=self.service_name)

        if self.test_config.generate_flavors:
            self.client.delete_flavor(flavor_id=self.flavor_id)

        super(TestFuzzCreateService, self).tearDown()
