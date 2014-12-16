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
class TestSecurityBufferOverflowCreateService(providers.TestProviderBase):

    """Security Tests for Buffer Overflow vulnrablities
        for creating Service."""

    def setUp(self):
        super(TestSecurityBufferOverflowCreateService, self).setUp()
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

    @attrib.attr('security')
    def test_security_bufferoverflow_create_service(self):

        domain_list = [{"domain": "mywebsite.com"}]
        origin_list = [{"origin": "mywebsite1.com",
                         "port": 443,
                         "ssl": False}]
        caching_list = [{"name": "default", "ttl": 3600},
                         {"name": "home",
                          "ttl": 1200,
                          "rules": [{"name" : "index",
                                     "request_url" : "/index.htm"}]}]
        
        flavor_id = self.flavor_id

        for k in range(100000, 1500000, 100000):
          test_string = "A"*k

          for key in domain_list[0]:
            self.service_name = str(uuid.uuid1())
            domain_list[0][key] = test_string
            resp = self.client.create_service(service_name=self.service_name,
                                          domain_list=domain_list,
                                          origin_list=origin_list,
                                          caching_list=caching_list,
                                          flavor_id=flavor_id)
            self.assertTrue(resp.status_code<503)
          domain_list = [{"domain": "mywebsite.com"}]

          for key in origin_list[0]:
            self.service_name = str(uuid.uuid1())
            domain_list[0][key] = test_string
            resp = self.client.create_service(service_name=self.service_name,
                                          domain_list=domain_list,
                                          origin_list=origin_list,
                                          caching_list=caching_list,
                                          flavor_id=flavor_id)
            self.assertTrue(resp.status_code<503)
          origin_list = [{"origin": "mywebsite1.com",
                         "port": 443,
                         "ssl": False}]

          for key in caching_list[0]:
            self.service_name = str(uuid.uuid1())
            domain_list[0][key] = test_string
            resp = self.client.create_service(service_name=self.service_name,
                                          domain_list=domain_list,
                                          origin_list=origin_list,
                                          caching_list=caching_list,
                                          flavor_id=flavor_id)
            self.assertTrue(resp.status_code<503)
          caching_list = [{"name": "default", "ttl": 3600},
                         {"name": "home",
                          "ttl": 1200,
                          "rules": [{"name" : "index",
                                     "request_url" : "/index.htm"}]}]
        
          self.service_name = test_string
          resp = self.client.create_service(service_name=self.service_name,
                                          domain_list=domain_list,
                                          origin_list=origin_list,
                                          caching_list=caching_list,
                                          flavor_id=flavor_id)
          self.assertTrue(resp.status_code<503)

          self.service_name = str(uuid.uuid1())
          resp = self.client.create_service(service_name=self.service_name,
                                          domain_list=domain_list,
                                          origin_list=origin_list,
                                          caching_list=caching_list,
                                          flavor_id=test_string)
          self.assertTrue(resp.status_code<503)

