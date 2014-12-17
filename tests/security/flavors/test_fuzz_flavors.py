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
from tests.api.utils.schema import flavors


@ddt.ddt
class TestFuzzCreateFlavor(providers.TestProviderBase):

    """Security Tests for Fuzzing Create Flavor."""

    def setUp(self):
        super(TestFuzzCreateFlavor, self).setUp()
        self.flavor_id = str(uuid.uuid1())
    
    @attrib.attr('fuzz')
    @ddt.file_data('data_fuzz.json')
    def test_fuzz_flavor_id(self, test_data):

        provider_list = [{"provider": "fastly",
                          "links": [{"href": "www.watermelon.com", "rel": "provider_url"}]}]
        limits = [{"origins": {"min": 1, "max": 5}},
                  {"domains": {"min": 1, "max": 5}},
                  {"caching": {"min": 3600, "max": 604800, "incr": 300}}]
        
        flavor_id = test_data['fuzz_string']
        resp = self.client.create_flavor(flavor_id=flavor_id,
                                          provider_list=provider_list,
                                          limits=limits)
        self.assertNotEqual(resp.status_code, 500)
    
    @attrib.attr('fuzz')
    @ddt.file_data('data_fuzz.json')
    def test_fuzz_provider(self, test_data):

        provider_list = [{"provider": test_data['fuzz_string'],
                          "links": [{"href": "www.watermelon.com", "rel": "provider_url"}]}]
        limits = [{"origins": {"min": 1, "max": 5}},
                  {"domains": {"min": 1, "max": 5}},
                  {"caching": {"min": 3600, "max": 604800, "incr": 300}}]

        resp = self.client.create_flavor(flavor_id=self.flavor_id,
                                          provider_list=provider_list,
                                          limits=limits)
        self.assertNotEqual(resp.status_code, 500)
    
    @attrib.attr('fuzz')
    @ddt.file_data('data_fuzz.json')
    def test_fuzz_href(self, test_data):

        provider_list = [{"provider": "fastly",
                          "links": [{"href": test_data['fuzz_string'], "rel": "provider_url"}]}]
        limits = [{"origins": {"min": 1, "max": 5}},
                  {"domains": {"min": 1, "max": 5}},
                  {"caching": {"min": 3600, "max": 604800, "incr": 300}}]

        resp = self.client.create_flavor(flavor_id=self.flavor_id,
                                          provider_list=provider_list,
                                          limits=limits)
        self.assertNotEqual(resp.status_code, 500)
    
    @attrib.attr('fuzz')
    @ddt.file_data('data_fuzz.json')
    def test_fuzz_rel(self, test_data):

        provider_list = [{"provider": "fastly",
                          "links": [{"href": "www.watermelon.com", "rel": test_data['fuzz_string']}]}]
        limits = [{"origins": {"min": 1, "max": 5}},
                  {"domains": {"min": 1, "max": 5}},
                  {"caching": {"min": 3600, "max": 604800, "incr": 300}}]

        resp = self.client.create_flavor(flavor_id=self.flavor_id,
                                          provider_list=provider_list,
                                          limits=limits)
        self.assertNotEqual(resp.status_code, 500)
    
    @attrib.attr('fuzz')
    @ddt.file_data('data_fuzz.json')
    def test_fuzz_origins_min(self, test_data):

        provider_list = [{"provider": "fastly",
                          "links": [{"href": "www.watermelon.com", "rel": "provider_url"}]}]
        limits = [{"origins": {"min": test_data['fuzz_string'], "max": 5}},
                  {"domains": {"min": 1, "max": 5}},
                  {"caching": {"min": 3600, "max": 604800, "incr": 300}}]

        resp = self.client.create_flavor(flavor_id=self.flavor_id,
                                          provider_list=provider_list,
                                          limits=limits)
        self.assertNotEqual(resp.status_code, 500)
    
    @attrib.attr('fuzz')
    @ddt.file_data('data_fuzz.json')
    def test_fuzz_origins_max(self, test_data):

        provider_list = [{"provider": "fastly",
                          "links": [{"href": "www.watermelon.com", "rel": "provider_url"}]}]
        limits = [{"origins": {"min": 1, "max": test_data['fuzz_string']}},
                  {"domains": {"min": 1, "max": 5}},
                  {"caching": {"min": 3600, "max": 604800, "incr": 300}}]

        resp = self.client.create_flavor(flavor_id=self.flavor_id,
                                          provider_list=provider_list,
                                          limits=limits)
        self.assertNotEqual(resp.status_code, 500)
    
    @attrib.attr('fuzz')
    @ddt.file_data('data_fuzz.json')
    def test_fuzz_domains_min(self, test_data):

        provider_list = [{"provider": "fastly",
                          "links": [{"href": "www.watermelon.com", "rel": "provider_url"}]}]
        limits = [{"origins": {"min": 1, "max": 5}},
                  {"domains": {"min": test_data['fuzz_string'], "max": 5}},
                  {"caching": {"min": 3600, "max": 604800, "incr": 300}}]

        resp = self.client.create_flavor(flavor_id=self.flavor_id,
                                          provider_list=provider_list,
                                          limits=limits)
        self.assertNotEqual(resp.status_code, 500)
    
    @attrib.attr('fuzz')
    @ddt.file_data('data_fuzz.json')
    def test_fuzz_domains_max(self, test_data):

        provider_list = [{"provider": "fastly",
                          "links": [{"href": "www.watermelon.com", "rel": "provider_url"}]}]
        limits = [{"origins": {"min": 1, "max": 5}},
                  {"domains": {"min": 1, "max": test_data['fuzz_string']}},
                  {"caching": {"min": 3600, "max": 604800, "incr": 300}}]

        resp = self.client.create_flavor(flavor_id=self.flavor_id,
                                          provider_list=provider_list,
                                          limits=limits)
        self.assertNotEqual(resp.status_code, 500)
    
    @attrib.attr('fuzz')
    @ddt.file_data('data_fuzz.json')
    def test_fuzz_caching_min(self, test_data):

        provider_list = [{"provider": "fastly",
                          "links": [{"href": "www.watermelon.com", "rel": "provider_url"}]}]
        limits = [{"origins": {"min": 1, "max": 5}},
                  {"domains": {"min": 1, "max": 5}},
                  {"caching": {"min": test_data['fuzz_string'], "max": 604800, "incr": 300}}]

        resp = self.client.create_flavor(flavor_id=self.flavor_id,
                                          provider_list=provider_list,
                                          limits=limits)
        self.assertNotEqual(resp.status_code, 500)
    
    @attrib.attr('fuzz')
    @ddt.file_data('data_fuzz.json')
    def test_fuzz_caching_max(self, test_data):

        provider_list = [{"provider": "fastly",
                          "links": [{"href": "www.watermelon.com", "rel": "provider_url"}]}]
        limits = [{"origins": {"min": 1, "max": 5}},
                  {"domains": {"min": 1, "max": 5}},
                  {"caching": {"min": 3600, "max": test_data['fuzz_string'], "incr": 300}}]

        resp = self.client.create_flavor(flavor_id=self.flavor_id,
                                          provider_list=provider_list,
                                          limits=limits)
        self.assertNotEqual(resp.status_code, 500)
    
    @attrib.attr('fuzz')
    @ddt.file_data('data_fuzz.json')
    def test_fuzz_caching_incr(self, test_data):

        provider_list = [{"provider": "fastly",
                          "links": [{"href": "www.watermelon.com", "rel": "provider_url"}]}]
        limits = [{"origins": {"min": 1, "max": 5}},
                  {"domains": {"min": 1, "max": 5}},
                  {"caching": {"min": 3600, "max": 604800, "incr": test_data['fuzz_string']}}]

        resp = self.client.create_flavor(flavor_id=self.flavor_id,
                                          provider_list=provider_list,
                                          limits=limits)
        self.assertNotEqual(resp.status_code, 500)

    def tearDown(self):
        self.client.delete_flavor(flavor_id=self.flavor_id)
        super(TestFuzzCreateFlavor, self).tearDown()
