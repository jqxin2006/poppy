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
import gzip
import StringIO
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

    def create_invalid_json(self, length):
        """
        Create invalid_json like [[[[[[[[[[[[[test]]]]]]]]]]]]]
        """
        str = ""
        str += "[" * length
        str += "\"test\""
        str += "]" * length
        return str

    def create_malicious_json(self, length):
        """
        Create malicious json like {{{{t:{{{{{}}}}}}}}}
        """
        str = "{"
        for k in range(0, length):
            str += "\"t%s\":{" % k
        str += "\"t\":\"t\""
        for k in range(0, length):
            str += "}"
        str += "}"
        return str

    def data_zip(self, data):
        """
        zip the data using gzip format
        """
        stringio = StringIO.StringIO()
        gzip_file = gzip.GzipFile(fileobj=stringio, mode='wb')
        gzip_file.write(data)
        gzip_file.close()
        return stringio.getvalue()

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
    def test_invalid_json_create_flavor(self):
        """
        Check whether it is possible to kill the application by
        creating a big invalid json blob.
        """
        # create a payload with invalid json blob
        attack_string = self.create_invalid_json(2500)
        kwargs = {"data": attack_string}
        print kwargs
        resp = self.client.create_flavor(flavor_id=self.flavor_id,
                                         provider_list=self.provider_list,
                                         limits=self.limits_list,
                                         requestslib_kwargs=kwargs)
        self.assertTrue(resp.status_code < 503)

    @attrib.attr('security')
    def test_malicious_json_create_flavor(self):
        """
        Check whether it is possible to kill the application by
        creating a big malicious json blob.
        """
        # create a payload with malicous json blob
        attack_string = self.create_malicious_json(900)
        headers = {"X-Auth-Token": self.client.auth_token,
                   "X-Project-Id": self.client.project_id}
        kwargs = {"headers": headers, "data": attack_string}
        resp = self.client.create_flavor(flavor_id=self.flavor_id,
                                         provider_list=self.provider_list,
                                         limits=self.limits_list,
                                         requestslib_kwargs=kwargs)
        self.assertTrue(resp.status_code < 503)

    @attrib.attr('security')
    def test_malicious_json_utf_8_create_flavor(self):
        """
        Check whether it is possible to kill the application by
        creating a big malicious json blob with utf-8 encoding.
        """
        # create a payload with malicious json blob
        attack_string = self.create_malicious_json(800)
        headers = {"X-Auth-Token": self.client.auth_token,
                   "X-Project-Id": self.client.project_id}
        kwargs = {"headers": headers, "data": attack_string.encode("utf-8")}
        resp = self.client.create_flavor(flavor_id=self.flavor_id,
                                         provider_list=self.provider_list,
                                         limits=self.limits_list,
                                         requestslib_kwargs=kwargs)
        self.assertTrue(resp.status_code < 503)

    @attrib.attr('security')
    def test_create_flavor_with_big_project_id(self):
        """
        Check whether it is possible to kill the application by
        creating service with big X-Project-Id header.
        """
        failed_count = 0
        for k in range(2500, 8000, 500):
            self.reset_defaults()
            headers = {"X-Auth-Token": self.client.auth_token,
                       "X-Project-Id": "1"*k,
                       "Content-Type": "application/json"}
            kwargs = {"headers": headers}
            self.flavor_id = str(uuid.uuid1())
            resp = self.client.create_flavor(flavor_id=self.flavor_id,
                                             provider_list=self.provider_list,
                                             limits=self.limits_list,
                                             requestslib_kwargs=kwargs)
            
            #self.assertTrue(resp.status_code < 503)
            if (resp.status_code == 503):
                failed_count += 1
            resp = self.client.list_services(requestslib_kwargs=kwargs)
            if (resp.status_code == 503):
                failed_count += 1
            self.assertTrue(failed_count <= 3)
            #self.assertTrue(resp.status_code < 503)

    @attrib.attr('security')
    def test_malicious_json_utf_16_create_flavor(self):
        """
        Check whether it is possible to kill the application by
        creating a big malicious json blob with utf-16 encoding.
        """
        # create a payload with malicous json blob
        attack_string = self.create_malicious_json(400)
        headers = {"X-Auth-Token": self.client.auth_token,
                   "X-Project-Id": self.client.project_id}
        kwargs = {"headers": headers, "data": attack_string.encode("utf-16")}
        resp = self.client.create_flavor(flavor_id=self.flavor_id,
                                         provider_list=self.provider_list,
                                         limits=self.limits_list,
                                         requestslib_kwargs=kwargs)
        self.assertTrue(resp.status_code < 503)

    @attrib.attr('security')
    def test_malicious_json_gzip_create_flavor(self):
        """
        Check whether it is possible to kill the application by
        creating a big malicious json blob with gzip.
        """
        # create a payload with malicous json blob
        attack_string = self.create_malicious_json(2500)
        headers = {"X-Auth-Token": self.client.auth_token,
                   "X-Project-Id": self.client.project_id,
                   "Content-Encoding": "gzip"}
        kwargs = {"headers": headers, "data": self.data_zip(attack_string)}
        resp = self.client.create_flavor(flavor_id=self.flavor_id,
                                         provider_list=self.provider_list,
                                         limits=self.limits_list,
                                         requestslib_kwargs=kwargs)
        self.assertTrue(resp.status_code < 503)

    @attrib.attr('security')
    def test_dos_create_flavor_provider_list(self):
        """
        Check whether it is possible to kill the application by
        creating a flavor with huge list of providers.
        """
        # create a huge list of domain
        self.reset_defaults()
        for k in range(1, 30000):
            self.provider_list.append({"provider": "%s" % k,
                                       "links": [{"href": "www.watermelon.com",
                                          "rel": "provider_url"}]})

        # send MAX_ATTEMPTS requests
        for k in range(1, self.MAX_ATTEMPTS):
            self.flavor_id = str(uuid.uuid1())
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
            self.flavor_id = str(uuid.uuid1())
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

        # send MAX_ATTEMPTS requests
        for k in range(1, self.MAX_ATTEMPTS):
            self.flavor_id = str(uuid.uuid1())
            self.check_one_request()

    @attrib.attr('security')
    def test_dos_list_flavors_huge_junk(self):
        """
        Check whether it is possible to kill the application by
        listing all flavors with a huge junk parameter
        """
        # create a huge list of junk
        attack_string = "1" * 3500
        params = {"junk": attack_string}
        resp = self.client.list_flavors(param=params)
        self.assertTrue(resp.status_code < 503)

    def tearDown(self):
        self.client.delete_flavor(flavor_id=self.flavor_id)
        super(TestDOSCreateFlavor, self).tearDown()
