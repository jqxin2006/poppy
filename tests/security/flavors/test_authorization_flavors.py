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
import json
from nose.plugins import attrib
from tests.api import providers
from tests.api.utils.models.requests import CreateFlavor


@ddt.ddt
class TestAuthorizationFlavor(providers.TestProviderBase):

    """Security Tests for Authorization vulnerablities
        for Flavor Functions."""

    def setUp(self):
        """
        Setup for the tests
        """
        super(TestAuthorizationFlavor, self).setUp()
        self.reset_defaults()

    def reset_defaults(self):
        """
        Reset provider_list, limits
        and flavor_id to its default value.
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
        Check the response of one request to see whether one request can
        kill the application.
        """
        resp = self.client.create_flavor(flavor_id=self.flavor_id,
                                         provider_list=self.provider_list,
                                         limits=self.limits_list)
        # delete the flavor
        self.assertTrue(resp.status_code < 503)

        self.client.delete_flavor(flavor_id=self.flavor_id)

    @attrib.attr('security')
    def test_authorization_create_flavor_no_token(self):
        """
        Check whether it is possible to create a flavor without a
        valid token.
        """
        # create header without token
        headers = {"X-Auth-Token": ""}
        kwargs = {"headers": headers}
        resp = self.client.create_flavor(flavor_id=self.flavor_id,
                                         provider_list=self.provider_list,
                                         limits=self.limits_list,
                                         requestslib_kwargs=kwargs)
        self.assertTrue(resp.status_code == 401)

    @attrib.attr('security')
    def test_authorization_create_flavor_other_user_token(self):
        """
        Check whether it is possible to create a flavor with a
        valid token from another user.
        """
        # replace the token with another user's token
        headers = {"X-Auth-Token": self.alt_user_client.auth_token,
                   "X-Project-Id": self.client.project_id}
        kwargs = {"headers": headers}

        resp = self.client.create_flavor(flavor_id=self.flavor_id,
                                         provider_list=self.provider_list,
                                         limits=self.limits_list,
                                         requestslib_kwargs=kwargs)
        self.assertTrue(resp.status_code == 401)

    @attrib.attr('security2')
    def test_authorization_list_flavor_other_user_token(self):
        """
        Check whether it is possible to list flavors with a
        valid token from another user.
        """
        # replace the token with another user's token
        headers = {"X-Auth-Token": self.alt_user_client.auth_token,
                   "X-Project-Id": self.client.project_id}
        kwargs = {"headers": headers}

        resp = self.client.list_flavors(requestslib_kwargs=kwargs)
        print '>>>> resp=' + str(resp)
        self.assertTrue(resp.status_code == 401)

    @attrib.attr('security2')
    def test_authorization_list_flavor_no_token(self):
        """
        Check whether it is possible to list all flavors with no token.
        """
        # create header without token
        headers = {"X-Auth-Token": ""}
        kwargs = {"headers": headers}
        resp = self.client.list_flavors(requestslib_kwargs=kwargs)
        self.assertTrue(resp.status_code == 401)

    @attrib.attr('security')
    def test_authorization_get_flavor_other_user_token(self):
        """
        Check whether it is possible to get one flavor with a
        valid token from another user.
        """
        # replace the token with another user's token
        headers = {"X-Auth-Token": self.alt_user_client.auth_token,
                   "X-Project-Id": self.client.project_id}
        kwargs = {"headers": headers}

        self.reset_defaults()
        resp = self.client.create_flavor(flavor_id=self.flavor_id,
                                         provider_list=self.provider_list,
                                         limits=self.limits_list)
        self.assertTrue(resp.status_code == 202)
        
        resp = self.client.get_flavor(flavor_id=self.flavor_id)
        self.assertTrue(resp.status_code == 200)

        resp = self.client.get_flavor(flavor_id=self.flavor_id,
                                       requestslib_kwargs=kwargs)
        self.assertTrue(resp.status_code == 401)

        self.client.delete_flavor(flavor_id=self.flavor_id)

    @attrib.attr('security')
    def test_authorization_get_flavor_no_token(self):
        """
        Check whether it is possible to get a flavor with no token.
        """
        # create header without token
        headers = {"X-Auth-Token": ""}
        kwargs = {"headers": headers}
        self.reset_defaults()

        resp = self.client.create_flavor(flavor_id=self.flavor_id,
                                         provider_list=self.provider_list,
                                         limits=self.limits_list)
        self.assertTrue(resp.status_code == 202)
        
        resp = self.client.get_flavor(flavor_id=self.flavor_id)
        self.assertTrue(resp.status_code == 200)

        resp = self.client.get_flavor(flavor_id=self.flavor_id,
                                       requestslib_kwargs=kwargs)
        self.assertTrue(resp.status_code == 401)
        
        self.client.delete_flavor(flavor_id=self.flavor_id)

    @attrib.attr('security')
    def test_authorization_delete_flavor_no_token(self):
        """
        Check whether it is possible to delete a flavor with no token.
        """
        # create header without token
        headers = {"X-Auth-Token": ""}
        kwargs = {"headers": headers}
        self.reset_defaults()

        resp = self.client.create_flavor(flavor_id=self.flavor_id,
                                         provider_list=self.provider_list,
                                         limits=self.limits_list)
        self.assertTrue(resp.status_code == 202)
        
        resp = self.client.get_flavor(flavor_id=self.flavor_id)
        self.assertTrue(resp.status_code == 200)

        resp = self.client.delete_flavor(flavor_id=self.flavor_id,
                                          requestslib_kwargs=kwargs)
        self.assertTrue(resp.status_code == 401)
        
        self.client.delete_flavor(flavor_id=self.flavor_id)

    @attrib.attr('security')
    def test_authorization_delete_flavor_other_user_token(self):
        """
        Check whether it is possible to delete one flavor with a
        valid token from another user.
        """
        # replace the token with another user's token
        headers = {"X-Auth-Token": self.alt_user_client.auth_token,
                   "X-Project-Id": self.client.project_id}
        kwargs = {"headers": headers}

        self.reset_defaults()
        resp = self.client.create_flavor(flavor_id=self.flavor_id,
                                         provider_list=self.provider_list,
                                         limits=self.limits_list)
        self.assertTrue(resp.status_code == 202)
        
        resp = self.client.get_flavor(flavor_id=self.flavor_id)
        self.assertTrue(resp.status_code == 200)

        resp = self.client.delete_flavor(flavor_id=self.flavor_id,
                                          requestslib_kwargs=kwargs)
        self.assertTrue(resp.status_code == 401)

        self.client.delete_flavor(flavor_id=self.flavor_id)

    @attrib.attr('security')
    def test_authorization_delete_flavor_invalid_token(self):
        """
        Check whether it is possible to delete a flavor with invalid token.
        """
        # create header without token
        headers = {"X-Auth-Token": "1"*1000}
        kwargs = {"headers": headers}
        self.reset_defaults()

        resp = self.client.create_flavor(flavor_id=self.flavor_id,
                                         provider_list=self.provider_list,
                                         limits=self.limits_list)
        self.assertTrue(resp.status_code == 202)
        
        resp = self.client.get_flavor(flavor_id=self.flavor_id)
        self.assertTrue(resp.status_code == 200)

        resp = self.client.delete_flavor(flavor_id=self.flavor_id,
                                          requestslib_kwargs=kwargs)
        self.assertTrue(resp.status_code == 401)

        self.client.delete_flavor(flavor_id=self.flavor_id)

    @attrib.attr('security')
    def test_authorization_get_flavor_invalid_token(self):
        """
        Check whether it is possible to get a flavor with invalid token.
        """
        # create header without token
        headers = {"X-Auth-Token": "1"*1000}
        kwargs = {"headers": headers}
        self.reset_defaults()

        resp = self.client.create_flavor(flavor_id=self.flavor_id,
                                         provider_list=self.provider_list,
                                         limits=self.limits_list)
        self.assertTrue(resp.status_code == 202)
        
        resp = self.client.get_flavor(flavor_id=self.flavor_id)
        self.assertTrue(resp.status_code == 200)

        resp = self.client.get_flavor(flavor_id=self.flavor_id,
                                       requestslib_kwargs=kwargs)
        self.assertTrue(resp.status_code == 401)
        
        self.client.delete_flavor(flavor_id=self.flavor_id)

    @attrib.attr('security2')
    def test_authorization_list_flavor_invalid_token(self):
        """
        Check whether it is possible to list all flavor with invlid token.
        """
        # create header without token
        headers = {"X-Auth-Token": "1"*1000}
        kwargs = {"headers": headers}
        resp = self.client.list_flavors(requestslib_kwargs=kwargs)
        self.assertTrue(resp.status_code == 401)

    @attrib.attr('security')
    def test_authorization_create_flavor_invalid_token(self):
        """
        Check whether it is possible to create a flavor with an invalid token.
        """
        # create header without token
        headers = {"X-Auth-Token": "1"*1000}
        kwargs = {"headers": headers}
        resp = self.client.create_flavor(flavor_id=self.flavor_id,
                                         provider_list=self.provider_list,
                                         limits=self.limits_list)
        self.assertTrue(resp.status_code == 401)

    @attrib.attr('security')
    def test_authorization_patch_flavor_invalid_token(self):
        """
        Check whether it is possible to create a flavor with an invalid token.
        """
        # create header without token
        headers = {"X-Auth-Token": "1"*1000}
        kwargs = {"headers": headers}
        resp = self.client.create_flavor(flavor_id=self.flavor_id,
                                         provider_list=self.provider_list,
                                         limits=self.limits_list)
        self.assertTrue(resp.status_code == 202)
        
        request_body = json.loads(
            CreateFlavor(flavor_id=self.flavor_id,
                                         provider_list=self.provider_list,
                                         limits=self.limits_list))
        resp = self.client.get_flavor(flavor_id=self.flavor_id)
        self.assertTrue(resp.status_code == 200)
        
        resp = self.client.patch_flavor(flavor_id=self.flavor_id,
                                         request_body=request_body,
                                         requestslib_kwargs=kwargs)
        self.assertTrue(resp.status_code == 401)
        
        self.client.delete_flavor(flavor_id=self.flavor_id)

    def tearDown(self):
        self.client.delete_flavor(flavor_id=self.flavor_id)
        super(TestAuthorizationFlavor, self).tearDown()
