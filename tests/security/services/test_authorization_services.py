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
from tests.api.utils.models.requests import CreateService


@ddt.ddt
class TestAuthorizationService(providers.TestProviderBase):

    """Security Tests for Authorization vulnerablities
        for Service Functions."""

    def setUp(self):
        """
        Setup for the tests
        """
        super(TestAuthorizationService, self).setUp()
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
    def test_authorization_create_service_no_token(self):
        """
        Check whether it is possible to create a servcie without a
        valid token.
        """
        # create header without token
        headers = {"X-Auth-Token": ""}
        kwargs = {"headers": headers}
        resp = self.client.create_service(service_name=self.service_name,
                                          domain_list=self.domain_list,
                                          origin_list=self.origin_list,
                                          caching_list=self.caching_list,
                                          flavor_id=self.flavor_id,
                                          requestslib_kwargs=kwargs)
        self.assertTrue(resp.status_code == 401)

    @attrib.attr('security')
    def test_authorization_create_service_other_user_token(self):
        """
        Check whether it is possible to create a servcie with a
        valid token from another user.
        """
        # replace the token with another user's token
        headers = {"X-Auth-Token": self.alt_user_client.auth_token,
                   "X-Project-Id": self.client.project_id}
        kwargs = {"headers": headers}

        resp = self.client.create_service(service_name=self.service_name,
                                          domain_list=self.domain_list,
                                          origin_list=self.origin_list,
                                          caching_list=self.caching_list,
                                          flavor_id=self.flavor_id,
                                          requestslib_kwargs=kwargs)
        self.assertTrue(resp.status_code == 401)

    @attrib.attr('security')
    def test_authorization_list_services_other_user_token(self):
        """
        Check whether it is possible to list services with a
        valid token from another user.
        """
        # replace the token with another user's token
        headers = {"X-Auth-Token": self.alt_user_client.auth_token,
                   "X-Project-Id": self.client.project_id}
        kwargs = {"headers": headers}

        resp = self.client.list_services(requestslib_kwargs=kwargs)
        self.assertTrue(resp.status_code == 401)

    @attrib.attr('security')
    def test_authorization_list_service_no_token(self):
        """
        Check whether it is possible to list all services with no token.
        """
        # create header without token
        headers = {"X-Auth-Token": ""}
        kwargs = {"headers": headers}
        resp = self.client.list_services(requestslib_kwargs=kwargs)
        self.assertTrue(resp.status_code == 401)

    @attrib.attr('security')
    def test_authorization_get_service_other_user_token(self):
        """
        Check whether it is possible to get one service with a
        valid token from another user.
        """
        # replace the token with another user's token
        headers = {"X-Auth-Token": self.alt_user_client.auth_token,
                   "X-Project-Id": self.client.project_id}
        kwargs = {"headers": headers}

        self.reset_defaults()
        resp = self.client.create_service(service_name=self.service_name,
                                          domain_list=self.domain_list,
                                          origin_list=self.origin_list,
                                          caching_list=self.caching_list,
                                          flavor_id=self.flavor_id)
        self.assertTrue(resp.status_code == 202)
        resp = self.client.get_service(service_name=self.service_name)
        self.assertTrue(resp.status_code == 200)

        resp = self.client.get_service(service_name=self.service_name,
                                       requestslib_kwargs=kwargs)
        self.assertTrue(resp.status_code == 401)
        self.client.delete_service(service_name=self.service_name)

    @attrib.attr('security')
    def test_authorization_get_service_no_token(self):
        """
        Check whether it is possible to get a service with no token.
        """
        # create header without token
        headers = {"X-Auth-Token": ""}
        kwargs = {"headers": headers}
        self.reset_defaults()

        resp = self.client.create_service(service_name=self.service_name,
                                          domain_list=self.domain_list,
                                          origin_list=self.origin_list,
                                          caching_list=self.caching_list,
                                          flavor_id=self.flavor_id)
        self.assertTrue(resp.status_code == 202)
        resp = self.client.get_service(service_name=self.service_name)
        self.assertTrue(resp.status_code == 200)

        resp = self.client.get_service(service_name=self.service_name,
                                       requestslib_kwargs=kwargs)
        self.assertTrue(resp.status_code == 401)
        self.client.delete_service(service_name=self.service_name)

    @attrib.attr('security')
    def test_authorization_delete_service_no_token(self):
        """
        Check whether it is possible to delete a service with no token.
        """
        # create header without token
        headers = {"X-Auth-Token": ""}
        kwargs = {"headers": headers}
        self.reset_defaults()

        resp = self.client.create_service(service_name=self.service_name,
                                          domain_list=self.domain_list,
                                          origin_list=self.origin_list,
                                          caching_list=self.caching_list,
                                          flavor_id=self.flavor_id)
        self.assertTrue(resp.status_code == 202)
        resp = self.client.get_service(service_name=self.service_name)
        self.assertTrue(resp.status_code == 200)

        resp = self.client.delete_service(service_name=self.service_name,
                                          requestslib_kwargs=kwargs)
        self.assertTrue(resp.status_code == 401)
        self.client.delete_service(service_name=self.service_name)

    @attrib.attr('security')
    def test_authorization_delete_service_other_user_token(self):
        """
        Check whether it is possible to delete one service with a
        valid token from another user.
        """
        # replace the token with another user's token
        headers = {"X-Auth-Token": self.alt_user_client.auth_token,
                   "X-Project-Id": self.client.project_id}
        kwargs = {"headers": headers}

        self.reset_defaults()
        resp = self.client.create_service(service_name=self.service_name,
                                          domain_list=self.domain_list,
                                          origin_list=self.origin_list,
                                          caching_list=self.caching_list,
                                          flavor_id=self.flavor_id)
        self.assertTrue(resp.status_code == 202)
        resp = self.client.get_service(service_name=self.service_name)
        self.assertTrue(resp.status_code == 200)

        resp = self.client.delete_service(service_name=self.service_name,
                                          requestslib_kwargs=kwargs)
        self.assertTrue(resp.status_code == 401)
        self.client.delete_service(service_name=self.service_name)

    @attrib.attr('security')
    def test_authorization_delete_service_invalid_token(self):
        """
        Check whether it is possible to delete a service with invalid token.
        """
        # create header without token
        headers = {"X-Auth-Token": "1"*1000}
        kwargs = {"headers": headers}
        self.reset_defaults()

        resp = self.client.create_service(service_name=self.service_name,
                                          domain_list=self.domain_list,
                                          origin_list=self.origin_list,
                                          caching_list=self.caching_list,
                                          flavor_id=self.flavor_id)
        self.assertTrue(resp.status_code == 202)
        resp = self.client.get_service(service_name=self.service_name)
        self.assertTrue(resp.status_code == 200)

        resp = self.client.delete_service(service_name=self.service_name,
                                          requestslib_kwargs=kwargs)
        self.assertTrue(resp.status_code == 401)

        self.client.delete_service(service_name=self.service_name)

    @attrib.attr('security')
    def test_authorization_get_service_invalid_token(self):
        """
        Check whether it is possible to get a service with invalid token.
        """
        # create header without token
        headers = {"X-Auth-Token": "1"*1000}
        kwargs = {"headers": headers}
        self.reset_defaults()

        resp = self.client.create_service(service_name=self.service_name,
                                          domain_list=self.domain_list,
                                          origin_list=self.origin_list,
                                          caching_list=self.caching_list,
                                          flavor_id=self.flavor_id)
        self.assertTrue(resp.status_code == 202)
        resp = self.client.get_service(service_name=self.service_name)
        self.assertTrue(resp.status_code == 200)

        resp = self.client.get_service(service_name=self.service_name,
                                       requestslib_kwargs=kwargs)
        self.assertTrue(resp.status_code == 401)
        self.client.delete_service(service_name=self.service_name)

    @attrib.attr('security')
    def test_authorization_list_service_invalid_token(self):
        """
        Check whether it is possible to list all services with invlid token.
        """
        # create header without token
        headers = {"X-Auth-Token": "1"*1000}
        kwargs = {"headers": headers}
        resp = self.client.list_services(requestslib_kwargs=kwargs)
        self.assertTrue(resp.status_code == 401)

    @attrib.attr('security')
    def test_authorization_create_service_invalid_token(self):
        """
        Check whether it is possible to create a servcie with an invalid token.
        """
        # create header without token
        headers = {"X-Auth-Token": "1"*1000}
        kwargs = {"headers": headers}
        resp = self.client.create_service(service_name=self.service_name,
                                          domain_list=self.domain_list,
                                          origin_list=self.origin_list,
                                          caching_list=self.caching_list,
                                          flavor_id=self.flavor_id,
                                          requestslib_kwargs=kwargs)
        self.assertTrue(resp.status_code == 401)

    @attrib.attr('security')
    def test_authorization_patch_service_invalid_token(self):
        """
        Check whether it is possible to create a servcie with an invalid token.
        """
        # create header without token
        headers = {"X-Auth-Token": "1"*1000}
        kwargs = {"headers": headers}
        resp = self.client.create_service(service_name=self.service_name,
                                          domain_list=self.domain_list,
                                          origin_list=self.origin_list,
                                          caching_list=self.caching_list,
                                          flavor_id=self.flavor_id)
        self.assertTrue(resp.status_code == 202)
        request_body = json.loads(
            CreateService(service_name=self.service_name,
                          domain_list=self.domain_list,
                          origin_list=self.origin_list,
                          caching_list=self.caching_list,
                          flavor_id=self.flavor_id)._obj_to_json())
        resp = self.client.get_service(service_name=self.service_name)
        self.assertTrue(resp.status_code == 200)
        resp = self.client.patch_service(service_name=self.service_name,
                                         request_body=request_body,
                                         requestslib_kwargs=kwargs)
        self.assertTrue(resp.status_code == 401)
        self.client.delete_service(service_name=self.service_name)

    @attrib.attr('security')
    def test_authorization_patch_service_other_user_token(self):
        """
        Check whether it is possible to patch one service with a
        valid token from another user.
        """
        # replace the token with another user's token
        headers = {"X-Auth-Token": self.alt_user_client.auth_token,
                   "X-Project-Id": self.client.project_id}
        kwargs = {"headers": headers}

        self.reset_defaults()
        resp = self.client.create_service(service_name=self.service_name,
                                          domain_list=self.domain_list,
                                          origin_list=self.origin_list,
                                          caching_list=self.caching_list,
                                          flavor_id=self.flavor_id)
        self.assertTrue(resp.status_code == 202)
        resp = self.client.get_service(service_name=self.service_name)
        self.assertTrue(resp.status_code == 200)
        request_body = json.loads(
            CreateService(service_name=self.service_name,
                          domain_list=self.domain_list,
                          origin_list=self.origin_list,
                          caching_list=self.caching_list,
                          flavor_id=self.flavor_id)._obj_to_json())

        resp = self.client.patch_service(service_name=self.service_name,
                                         request_body=request_body,
                                         requestslib_kwargs=kwargs)
        self.assertTrue(resp.status_code == 401)
        self.client.delete_service(service_name=self.service_name)

    @attrib.attr('security')
    def test_authorization_patch_service_no_token(self):
        """
        Check whether it is possible to create a servcie with an invalid token.
        """
        # create header without token
        headers = {"X-Auth-Token": ""}
        kwargs = {"headers": headers}
        self.reset_defaults()
        resp = self.client.create_service(service_name=self.service_name,
                                          domain_list=self.domain_list,
                                          origin_list=self.origin_list,
                                          caching_list=self.caching_list,
                                          flavor_id=self.flavor_id)
        self.assertTrue(resp.status_code == 202)
        request_body = json.loads(
            CreateService(service_name=self.service_name,
                          domain_list=self.domain_list,
                          origin_list=self.origin_list,
                          caching_list=self.caching_list,
                          flavor_id=self.flavor_id)._obj_to_json())
        resp = self.client.get_service(service_name=self.service_name)
        self.assertTrue(resp.status_code == 200)
        resp = self.client.patch_service(service_name=self.service_name,
                                         request_body=request_body,
                                         requestslib_kwargs=kwargs)
        self.assertTrue(resp.status_code == 401)

    def tearDown(self):
        self.client.delete_service(service_name=self.service_name)

        if self.test_config.generate_flavors:
            self.client.delete_flavor(flavor_id=self.flavor_id)

        super(TestAuthorizationService, self).tearDown()
