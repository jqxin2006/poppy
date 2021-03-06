# -*- coding: utf-8 -*-
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
import mock

from poppy.provider.mock import services
from poppy.transport.pecan.models.request import service
from tests.unit import base


@ddt.ddt
class MockProviderServicesTest(base.TestCase):

    @mock.patch('poppy.provider.mock.driver.CDNProvider')
    def setUp(self, mock_driver):
        super(MockProviderServicesTest, self).setUp()
        self.driver = mock_driver()
        self.test_provider_service_id = uuid.uuid1()
        self.sc = services.ServiceController(self.driver)

    @ddt.file_data('data_service.json')
    def test_update(self, service_json):
        service_obj = service.load_from_json(service_json)
        service_old = service_obj
        response = self.sc.update(self.test_provider_service_id, service_old,
                                  service_obj)
        self.assertTrue(response is not None)

    def test_delete(self):
        response = self.sc.delete(self.test_provider_service_id)
        self.assertTrue(response is not None)

    def test_get(self):
        response = self.sc.get("mock_name")
        self.assertTrue(response is not None)

    def test_purge(self):
        response = self.sc.purge("mock_name")
        self.assertTrue(response is not None)

    @ddt.file_data('data_service.json')
    def test_create(self, service_json):
        service_obj = service.load_from_json(service_json)
        response = self.sc.create(service_obj)
        self.assertTrue(response is not None)

    @ddt.data("my_mock_service.com", u'www.düsseldorf-Lörick.com')
    def test__map_service_name(self, service_name):
        self.assertTrue(self.sc._map_service_name(service_name),
                        service_name)

    def test_current_customer(self):
        self.assertTrue(self.sc.current_customer is None)
