# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"). You may
# not use this file except in compliance with the License. A copy of the
# License is located at
#
# 	 http://aws.amazon.com/apache2.0/
#
# or in the "license" file accompanying this file. This file is distributed
# on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
# express or implied. See the License for the specific language governing
# permissions and limitations under the License.

"""Integration tests for the WAFv2 IPSet resource"""

import time
import pytest

from acktest.k8s import condition
from acktest.k8s import resource as k8s
from acktest.resources import random_suffix_name
from e2e import service_marker, CRD_GROUP, CRD_VERSION, load_wafv2_resource
from e2e.replacement_values import REPLACEMENT_VALUES
from e2e import ip_set

IP_SET_RESOURCE_PLURAL = "ipsets"

CREATE_WAIT_SECONDS = 10
MODIFY_WAIT_SECONDS = 10
DELETE_WAIT_SECONDS = 10


@pytest.fixture(scope="module")
def simple_ip_set():
    ip_set_name = random_suffix_name("my-simple-ip-set", 24)

    replacements = REPLACEMENT_VALUES.copy()
    replacements["IP_SET_NAME"] = ip_set_name

    resource_data = load_wafv2_resource(
        "ip_set_simple",
        additional_replacements=replacements,
    )

    ref = k8s.CustomResourceReference(
        CRD_GROUP,
        CRD_VERSION,
        IP_SET_RESOURCE_PLURAL,
        ip_set_name,
        namespace="default",
    )
    k8s.create_custom_resource(ref, resource_data)
    cr = k8s.wait_resource_consumed_by_controller(ref)

    assert cr is not None
    assert k8s.get_resource_exists(ref)

    yield (ref, cr)

    try:
        _, deleted = k8s.delete_custom_resource(ref, DELETE_WAIT_SECONDS)
        assert deleted
    except:
        pass


@service_marker
@pytest.mark.canary
class TestIPSet:
    def test_crud(self, simple_ip_set):
        ref, _ = simple_ip_set

        time.sleep(CREATE_WAIT_SECONDS)
        condition.assert_synced(ref)

        cr = k8s.get_resource(ref)

        assert "spec" in cr
        assert "name" in cr["spec"]
        ip_set_name = cr["spec"]["name"]

        assert "status" in cr
        assert "id" in cr["status"]
        ip_set_id = cr["status"]["id"]

        latest = ip_set.get(ip_set_name, ip_set_id)
        assert latest is not None
        assert "Addresses" in latest
        assert "Description" in latest
        addresses = latest["Addresses"]
        description = latest["Description"]
        assert len(addresses) == 2
        assert description == "initial description"

        # update the CR
        updates = {
            "spec": {
                "addresses": [addresses[0], addresses[1], "192.0.0.0/16"],
                "description": "updated description",
            },
        }
        k8s.patch_custom_resource(ref, updates)
        time.sleep(MODIFY_WAIT_SECONDS)

        latest = ip_set.get(ip_set_name, ip_set_id)
        assert latest is not None
        assert "Addresses" in latest
        assert "Description" in latest
        addresses = latest["Addresses"]
        description = latest["Description"]
        assert len(addresses) == 3
        assert description == "updated description"

        # delete the CR
        _, deleted = k8s.delete_custom_resource(ref, DELETE_WAIT_SECONDS)
        assert deleted
        ip_set.wait_until_deleted(ip_set_name, ip_set_id)
