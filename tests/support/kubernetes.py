"""Mock Kubernetes API for testing."""

from __future__ import annotations

import copy
import uuid
from typing import TYPE_CHECKING
from unittest.mock import Mock

import kubernetes
from kubernetes.client import ApiException, V1Secret

if TYPE_CHECKING:
    from typing import Any, Callable, Dict, List, Optional

__all__ = ["MockKubernetesApi", "assert_kubernetes_objects_are"]


def assert_kubernetes_objects_are(
    mock_kubernetes: MockKubernetesApi, kind: str, expected: List[Any]
) -> None:
    """Assert that Kubernetes contains only the specified models."""
    seen = mock_kubernetes.get_all_objects_for_test(kind)
    expected_sorted = sorted(
        expected, key=lambda o: (o.metadata.namespace, o.kind, o.metadata.name)
    )
    assert seen == expected_sorted


class MockKubernetesApi(Mock):
    """Mock Kubernetes API for testing.

    This object simulates (with almost everything left out) the
    `kubernetes.client.CoreV1Api` and `kubernetes.client.CustomObjectApi`
    client objects while keeping simple internal state.  It is intended to be
    used as a mock inside tests.

    Methods ending with ``_for_test`` are outside of the API and are intended
    for use by the test suite.
    """

    def __init__(self) -> None:
        super().__init__(spec=kubernetes.client.CoreV1Api)
        self.error_callback: Optional[Callable[..., None]] = None
        self.objects: Dict[str, Dict[str, Dict[str, Any]]] = {}

    def get_all_objects_for_test(self, kind: str) -> List[Any]:
        """Return all objects of a given kind sorted by namespace and name."""
        results = []
        for namespace in sorted(self.objects.keys()):
            if kind not in self.objects[namespace]:
                continue
            for name in sorted(self.objects[namespace][kind].keys()):
                results.append(self.objects[namespace][kind][name])
        return results

    def _maybe_error(self, method: str, *args: Any) -> None:
        """Helper function to avoid using class method call syntax."""
        if self.error_callback:
            callback = self.error_callback
            callback(method, *args)

    # CUSTOM OBJECT API

    def create_namespaced_custom_object(
        self,
        group: str,
        version: str,
        namespace: str,
        plural: str,
        body: Dict[str, Any],
    ) -> None:
        self._maybe_error(
            "create_namespaced_custom_object",
            group,
            version,
            namespace,
            plural,
            body,
        )
        assert group == "gafaelfawr.lsst.io"
        assert version == "v1alpha1"
        assert plural == "gafaelfawrservicetokens"
        assert body["kind"] == "GafaelfawrServiceToken"
        assert namespace == body["metadata"]["namespace"]
        name = body["metadata"]["name"]
        obj = copy.deepcopy(body)
        obj["metadata"]["uid"] = uuid.uuid4()
        if namespace not in self.objects:
            self.objects[namespace] = {}
        if body["kind"] not in self.objects[namespace]:
            self.objects[namespace][body["kind"]] = {}
        if name in self.objects[namespace][body["kind"]]:
            raise ApiException(status=500, reason=f"{namespace}/{name} exists")
        self.objects[namespace][body["kind"]][name] = obj

    def get_namespaced_custom_object(
        self,
        group: str,
        version: str,
        namespace: str,
        plural: str,
        name: str,
    ) -> Dict[str, Any]:
        assert group == "gafaelfawr.lsst.io"
        assert version == "v1alpha1"
        assert plural == "gafaelfawrservicetokens"
        if namespace not in self.objects:
            reason = f"{namespace}/{name} not found"
            raise ApiException(status=404, reason=reason)
        kind = "GafaelfawrServiceToken"
        if name not in self.objects[namespace].get(kind, {}):
            reason = f"{namespace}/{name} not found"
            raise ApiException(status=404, reason=reason)
        return self.objects[namespace][kind][name]

    def list_cluster_custom_object(
        self, group: str, version: str, plural: str
    ) -> List[Dict[str, Any]]:
        self._maybe_error("list_cluster_custom_object", group, version, plural)
        assert group == "gafaelfawr.lsst.io"
        assert version == "v1alpha1"
        if plural == "gafaelfawrservicetokens":
            kind = "GafaelfawrServiceToken"
        else:
            assert False, f"unknown object plural {plural}"
        results = []
        for namespace in self.objects.keys():
            for name in self.objects[namespace][kind].keys():
                results.append(self.objects[namespace][kind][name])
        return results

    def patch_namespaced_custom_object_status(
        self,
        group: str,
        version: str,
        namespace: str,
        plural: str,
        name: str,
        body: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        assert group == "gafaelfawr.lsst.io"
        assert version == "v1alpha1"
        assert plural == "gafaelfawrservicetokens"
        if namespace not in self.objects:
            reason = f"{namespace}/{name} not found"
            raise ApiException(status=404, reason=reason)
        kind = "GafaelfawrServiceToken"
        if name not in self.objects[namespace].get(kind, {}):
            reason = f"{namespace}/{name} not found"
            raise ApiException(status=404, reason=reason)
        assert len(body) == 1
        patch = body[0]
        assert patch["op"] == "replace"
        assert patch["path"] == "/status/conditions"
        obj = copy.deepcopy(self.objects[namespace][kind][name])
        if "status" not in obj:
            obj["status"] = {}
        obj["status"]["conditions"] = patch["value"]
        self.objects[namespace][kind][name] = obj
        return obj

    # SECRETS API

    def create_namespaced_secret(
        self, namespace: str, secret: V1Secret
    ) -> None:
        self._maybe_error("create_namespaced_secret", namespace, secret)
        assert namespace == secret.metadata.namespace
        name = secret.metadata.name
        if namespace not in self.objects:
            self.objects[namespace] = {}
        if "Secret" not in self.objects[namespace]:
            self.objects[namespace]["Secret"] = {}
        if name in self.objects[namespace]["Secret"]:
            raise ApiException(status=500, reason=f"{namespace}/{name} exists")
        self.objects[namespace]["Secret"][name] = secret

    def read_namespaced_secret(self, name: str, namespace: str) -> V1Secret:
        self._maybe_error("read_namespaced_secret", name, namespace)
        if namespace not in self.objects:
            reason = f"{namespace}/{name} not found"
            raise ApiException(status=404, reason=reason)
        if name not in self.objects[namespace].get("Secret", {}):
            reason = f"{namespace}/{name} not found"
            raise ApiException(status=404, reason=reason)
        return self.objects[namespace]["Secret"][name]

    def replace_namespaced_secret(
        self, namespace: str, secret: V1Secret
    ) -> None:
        self._maybe_error("replace_namespaced_secret", namespace, secret)
        name = secret.metadata.name
        if namespace not in self.objects:
            reason = f"{namespace}/{name} not found"
            raise ApiException(status=404, reason=reason)
        if name not in self.objects[namespace].get("Secret", {}):
            reason = f"{namespace}/{name} not found"
            raise ApiException(status=404, reason=reason)
        self.objects[namespace]["Secret"][name] = secret
