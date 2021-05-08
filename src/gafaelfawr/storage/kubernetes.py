"""Kubernetes storage layer for Gafaelfawr."""

from __future__ import annotations

import os
from base64 import b64encode
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from functools import wraps
from typing import TYPE_CHECKING, Any, Callable, TypeVar, cast

import kubernetes
from kubernetes.client import (
    ApiException,
    V1ObjectMeta,
    V1OwnerReference,
    V1Secret,
)

from gafaelfawr.exceptions import KubernetesError
from gafaelfawr.models.token import Token

if TYPE_CHECKING:
    from typing import Dict, List, Optional

    from structlog.stdlib import BoundLogger

F = TypeVar("F", bound=Callable[..., Any])

__all__ = ["KubernetesStorage"]


@dataclass
class GafaelfawrServiceToken:
    """The key data from a GafaelfawrServiceToken Kubernetes object."""

    name: str
    """The name of the GafaelfawrServiceToken object."""

    namespace: str
    """The namespace in which the GafaelfawrServiceToken object is located."""

    annotations: Dict[str, str]
    """The annotations of the GafaelfawrServiceToken object."""

    labels: Dict[str, str]
    """The labels of the GafaelfawrServiceToken object."""

    uid: str
    """The UID of the GafaelfawrServiceToken object."""

    generation: int
    """The generation of the GafaelfawrServiceToken object."""

    service: str
    """The username of the service token."""

    scopes: List[str]
    """The scopes to grant to the service token."""


class StatusReason(Enum):
    """Reason for the status update of a GafaelfawrServiceToken."""

    Created = "Created"
    Updated = "Updated"
    Failed = "Failed"


def _convert_exception(f: F) -> F:
    """Convert Kubernetes ApiException to KubernetesError."""

    @wraps(f)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        try:
            return f(*args, **kwargs)
        except ApiException as e:
            raise KubernetesError(f"Kubernetes API error: {str(e)}") from e

    return cast(F, wrapper)


class KubernetesStorage:
    """Kubernetes storage layer.

    This abstracts storage of Kubernetes objects by wrapping the underlying
    Kubernetes Python client.
    """

    def __init__(
        self,
        logger: BoundLogger,
    ) -> None:
        if "KUBERNETES_PORT" in os.environ:
            kubernetes.config.load_incluster_config()
        else:
            kubernetes.config.load_kube_config()
        self._api = kubernetes.client.CoreV1Api()
        self._custom_api = kubernetes.client.CustomObjectsApi()
        self._logger = logger

    @_convert_exception
    def create_secret_for_service_token(
        self, parent: GafaelfawrServiceToken, token: Token
    ) -> None:
        """Create a Kubernetes secret from a token.

        The token will always be stored in the data field ``token``.

        Parameters
        ----------
        parent : `GafaelfawrServiceToken`
            The parent ``GafaelfawrServiceToken`` object for the secret.
        token : `gafaelfawr.models.token.Token`
            The token to store.
        """
        secret = self._build_secret_for_service_token(parent, token)
        self._api.create_namespaced_secret(parent.namespace, secret)
        self.update_service_token_status(
            parent,
            reason=StatusReason.Created,
            message="Secret was created",
            success=True,
        )

    @_convert_exception
    def get_secret_for_service_token(
        self, parent: GafaelfawrServiceToken
    ) -> Optional[V1Secret]:
        """Retrieve the secret corresponding to a GafaelfawrServiceToken.

        Parameters
        ----------
        parent : `GafaelfawrServiceToken`
            The parent GafaelfawrServiceToken object.

        Returns
        -------
        secret : `kubernetes.client.V1Secret` or `None`
            The Kubernetes secret, or `None` if that secret does not exist.
        """
        try:
            secret = self._api.read_namespaced_secret(
                parent.name, parent.namespace
            )
        except ApiException as e:
            if e.status == 404:
                return None
            raise

        return secret

    @_convert_exception
    def list_service_tokens(self) -> List[GafaelfawrServiceToken]:
        """Return a list of all GafaelfawrServiceToken objects in the cluster.

        Returns
        -------
        objects : List[Dict[`str`, Any]]
        """
        obj_list = self._custom_api.list_cluster_custom_object(
            "gafaelfawr.lsst.io", "v1alpha1", "gafaelfawrservicetokens"
        )

        # Convert to GafaelfawrServiceToken objects.
        tokens = []
        for obj in obj_list:
            name = None
            namespace = None
            try:
                name = obj["metadata"]["name"]
                namespace = obj["metadata"]["namespace"]
                token = GafaelfawrServiceToken(
                    name=name,
                    namespace=namespace,
                    annotations=obj["metadata"].get("annotations", {}),
                    labels=obj["metdata"].get("labels", {}),
                    uid=obj["metadata"]["uid"],
                    generation=obj["metadata"]["generation"],
                    service=obj["spec"]["service"],
                    scopes=obj["spec"]["scopes"],
                )
                tokens.append(token)
            except KeyError as e:
                if name and namespace:
                    msg = (
                        f"GafaelfawrServiceToken {namespace}/{name} is"
                        f" malformed: {str(e)}"
                    )
                else:
                    msg = f"GafaelfawrServiceToken is malformed: {str(e)}"
                self._logger.warning(msg)

        return tokens

    @_convert_exception
    def replace_secret_for_service_token(
        self, parent: GafaelfawrServiceToken, token: Token
    ) -> None:
        """Replace the token in a secret.

        Parameters
        ----------
        parent : `GafaelfawrServiceToken`
            The parent ``GafaelfawrServiceToken`` object for the secret.
        token : `gafaelfawr.models.token.Token`
            The token to store.
        """
        secret = self._build_secret_for_service_token(parent, token)
        self._api.replace_namespaced_secret(parent.namespace, secret)
        self.update_service_token_status(
            parent,
            reason=StatusReason.Updated,
            message="Secret was updated",
            success=True,
        )

    @_convert_exception
    def update_service_token_status(
        self,
        service_token: GafaelfawrServiceToken,
        *,
        reason: StatusReason,
        message: str,
        success: bool,
    ) -> None:
        """Update the status field of the parent GafaelfawrServiceToken.

        Parameters
        ----------
        service_token : `GafaelfawrServiceToken`
            The service token to update.
        reason : `StatusReason`
            The reason for the current condition.
        message : `str`
            Human-readable message describing the current condition.
        success : `bool`
            Whether the GafaelfawrServiceToken was successfully processed.
        """
        now = datetime.now(tz=timezone.utc).isoformat(timespec="seconds") + "Z"
        patch = [
            {
                "op": "replace",
                "path": "/status/conditions",
                "value": [
                    {
                        "lastTransitionTime": now,
                        "message": message,
                        "observedGeneration": service_token.generation,
                        "reason": StatusReason.value,
                        "status": "True" if success else "False",
                        "type": "SecretCreated",
                    },
                ],
            },
        ]
        self._custom_api.patch_namespaced_custom_object_status(
            "gafaelfawr.lsst.io",
            "v1alpha1",
            service_token.namespace,
            "gafaelfawrservicetokens",
            service_token.name,
            patch,
        )

    def _build_secret_for_service_token(
        self, parent: GafaelfawrServiceToken, token: Token
    ) -> V1Secret:
        """Construct a new Secret object.

        Parameters
        ----------
        parent : `GafaelfawrServiceSecret`
            The parent GafaelfawrServiceSecret object.
        token : `gafaelfawr.models.token.Token`
            The Gafaelfawr token to store in the secret.
        """
        return V1Secret(
            api_version="v1",
            data={"token": self._encode_token(token)},
            metadata=V1ObjectMeta(
                name=parent.name,
                namespace=parent.namespace,
                annotations=parent.annotations,
                labels=parent.labels,
            ),
            ownerReferences=[
                V1OwnerReference(
                    api_version="gafaelfawr.lsst.io/v1alpha1",
                    block_owner_deletion=True,
                    controller=True,
                    kind="GafaelfawrServiceToken",
                    name=parent.name,
                    uid=parent.uid,
                ),
            ],
            type="Opaque",
        )

    @staticmethod
    def _encode_token(token: Token) -> str:
        """Encode a token in base64."""
        return b64encode(str(token).encode()).decode()
