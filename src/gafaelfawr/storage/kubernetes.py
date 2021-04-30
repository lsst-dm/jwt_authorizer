"""Kubernetes storage layer for Gafaelfawr."""

from __future__ import annotations

import os
from base64 import b64encode
from enum import Enum
from functools import wraps
from typing import Any, Callable, List, Optional, TypeVar, cast

import kubernetes
from kubernetes.client import ApiException, V1ObjectMeta, V1Secret

from gafaelfawr.constants import KUBERNETES_TOKEN_TYPE_LABEL
from gafaelfawr.exceptions import KubernetesError
from gafaelfawr.models.token import Token

F = TypeVar("F", bound=Callable[..., Any])

__all__ = ["KubernetesStorage"]


class SecretType(Enum):
    """Types of managed secrets."""

    service = "service"


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

    def __init__(self) -> None:
        if "KUBERNETES_PORT" in os.environ:
            kubernetes.config.load_incluster_config()
        else:
            kubernetes.config.load_kube_config()
        self._api = kubernetes.client.CoreV1Api()

    @_convert_exception
    def create_secret(
        self, name: str, namespace: str, secret_type: SecretType, token: Token
    ) -> None:
        """Create a Kubernetes secret from a token.

        The token will always be stored in the data field ``token``.

        Parameters
        ----------
        name : `str`
            Name of secret to create.
        namespace : `str`
            Namespace in which to create the secret.
        secret_type : `SecretType`
            Type of token stored in the secret.
        token : `gafaelfawr.models.token.Token`
            The token to store.
        """
        secret = V1Secret(
            api_version="v1",
            data={"token": self._encode_token(token)},
            metadata=V1ObjectMeta(
                labels={KUBERNETES_TOKEN_TYPE_LABEL: secret_type.value},
                name=name,
                namespace=namespace,
            ),
            type="Opaque",
        )
        self._api.create_namespaced_secret(namespace, secret)

    @_convert_exception
    def delete_secret(
        self, name: str, namespace: str, secret_type: SecretType
    ) -> None:
        """Delete a Gafaelfawr-managed Kubernetes secret.

        Parameters
        ----------
        name : `str`
            Name of secret to create.
        namespace : `str`
            Namespace in which to create the secret.
        secret_type : `SecretType`
            Type of token stored in the secret.
        """
        if not self.get_secret(name, namespace, secret_type):
            return
        self._api.delete_namespaced_secret(name, namespace)

    @_convert_exception
    def get_secret(
        self, name: str, namespace: str, secret_type: SecretType
    ) -> Optional[V1Secret]:
        """Retrieve an existing Gafaelfawr-managed secret.

        Verifies that it has the correct annotations as a sanity check.

        Parameters
        ----------
        name : `str`
            Name of secret to create.
        namespace : `str`
            Namespace in which to create the secret.
        secret_type : `SecretType`
            Type of token stored in the secret.

        Returns
        -------
        secret : `kubernetes.client.V1Secret` or `None`
            The Kubernetes secret, or `None` if that secret does not exist.
        """
        try:
            secret = self._api.read_namespaced_secret(name, namespace)
        except ApiException as e:
            if e.status == 404:
                return None
            raise

        # Check the label to ensure this is one of ours.
        if KUBERNETES_TOKEN_TYPE_LABEL not in secret.metadata.labels:
            msg = f"Secret {namespace}/{name} exists but has incorrect label"
            raise KubernetesError(msg)
        label = secret.metadata.labels[KUBERNETES_TOKEN_TYPE_LABEL]
        if label != secret_type.value:
            msg = f"Secret {namespace}/{name} is of type {label}, not service"
            raise KubernetesError(msg)

        return secret

    @_convert_exception
    def list_secrets(self, secret_type: SecretType) -> List[V1Secret]:
        """Return a list of all existing secrets of a given type.

        Parameters
        ----------
        secret_type : `SecretType`
            Type of token stored in the secret.

        Returns
        -------
        secrets : List[`kubernetes.client.V1Secret`]
            The Kubernetes secrets.
        """
        secret_list = self._api.list_secret_for_all_namespaces(
            label_selector=f"{KUBERNETES_TOKEN_TYPE_LABEL}={secret_type.value}"
        )
        return secret_list.items

    @_convert_exception
    def patch_secret(self, name: str, namespace: str, token: Token) -> None:
        """Replace the token in a secret.

        Parameters
        ----------
        name : `str`
            Name of secret to create.
        namespace : `str`
            Namespace in which to create the secret.
        token : `gafaelfawr.models.token.Token`
            The token to store.
        """
        patch = [
            {
                "op": "replace",
                "path": "/data/token",
                "value": self._encode_token(token),
            }
        ]
        self._api.patch_namespaced_secret(name, namespace, patch)

    @staticmethod
    def _encode_token(token: Token) -> str:
        """Encode a token in base64."""
        return b64encode(str(token).encode()).decode()
