"""Manage Kubernetes secrets."""

from __future__ import annotations

from base64 import b64decode
from typing import TYPE_CHECKING

from gafaelfawr.config import KubernetesConfig
from gafaelfawr.exceptions import (
    KubernetesError,
    PermissionDeniedError,
    ValidationError,
)
from gafaelfawr.models.token import (
    AdminTokenRequest,
    Token,
    TokenData,
    TokenType,
)
from gafaelfawr.storage.kubernetes import StatusReason

if TYPE_CHECKING:
    from typing import List

    from kubernetes.client import V1Secret
    from structlog.stdlib import BoundLogger

    from gafaelfawr.services.token import TokenService
    from gafaelfawr.storage.kubernetes import (
        GafaelfawrServiceToken,
        KubernetesStorage,
    )

__all__ = ["KubernetesService"]


class KubernetesService:
    """Manage Gafaelfawr-related Kubernetes secrets.

    Gafaelfawr supports automatic creation and management of service tokens
    for other Kubernetes services running in the same cluster.  This service
    ensures that all the configured service tokens exist as secrets in the
    appropriate namespace, and that no other secrets exist that are
    labelled with gafaelfawr.lsst.io/token-type=service.
    """

    def __init__(
        self,
        config: KubernetesConfig,
        token_service: TokenService,
        storage: KubernetesStorage,
        logger: BoundLogger,
    ) -> None:
        self._config = config
        self._token_service = token_service
        self._storage = storage
        self._logger = logger

    async def update_service_secrets(self) -> None:
        """Ensure all GafaelfawrServiceToken secrets exist and are valid.

        Raises
        ------
        gafaelfawr.exceptions.KubernetesError
            On a fatal error that prevents all further processing.  Exceptions
            processing single secrets will be logged but this method will
            attempt to continue processing the remaining secrets.
        """
        try:
            service_tokens = self._storage.list_service_tokens()
        except KubernetesError as e:
            # Report this error even though it's unrecoverable and we're
            # re-raising it, since our caller doesn't have the context that
            # the failure was due to listing GafaelfawrServiceToken objects.
            msg = "Unable to list GafaelfawrServiceToken objects"
            self._logger.error(msg, error=str(e))
            raise

        # Process each GafaelfawrServiceToken and create or update its
        # corresponding secret if needed.
        for service_token in service_tokens:
            await self._update_service_secret(service_token)

    async def _check_service_secret(
        self, parent: GafaelfawrServiceToken, secret: V1Secret
    ) -> bool:
        """Check if a secret needs to be updated."""
        okay = (
            secret.metadata.annotations == parent.annotations
            and secret.metadata.labels == parent.labels
            and "token" in secret.data
        )
        if not okay:
            return False

        # Check the token contained in the secret.
        try:
            token_str = b64decode(secret.data["token"]).decode()
            token = Token.from_str(token_str)
            okay = await self._check_service_token(token, parent)
        except Exception:
            okay = False

        return okay

    async def _check_service_token(
        self, token: Token, parent: GafaelfawrServiceToken
    ) -> bool:
        """Check whether a service token matches its configuration."""
        token_data = await self._token_service.get_data(token)
        if not token_data:
            return False
        if token_data.username != parent.service:
            return False
        if sorted(token_data.scopes) != sorted(parent.scopes):
            return False
        return True

    async def _create_service_token(
        self, service: str, scopes: List[str]
    ) -> Token:
        request = AdminTokenRequest(
            username=service,
            token_type=TokenType.service,
            scopes=scopes,
        )
        return await self._token_service.create_token_from_admin_request(
            request, TokenData.internal_token(), ip_address=None
        )

    async def _update_service_secret(
        self, parent: GafaelfawrServiceToken
    ) -> None:
        """Verify that a service secret is still correct.

        This checks that the contained service token is still valid and the
        secret metadata matches the GafaelfawrServiceToken metadata and
        replaces it with a new one if not.
        """
        name = parent.secret_name
        namespace = parent.secret_namespace
        try:
            secret = self._storage.get_service_secret(parent)
        except KubernetesError as e:
            msg = f"Updating {namespace}/{name} failed"
            self._logger.error(msg, error=str(e))
            return
        if secret and await self._check_service_secret(parent, secret):
            return

        # Something is either different or invalid.  Replace the secret.
        try:
            token = await self._create_service_secret(parent)
            if secret:
                self._storage.replace_service_secret(parent, token)
            else:
                self._storage.create_service_secret(parent, token)
        except (PermissionDeniedError, ValidationError) as e:
            msg = f"Updating {namespace}/{name} failed"
            self._logger.error(msg, error=str(e))
            try:
                self._storage.update_service_token_status(
                    parent,
                    reason=StatusReason.Failed,
                    message=str(e),
                    success=False,
                )
            except KubernetesError as e:
                msg = f"Updating status of {namespace}/{name} failed"
                self._logger.error(msg, error=str(e))
        except KubernetesError as e:
            msg = f"Updating {namespace}/{name} failed"
            self._logger.error(msg, error=str(e))
        else:
            self._logger.info(
                f"Updated {namespace}/{name} secret",
                service=parent.service,
                scopes=parent.scopes,
            )
