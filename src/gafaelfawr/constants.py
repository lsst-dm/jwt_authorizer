"""Constants for Gafaelfawr."""

ALGORITHM = "RS256"
"""JWT algorithm to use for all tokens."""

COOKIE_NAME = "gafaelfawr"
"""Name of the state cookie."""

HTTP_TIMEOUT = 10.0
"""Timeout (in seconds) for outbound HTTP requests to auth providers."""

MINIMUM_LIFETIME = 5 * 60
"""Minimum expiration lifetime for a token in seconds."""

OIDC_AUTHORIZATION_LIFETIME = 60 * 60
"""How long (in seconds) an authorization code is good for."""

SETTINGS_PATH = "/etc/gafaelfawr/gafaelfawr.yaml"
"""Default configuration path."""

TOKEN_CACHE_SIZE = 10000
"""How many internal and notebook tokens to cache in memory."""

# The following constants are used for field validation.  Minimum and maximum
# length are handled separately.

CURSOR_REGEX = "^p?[0-9]+_[0-9]+$"
"""Regex matching a valid cursor."""

GROUPNAME_REGEX = "^[a-z_][a-zA-Z0-9._-]*$"
"""Regex matching all valid group names."""

SCOPE_REGEX = "^[a-zA-Z0-9:._-]+$"
"""Regex matching a valid scope."""

USERNAME_REGEX = "^[a-z0-9](?:[a-z0-9]|-[a-z0-9])*$"
"""Regex matching all valid usernames."""

ACTOR_REGEX = f"{USERNAME_REGEX}|^<[a-z]+>$"
""""Regex matching all valid actors (including ``<bootstrap>``)."""
