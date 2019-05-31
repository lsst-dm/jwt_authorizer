import base64
import logging
from datetime import datetime, timedelta
from typing import Optional, Any, Dict, Mapping, Tuple

from flask import request, Response, current_app, render_template, flash, redirect, url_for
from jwt import PyJWTError

from .authnz import authenticate, authorize, verify_authorization_strategy, capabilities_from_groups
from .config import AuthorizerApp
from .tokens import (
    issue_token,
    api_capabilities_token_form,
    Ticket,
    parse_ticket,
    issue_default_token,
    issue_internal_token,
    get_tokens,
    revoke_token,
    AlterTokenForm,
)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


app = AuthorizerApp(__name__)


ORIGINAL_TOKEN_HEADER = "X-Orig-Authorization"


@app.route("/auth")
def authnz_token():  # type: ignore
    """Authenticate and authorize a token.
    :query capability: One or more capabilities to check
    :query satisfy: satisfy ``all`` (default) or ``any`` of the
     capability checks.
    :query reissue_token: If ``true``, then reissue token before
     setting the user headers.
    :<header Authorization: The JWT token. This must always be the
     full JWT token. The token should be in this  header as
     type ``Bearer``, but it may be type ``Basic`` if ``x-oauth-basic``
     is the username or password.
    :<header X-Orig-Authorization: The Authorization header as it was
     received before processing by ``oauth2_proxy``. This is useful when
     the original header was an ``oauth2_proxy`` ticket, as this gives
     access to the ticket.
    :>header X-Auth-Request-Email: If enabled and email is available,
     this will be set based on the ``email`` claim.
    :>header X-Auth-Request-User: If enabled and the field is available,
     this will be set from token based on the ``JWT_USERNAME_KEY`` field
    :>header X-Auth-Request-Uid: If enabled and the field is available,
     this will be set from token based on the ``JWT_UID_KEY`` field
    :>header X-Auth-Request-Groups: When a token has groups available
     in the ``isMemberOf`` claim, the names of the groups will be
     returned, comma-separated, in this header.
    :>header X-Auth-Request-Token: If enabled, the encoded token will
     be set. If ``reissue_token`` is true, the token is reissued first
    :>header X-Auth-Request-Token-Ticket: When a ticket is available
     for the token, we will return it under this header.
    :>header X-Auth-Request-Token-Capabilities: If the token has
     capabilities in the ``scope`` claim, they will be returned in this
     header.
    :>header X-Auth-Request-Token-Capabilities-Accepted: A
     space-separated list of token capabilities the reliant resource
     accepts
    :>header X-Auth-Request-Token-Capabilities-Satisfy: The strategy
     the reliant resource uses to accept a capability.
     Values include ``any`` or ``all``
    :>header WWW-Authenticate: If the request is unauthenticated, this
     header will be set.

    """
    # Default to Server Error for safety, so we must always set it to
    # 200 if it's okay.
    response = Response(status=500)
    if "Authorization" not in request.headers:
        _make_needs_authentication(response, "No Authorization header", "")
        return response

    encoded_token = _find_token("Authorization")
    if not encoded_token:
        _make_needs_authentication(response, "Unable to find token", "")
        return response

    # Authentication
    try:
        verified_token = authenticate(encoded_token)
    except PyJWTError as e:
        # All JWT failures get 401s and are logged.
        _make_needs_authentication(response, "Invalid Token", str(e))
        logger.exception("Failed to authenticate Token")
        logger.exception(e)
        return response

    # Authorization
    success, message = authorize(verified_token)

    # Always add info about authorization
    _make_capability_headers(response, verified_token)

    jti = verified_token.get("jti", "UNKNOWN")
    if success:
        response.status_code = 200
        _make_success_headers(response, encoded_token, verified_token)
        logger.info(f"Allowed token with Token ID: {jti} " f"from issuer {verified_token['iss']}")
        return response

    response.set_data(message)
    # All authorization failures get 403s
    response.status_code = 403
    logger.error(f"Failed to authorize Token ID {jti} because {message}")
    return response


@app.route("/auth/tokens", methods=["GET"])
def tokens():  # type: ignore
    try:
        encoded_token = request.headers["X-Auth-Request-Token"]
        decoded_token = authenticate(encoded_token)
    except PyJWTError as e:
        response = Response()
        _make_needs_authentication(response, "Invalid Token", str(e))
        logger.exception("Failed to authenticate Token")
        logger.exception(e)
        return response
    user_id = decoded_token[current_app.config["JWT_UID_KEY"]]
    user_tokens = get_tokens(user_id)
    forms = {}
    for user_token in user_tokens:
        forms[user_token["jti"]] = AlterTokenForm()
    return render_template("tokens.html", title="Tokens", tokens=user_tokens, forms=forms)


@app.route("/auth/tokens/<handle>", methods=["GET", "POST"])
def token_for_handle(handle: str):  # type: ignore
    try:
        encoded_token = request.headers["X-Auth-Request-Token"]
        decoded_token = authenticate(encoded_token)
    except PyJWTError as e:
        response = Response()
        _make_needs_authentication(response, "Invalid Token", str(e))
        logger.exception("Failed to authenticate Token")
        logger.exception(e)
        return response
    user_id = decoded_token[current_app.config["JWT_UID_KEY"]]
    user_tokens = {t["jti"]: t for t in get_tokens(user_id)}
    user_token = user_tokens[handle]

    form = AlterTokenForm()
    if request.method == "POST" and form.validate():
        if form.method_.data == "DELETE":
            success = revoke_token(user_id, handle)
            if success:
                flash(f"Your token with the ticket_id {handle} was deleted")
            if not success:
                flash(f"An error was encountered when deleting your token.")
            return redirect(url_for("tokens"))

    return render_template("token.html", title="Tokens", token=user_token)


@app.route("/auth/tokens/new", methods=["GET", "POST"])
def new_tokens():  # type: ignore
    try:
        encoded_token = request.headers["X-Auth-Request-Token"]
        decoded_token = authenticate(encoded_token)
    except PyJWTError as e:
        response = Response()
        _make_needs_authentication(response, "Invalid Token", str(e))
        logger.exception("Failed to authenticate Token")
        logger.exception(e)
        return response

    capabilities = current_app.config["KNOWN_CAPABILITIES"]
    form = api_capabilities_token_form(capabilities)

    if request.method == "POST" and form.validate():
        new_capabilities = []
        for capability in capabilities:
            if form[capability].data:
                new_capabilities.append(capability)
        scope = " ".join(new_capabilities)
        aud = current_app.config.get("OAUTH2_JWT.AUD.DEFAULT", decoded_token["aud"])
        new_token: Dict[str, Any] = {"scope": scope, "aud": aud}
        email = decoded_token.get("email")
        user = decoded_token.get(current_app.config["JWT_USERNAME_KEY"])
        uid = decoded_token.get(current_app.config["JWT_UID_KEY"])
        if email:
            new_token["email"] = email
        if user:
            new_token[current_app.config["JWT_USERNAME_KEY"]] = user
        if uid:
            new_token[current_app.config["JWT_UID_KEY"]] = uid

        # FIXME: Copies groups. Useful for WebDAV, maybe not necessary
        #
        # new_token['isMemberOf'] = decoded_token['isMemberOf']
        oauth2_proxy_ticket = Ticket()
        ticket_prefix = current_app.config["OAUTH2_STORE_SESSION"]["TICKET_PREFIX"]
        ticket_handle = oauth2_proxy_ticket.as_handle(ticket_prefix)
        new_token["jti"] = ticket_handle

        exp = datetime.utcnow() + timedelta(seconds=current_app.config["OAUTH2_JWT_EXP"])
        _ = issue_token(
            new_token, exp=exp, store_user_info=True, oauth2_proxy_ticket=oauth2_proxy_ticket
        )

        flash(
            f"Your Newly Created Token. Keep these Secret!<br>\n"
            f"Token: {oauth2_proxy_ticket} <br>"
        )
        return redirect(url_for("tokens"))

    return render_template(
        "new_token.html", title="New Token", form=form, capabilities=capabilities
    )


def _make_capability_headers(response: Response, verified_token: Mapping[str, Any]) -> None:
    """Set Headers scope headers that can be returned in the case of
    API authorization failure due to required capabiliites.
    :return: The mutated response object.
    """
    capabilities_required, satisfy = verify_authorization_strategy()
    group_capabilities_set = capabilities_from_groups(verified_token)
    scope_capabilities_set = set(verified_token.get("scope", "").split(" "))
    user_capabilities_set = group_capabilities_set.union(scope_capabilities_set)
    response.headers["X-Auth-Request-Token-Capabilities"] = " ".join(user_capabilities_set)
    response.headers["X-Auth-Request-Capabilities-Accepted"] = " ".join(capabilities_required)
    response.headers["X-Auth-Request-Capabilities-Satisfy"] = satisfy


def _make_success_headers(
    response: Response, encoded_token: str, verified_token: Mapping[str, Any]
) -> None:
    """Set Headers that will be returned in a successful response.
    :return: The mutated response object.
    """
    _make_capability_headers(response, verified_token)

    if current_app.config["SET_USER_HEADERS"]:
        email = verified_token.get("email")
        user = verified_token.get(current_app.config["JWT_USERNAME_KEY"])
        uid = verified_token.get(current_app.config["JWT_UID_KEY"])
        groups_list = verified_token.get("isMemberOf", list())
        if email:
            response.headers["X-Auth-Request-Email"] = email
        if user:
            response.headers["X-Auth-Request-User"] = user
        if uid:
            response.headers["X-Auth-Request-Uid"] = uid
        if groups_list:
            groups = ",".join([g["name"] for g in groups_list])
            response.headers["X-Auth-Request-Groups"] = groups

    ticket_prefix = current_app.config["OAUTH2_STORE_SESSION"]["TICKET_PREFIX"]
    original_auth = _find_token(ORIGINAL_TOKEN_HEADER) or ""
    oauth2_proxy_ticket = original_auth if original_auth.startswith(f"{ticket_prefix}:") else ""
    reissue_requested = request.args.get("reissue_token", "").lower() == "true"
    if reissue_requested:
        encoded_token, oauth2_proxy_ticket = _check_reissue_token(encoded_token, verified_token)
    response.headers["X-Auth-Request-Token"] = encoded_token
    response.headers["X-Auth-Request-Token-Ticket"] = oauth2_proxy_ticket


def _check_reissue_token(encoded_token: str, decoded_token: Mapping[str, Any]) -> Tuple[str, str]:
    """
    Reissue the token under two scenarios.
    The first scenario is a newly logged in session with a cookie,
    indicated by the token being issued from another issuer.
    We reissue the token with a default audience.
    The second scenario is a request to an internal resource, as
    indicated by the `audience` parameter being equal to the
    configured internal audience, where the current token's audience
    is from the default audience.
    :param encoded_token: The current token, encoded
    :param decoded_token: The current token, decoded
    :return: An encoded token, which may have been reissued.
    """
    # Only reissue token if it's requested and if it's a different
    # issuer than this application uses to reissue a token
    iss = current_app.config.get("OAUTH2_JWT.ISS", "")
    assert len(iss), "ERROR: Reissue requested but no Issuer Configured"
    default_audience = current_app.config.get("OAUTH2_JWT.AUD.DEFAULT", "")
    internal_audience = current_app.config.get("OAUTH2_JWT.AUD.INTERNAL", "")
    to_internal_audience = request.args.get("audience") == internal_audience
    from_this_issuer = decoded_token["iss"] == iss
    from_default_audience = decoded_token["aud"] == default_audience
    cookie_name = current_app.config["OAUTH2_STORE_SESSION"]["TICKET_PREFIX"]
    oauth2_proxy_ticket_str = request.cookies.get(cookie_name, "")

    if not from_this_issuer:
        ticket = parse_ticket(cookie_name, oauth2_proxy_ticket_str)
        # If we didn't issue it, it came from a provider, and it is
        # inherently a new session, and this happens only once, after
        # initial login. If there's no cookie, or we failed to
        # parse it, there's something funny going on.
        assert ticket, "ERROR: OAuth2 Proxy cookie must be present"
        # We transform the external provider tokens to internal tokens
        # with a fixed lifetime
        encoded_token = issue_default_token(decoded_token, ticket)
    elif from_this_issuer and from_default_audience and to_internal_audience:
        # Internal tokens should not be reissued
        encoded_token, oauth2_proxy_ticket = issue_internal_token(decoded_token)
        oauth2_proxy_ticket_str = oauth2_proxy_ticket.encode(cookie_name)

    return encoded_token, oauth2_proxy_ticket_str


def _find_token(header: str) -> Optional[str]:
    """
    From the request, find the token we need. Normally it should
    be in the Authorization header of type ``Bearer``, but it may
    be of type Basic for clients that don't support OAuth.
    :type header: HTTP Header to check for token
    :return: The token text, if found, otherwise None.
    """
    header_value = request.headers.get(header, "")
    if not header_value or " " not in header_value:
        return None
    auth_type, auth_blob = header_value.split(" ")
    encoded_token = None
    if auth_type.lower() == "bearer":
        encoded_token = auth_blob
    elif "x-forwarded-access-token" in request.headers:
        encoded_token = request.headers["x-forwarded-access-token"]
    elif "x-forwarded-ticket_id-token" in request.headers:
        encoded_token = request.headers["x-forwarded-ticket_id-token"]
    elif auth_type.lower() == "basic":
        logger.debug("Using OAuth with Basic")
        # We fallback to user:token. We ignore the user.
        # The Token is in the password
        encoded_basic_auth = auth_blob
        basic_auth = base64.b64decode(encoded_basic_auth)
        user, password = basic_auth.strip().split(b":")
        if password == "x-oauth-basic":
            # Recommended default
            encoded_token = user.decode()
        elif user == "x-oauth-basic":
            # ... Could be this though
            encoded_token = password.decode()
        else:
            logger.info("No protocol for token specified")
            encoded_token = user.decode()
    return encoded_token


def _make_needs_authentication(response: Response, error: str, message: str) -> None:
    """Modify response for a 401 as appropriate"""
    response.status_code = 401
    response.set_data(error)
    if not current_app.config.get("WWW_AUTHENTICATE"):
        return
    realm = current_app.config["REALM"]
    if current_app.config["WWW_AUTHENTICATE"].lower() == "basic":
        # Otherwise, send Bearer
        response.headers["WWW-Authenticate"] = f'Basic realm="{realm}"'
    else:
        response.headers[
            "WWW-Authenticate"
        ] = f'Bearer realm="{realm}",error="{error}",error_description="{message}"'
