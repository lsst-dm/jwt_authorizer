# This file is part of jwt_authorizer.
#
# Developed for the LSST Data Management System.
# This product includes software developed by the LSST Project
# (https://www.lsst.org).
# See the COPYRIGHT file at the top-level directory of this distribution
# for details of code ownership.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.


import base64
import hashlib
from datetime import datetime, timedelta
import logging
import os
from typing import Any, Tuple, Callable, List, Mapping, Optional

import jwt
from flask import Flask, request, Response, current_app, render_template, flash, redirect, url_for
from jwt import InvalidIssuerError, PyJWTError

from .config import Config, ALGORITHM
from .token import issue_token, get_key_as_pem, api_capabilities_token_form

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)
app = Flask(__name__)


@app.route("/auth")
def authnz_token():
    """
    Authenticate and authorize a token.
    :query capability: one or more capabilities to check.
    :query satisfy: satisfy ``all`` (default) or ``any`` of the
    capability checks.
    :query reissue_token: if ``true``, then reissue token before
    setting the user headers.
    :>header Authorization: The token should be in this header as
    type ``Bearer``, but it may be type ``Basic`` if ``x-oauth-basic``
    is the username or password.
    :<header X-Auth-Request-Email: If enabled and email is available,
    this will be set based on the ``email`` claim.
    :<header X-Auth-Request-User: If enabled and the field is available,
    this will be set from token based on the ``JWT_USERNAME_KEY`` field
    :<header X-Auth-Request-Uid: If enabled and the field is available,
    this will be set from token based on the ``JWT_UID_KEY`` field
    :<header X-Auth-Request-Token: If enabled, the encoded token will
    be set. If ``reissue_token`` is true, the token is reissued first
    :<header WWW-Authenticate: If the request is unauthenticated, this
    header will be set.
    """
    # Default to Server Error for safety, so we must always set it to 200
    # if it's okay.
    response = Response(status=500)
    if "Authorization" not in request.headers and "x-oauth-basic" not in request.cookies:
        _make_needs_authentication(response, "No Authorization header", "")
        return response

    encoded_token = _find_token()
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

    jti = verified_token.get("jti", "UNKNOWN")
    if success:
        response.status_code = 200
        _make_success_headers(response, encoded_token)
        logger.info(f"Allowed token with Token ID: {jti} " f"from issuer {verified_token['iss']}")
        return response

    response.set_data(message)
    # All authorization failures get 403s
    response.status_code = 403
    logger.error(f"Failed to authorize Token ID {jti} because {message}")
    return response


@app.route("/auth/tokens/new", methods=["GET", "POST"])
def new_tokens():
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

        new_token = {"scp": new_capabilities}
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

        exp = datetime.utcnow() + timedelta(seconds=current_app.config["OAUTH2_JWT_EXP"])
        handle = hashlib.sha1(os.urandom(16)).hexdigest()
        iv = base64.b64encode(os.urandom(16)).decode("utf-8")
        oauth2_proxy_cookie = f"{handle}.{iv}"

        _ = issue_token(
            new_token, aud=decoded_token["aud"], exp=exp, oauth2_proxy_cookie=oauth2_proxy_cookie
        )

        flash(
            f"Your Newly Created Token. Keep these Secret!<br>\n"
            f"Token: {oauth2_proxy_cookie} <br>"
        )
        return redirect(url_for("new_tokens"))

    return render_template(
        "new_token.html", title="New Token", form=form, capabilities=capabilities
    )


def authenticate(encoded_token: str) -> Mapping[str, Any]:
    """
    Authenticate the token.
    Upon successful authentication, the decoded token is returned.
    Otherwise, an exception is thrown.
    :param encoded_token: The encoded token in string form
    :return: The verified token
    :raises PyJWTError: if there's an issue decoding the token
    :raises Exception: if there's some other issue
    """
    unverified_token = jwt.decode(encoded_token, verify=False)
    unverified_headers = jwt.get_unverified_header(encoded_token)
    if current_app.config["NO_VERIFY"] is True:
        logger.debug("Skipping Verification of the token")
        return unverified_token

    issuer_url = unverified_token["iss"]
    if issuer_url not in current_app.config["ISSUERS"]:
        raise InvalidIssuerError(f"Unauthorized Issuer: {issuer_url}")
    issuer = current_app.config["ISSUERS"][issuer_url]

    # This can throw an InvalidIssuerError as well,
    # though it may be a server-side issue
    key = get_key_as_pem(issuer_url, unverified_headers["kid"])
    return jwt.decode(
        encoded_token,
        key,
        algorithm=ALGORITHM,
        audience=issuer["audience"],
        options=current_app.config.get("JWT_VERIFICATION_OPTIONS"),
    )


def authorize(verified_token: Mapping[str, Any]) -> Tuple[bool, str]:
    """
    Authorize the request based on the token.
    From the set of capabilities declared via the request,
    This method will gather the capabilities that need to be satisfied
    and determine the criteria for satisfaction.
    It will then, one by one, check authorization for each capability.
    :param verified_token: The decoded token used for authorization
    :return: A (success, message) pair. Success is true
    """
    if current_app.config["NO_AUTHORIZE"] is True:
        return True, ""

    # Authorization Checks
    capabilities = request.args.getlist("capability")
    satisfy = request.args.get("satisfy") or "all"

    # If no capability have been explicitly delineated in the URI,
    # get them from the request method. These shouldn't happen for properly
    # configured applications
    assert satisfy in ("any", "all"), "ERROR: Logic Error, Check nginx auth_request url (satisfy)"
    assert capabilities, "ERROR: Check nginx auth_request url (capability_names)"

    successes = []
    messages = []
    for capability in capabilities:
        logger.debug(f"Checking authorization for capability: {capability}")
        (success, message) = check_authorization(capability, verified_token)
        successes.append(success)
        if message:
            messages.append(message)
        if success and satisfy == "any":
            break

    if satisfy == "any":
        success = True in successes
    else:
        success = sum(successes) == len(capabilities)
    message = ", ".join(messages)
    return success, message


def _make_success_headers(response: Response, encoded_token: str):
    """Set Headers that will be returned in a successful response.
    :return: The mutated response object.
    """
    decoded_token = jwt.decode(encoded_token, verify=False)
    if current_app.config["SET_USER_HEADERS"]:
        email = decoded_token.get("email")
        user = decoded_token.get(current_app.config["JWT_USERNAME_KEY"])
        uid = decoded_token.get(current_app.config["JWT_UID_KEY"])
        if email:
            response.headers["X-Auth-Request-Email"] = uid
        if user:
            response.headers["X-Auth-Request-User"] = user
        if uid:
            response.headers["X-Auth-Request-Uid"] = uid

    # Only reissue token if it's requested and if it's a different issuer than
    # this application uses to reissue a token
    reissue_token = request.args.get("reissue_token", "").lower() == "true"
    if reissue_token and decoded_token["iss"] != current_app.config.get("OAUTH2_JWT_ISS"):
        oauth2_proxy_cookie = request.cookies["_oauth2_proxy"]
        exp = datetime.utcnow() + timedelta(seconds=current_app.config["OAUTH2_JWT_EXP"])
        encoded_token = issue_token(
            decoded_token,
            aud=decoded_token["aud"],
            exp=exp,
            oauth2_proxy_cookie=oauth2_proxy_cookie,
        )
        response.headers["X-Auth-Request-Token-Handle"] = oauth2_proxy_cookie

    response.headers["X-Auth-Request-Token"] = encoded_token


def _find_token() -> Optional[str]:
    """
    From the request, find the token we need. Normally it should
    be in the Authorization header of type ``Bearer``, but it may
    be of type Basic for clients that don't support OAuth.
    :return: The token, if found, otherwise None.
    """
    auth_type, auth_blob = request.headers["Authorization"].split(" ")
    encoded_token = None
    if auth_type.lower() == "bearer":
        encoded_token = auth_blob
    elif "x-forwarded-access-token" in request.headers:
        encoded_token = request.headers["x-forwarded-access-token"]
    elif "x-forwarded-id-token" in request.headers:
        encoded_token = request.headers["x-forwarded-id-token"]
    elif auth_type.lower() == "basic":
        logger.debug("Using OAuth with Basic")
        # We fallback to user:token. We ignore the user.
        # The Token is in the password
        encoded_basic_auth = auth_blob
        basic_auth = base64.b64decode(encoded_basic_auth)
        user, password = basic_auth.strip().split(b":")
        if password == "x-oauth-basic":
            # Recommended default
            encoded_token = user
        elif user == "x-oauth-basic":
            # ... Could be this though
            logger.warning("Protocol `x-oauth-basic` should be in password field")
            encoded_token = password
        else:
            logger.info("No protocol for token specified")
            encoded_token = user
    return encoded_token


def _make_needs_authentication(response: Response, error: str, message: str):
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


def check_authorization(capability: str, verified_token: Mapping[str, Any]) -> Tuple[bool, str]:
    """
    Check the authorization for a given capability.
    A given capability may be authorized by zero, one, or more criteria,
    modeled as a callables. All callables MUST pass, returning True,
    for authorization on the given capability to succeed.
    :param capability: The capability we are authorizing
    :param verified_token: The verified token
    :rtype: Tuple[bool, str]
    :returns: (True, message) with successful as True if the
    all checks pass, otherwiss returns (False, message)
    """

    check_access_callables = get_check_access_functions()

    successes = []
    message = ""
    for check_access in check_access_callables:
        logger.debug(f"Checking access using {check_access.__name__}")
        (successful, message) = check_access(capability, verified_token)
        if not successful:
            break
        successes.append(successful)

    success = sum(successes) == len(check_access_callables)
    return success, message


def get_check_access_functions() -> List[Callable]:
    """
    Return the check access callable for a resource.
    :return: A callable for check access
    """
    callables = []
    for checker_name in current_app.config["ACCESS_CHECKS"]:
        callables.append(current_app.ACCESS_CHECK_CALLABLES[checker_name])
    return callables


def configure(settings_path=None):
    settings_path = settings_path or "/etc/jwt-authorizer/authorizer.yaml"
    Config.validate(app, settings_path)


configure()
