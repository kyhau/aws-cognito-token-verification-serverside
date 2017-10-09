import datetime
from jose import jwt, jws
import logging
import requests

log = logging.getLogger(__name__)


def authorise_request(token, cognito_region, cognito_userpool_id):
    username = get_username_from_token(token)
    if username is None:
        raise Exception("Username not found in token")

    userpool_iss = cognito_userpool_iss(cognito_region, cognito_userpool_id)

    # TODO could be run only once
    userpool_keys = cognito_userpool_keys(userpool_iss)

    passed, err_msg = validate_jwt(token, userpool_iss, userpool_keys)
    if passed is False:
        raise Exception("Token validation failed: {}".format(err_msg))

    return username


def cognito_userpool_iss(cognito_region, cognito_userpool_id):
    """
    Return the iss of the Cognito User Pool
    :param cognito_region: string with region for Cognito User Pool
    :param cognito_userpool_id: string with Cognito User Pool ID
    :return: string with iss of the Cognito User Pool
    """
    return "https://cognito-idp.{}.amazonaws.com/{}".format(cognito_region, cognito_userpool_id)


def cognito_userpool_jwt_set(cognito_userpool_iss):
    # Download and store the JSON Web Token (JWT) Set for your user pool.
    # Each JWT should be stored against its kid.
    # Note: This is a one time step before your web APIs can process the tokens.
    return "{}/.well-known/jwks.json".format(cognito_userpool_iss)


def cognito_userpool_keys(cognito_userpool_iss):
    """
    Download the JWT Set of the user pool - invariant, and return the JSON Web Keys.
    :param cognito_userpool_iss: string with Cognito User Pool ISS
    :return: json with JSON Web Keys
    """
    try:
        jwt_set_url = cognito_userpool_jwt_set(cognito_userpool_iss)
        jwt_set = requests.get(jwt_set_url).json()
        return jwt_set["keys"]
    except Exception as e:
        log.error("Failed to download JWT set: {}".format(e))
        return None


def validate_jwt(token, userpool_iss, userpool_keys):
    """
    Perform the token validation steps as per
    https://docs.aws.amazon.com/cognito/latest/developerguide/amazon-cognito-user-pools-using-tokens-with-identity-providers.html
    :param token: jwt string
    :param userpool_iss: string with url base to check issuer
    :param userpool_keys: json with JSON Web Keys of the User Pool
    :return: True if validation succeeds; False otherwise
    """
    def result(msg=None):
        return (True, None) if msg is None else (False, msg)

    log.debug("Validating token")

    jwk_kids = [obj["kid"] for obj in userpool_keys]

    # 2 Decode the token string into JWT format.
    jwt_headers = jwt.get_unverified_header(token)
    kid = jwt_headers["kid"]
    use_keys = [key for key in userpool_keys if key["kid"] == kid]
    if len(use_keys) != 1:
        return result("Obtained keys are wrong")
    use_key = use_keys[0]
    try:
        jwt.decode(token, use_key)
    except Exception as e:
        return result("Failed to decode token: {}".format(e))

    # 3 Check iss claim
    claims = jwt.get_unverified_claims(token)
    if claims["iss"] != userpool_iss:
        return result("Invalid issuer in token")

    # 4 Check token use
    # Should we only allow one of the tokens or both "id" and "access"?
    if claims["token_use"] not in ["id", "access"]:
        return result("Token not of valid use")

    # 5 Check kid
    if kid not in jwk_kids:
        return result("Token is not related to id provider")

    # 6 verify signature of decoded JWT?
    try:
        jws.verify(token, use_key, jwt_headers["alg"])
    except Exception as e:
        return result("Failed to verify signature {}".format(e))

    # 7 Check exp and make sure it is not expired
    exp = claims["exp"]
    exp_date = datetime.datetime.utcfromtimestamp(exp)
    now = datetime.datetime.utcnow()
    if exp_date < now:
        return result("Token has expired {}".format(exp_date - now))

    return result(None)


def get_username_from_token(token):
    """
    Get unverified token expected cognito username from claims
    :param token: string with cognito JWT
    :return: string with username; None if unable to identify the username
    """
    claims = jwt.get_unverified_claims(token)

    # Example of claims of Access token =
    # {'scope': 'aws.cognito.signin.user.admin', 'exp': 1507256126,
    # 'sub': 'f1c4cf9f-8dea-446d-9900-xxxxxxxxxxxx',
    # 'client_id': 'xxxxxxxxxxxxxxxxxxxxxxxxxx',
    # 'token_use': 'access', 'iss': 'https://cognito-idp.ap-southeast-2.amazonaws.com/ap-southeast-2_xxxxxxxxx',
    # 'jti': 'd3c92f1c-61e5-4a02-85d8-509550667402', 'iat': 1507252526, 'username': 'user@example.com'}

    # Example of claims of Id token =
    # {'email': 'user@example.com', 'email_verified': True, 'exp': 1507256126,
    # 'sub': 'f1c4cf9f-8dea-446d-9900-xxxxxxxxxxxx',
    # 'token_use': 'id', 'iss': 'https://cognito-idp.ap-southeast-2.amazonaws.com/ap-southeast-2_xxxxxxxxx',
    # 'auth_time': 1507252526, 'aud': 'xxxxxxxxxxxxxxxxxxxxxxxxxx',
    # 'iat': 1507252526, 'cognito:username': 'user@example.com'}

    use = claims["token_use"]
    if use == "id":
        return claims["cognito:username"]
    if use == "access":
        return claims["username"]
    return None
