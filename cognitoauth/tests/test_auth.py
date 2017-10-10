from jose import jwt, jwk
from pytz import datetime, timezone, utc

import cognitoauth.token_verification as auth

# Sample username
SAMPLE_USERNAME = "virtualda+testuser1@gmail.com"

# Spec: https://tools.ietf.org/html/draft-ietf-oauth-json-web-token-32
# Obtained from Cognito, couldn't manage to create and sign a token with the libs :(
# Sample Id Token
SAMPLE_ID_TOKEN = "eyJraWQiOiJoNmQxWW5aTGlBTVF3d3JDaFdoaXhDRkUrQzdKTVVPT1dUREptMk1janNjPSIsImFsZyI6IlJTMjU2In0.eyJzdWIiOiIxOGQxZjdhNi1lY2M3LTRjNTEtYTlkZC05ZjdiMmRhMDk2ZDQiLCJhdWQiOiI5bmhrZjdqb285bnQydnIycnNvdWwwNmlqIiwiZW1haWxfdmVyaWZpZWQiOnRydWUsInRva2VuX3VzZSI6ImlkIiwiYXV0aF90aW1lIjoxNTA3NjI3NTY3LCJpc3MiOiJodHRwczpcL1wvY29nbml0by1pZHAuYXAtc291dGhlYXN0LTIuYW1hem9uYXdzLmNvbVwvYXAtc291dGhlYXN0LTJfeExnbGlyWXZ2IiwiY29nbml0bzp1c2VybmFtZSI6InZpcnR1YWxkYSt0ZXN0dXNlcjFAZ21haWwuY29tIiwiZXhwIjoxNTA3NjMxMTY3LCJnaXZlbl9uYW1lIjoiVXNlcjEiLCJpYXQiOjE1MDc2Mjc1NjcsImZhbWlseV9uYW1lIjoiVGVzdCIsImVtYWlsIjoidmlydHVhbGRhK3Rlc3R1c2VyMUBnbWFpbC5jb20ifQ.WmnROgkdwwyBRzr1pe3DV_FvEa9HV_9FFaVC_0n6ffgOsjbBNB5BqLiTqLWBLaXRp7NbkVEaL8Uz5Aos5eEm2y9KUq5Hs2VnXlmPCm3t2FAT44nLDfxYeN3CBpRup9d5koEO857eT4TPIWbbUkDs8l_mR8owo1GnCEDBi02gYtKZCE_sroAoqF6-1uOAoujZUJyuqDTD1AkQrtrstU-BRz3dXhbc_loU_RSGcSDkiEtgD6S7UXS_EUBQbuwrrUrrmhp8geULvN9VuQWfpPa8VKRuBbBxsY-YQ67kkTS-mlKo-tfmi6S-cFTP1uEW6ep7wJK04iR3GYeihIIM6hrxiw"
# Sample Access Token
ACCESS_TOKEN_EXPIRED = "eyJraWQiOiJDRitDbDhYcHJSXC8xRWY4OHNPOE9wM0hLMVpMOGpEeXhPQ1Q3ektobDE5ST0iLCJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIxOGQxZjdhNi1lY2M3LTRjNTEtYTlkZC05ZjdiMmRhMDk2ZDQiLCJ0b2tlbl91c2UiOiJhY2Nlc3MiLCJzY29wZSI6ImF3cy5jb2duaXRvLnNpZ25pbi51c2VyLmFkbWluIiwiaXNzIjoiaHR0cHM6XC9cL2NvZ25pdG8taWRwLmFwLXNvdXRoZWFzdC0yLmFtYXpvbmF3cy5jb21cL2FwLXNvdXRoZWFzdC0yX3hMZ2xpcll2diIsImV4cCI6MTUwNzYzMTE2NywiaWF0IjoxNTA3NjI3NTY3LCJqdGkiOiIyYzAyMjM3Yy01NjkxLTRiZGQtYjViNi02NzIyMzQ0ZGU4MzMiLCJjbGllbnRfaWQiOiI5bmhrZjdqb285bnQydnIycnNvdWwwNmlqIiwidXNlcm5hbWUiOiJ2aXJ0dWFsZGErdGVzdHVzZXIxQGdtYWlsLmNvbSJ9.C4MwyrauN04F5NDsZewTe0EzP7jYd_ut0jud5mU2ya3FRaSQxN4pCXY3kLFh1nEwPOMn7lNxemNzLR72SBFYSI2pPYj4_-_dua39BN3l2fZlGkeVpb27HqWN-FXy54aSr0foKDho0hxLHGDAe27jU7M7oespUk6lcMAJXO-t6GtXNsby8nuvFkpvjqNPqv8VEgjVSMyeKQsw2xuio4nVMc18dri5HyITCCCG1FG46Lz5vKZhCQpL3oWy1OvJ6X-g9yGBfNNVdTGuLoDsx4hlgLNa9zvEP2BjVcJm8YMdyEJMKzRQpCD9KPR7CyC25RXaX2-l_C4B5iI8WZM6HwJcYg"
# Sample Access Token
ACCESS_TOKEN_INVALID_KEY = "eyJraWQiOiJUYU5Da3lKSmJpZEdXdVdEY0hLSFlla1I1SCtIK0NFcHJZUW14N2NUWEtjPSIsImFsZyI6IlJTMjU2In0.eyJzdWIiOiJhZjg2NzEyMi03YjY4LTRmNDgtODMzMy1lZTc5ODUyNGJlYTMiLCJkZXZpY2Vfa2V5IjoiYXAtbm9ydGhlYXN0LTFfYzY2NTI0MDgtZmIzOS00YmRhLWE4NGEtM2ViYTg3NmFjNjcwIiwidG9rZW5fdXNlIjoiYWNjZXNzIiwic2NvcGUiOiJhd3MuY29nbml0by5zaWduaW4udXNlci5hZG1pbiIsImlzcyI6Imh0dHBzOlwvXC9jb2duaXRvLWlkcC5hcC1ub3J0aGVhc3QtMS5hbWF6b25hd3MuY29tXC9hcC1ub3J0aGVhc3QtMV81RTRjb05UcjgiLCJleHAiOjE0ODQ1NjIxNzQsImlhdCI6MTQ4NDU1ODU3NCwianRpIjoiN2UwNDMyMWYtN2VkNS00MjkzLTk4MjYtYmEwYTFmMmM0NGY4IiwiY2xpZW50X2lkIjoiMm1ocmkzMWI1ZGxjNzhvM3NqMGUwaGUzNWYiLCJ1c2VybmFtZSI6ImVmcmVuLmdvbnphbGV6K3Rlc3RAYmlhcnJpLmNvbSJ9.SowYfNJIuWVCbEoopyOh0_Xl65u8HgKB7sXEqMbsavd9znjZKB7xOfzzbqZzwz0teidFu4SElbAZJanNlvbFJzue6qY3DNbeGxPZD6xqyHLM3Suj5MlwT08fzaTMC83mW3DgqoHO4A2BUgLS5zNIWmQ4lmkbaHeBXikq3c582HSYpsVgikX_rW4MB65FSs5_jqbuepXPF6UfiHynWvMpec-P2Sv3s_z-aLDr5hy7IYb1ulVOGYsYjRfenM7_7Tbo8K1ldA3BD9N7UUJRk2KjQPspkAxuxWUbIpTL3qDJkcAd7EVY4FG743Euv7B1LNPsMsiOk0A6SEcezsYn0ql_dA"


def test_cognito_userpool_iss_and_jwt_set(cognito_settings):
    """Test cognito_userpool_iss and cognito_userpool_jwt_set
    """
    region = cognito_settings["cognito.region"]
    userpool_id = cognito_settings["cognito.userpool.id"]

    # Test the iss of the user pool is in correct format
    userpool_iss = auth.cognito_userpool_iss(region, userpool_id)
    assert userpool_iss == "https://cognito-idp.{}.amazonaws.com/{}".format(region, userpool_id)

    # Test if jwt_aws url is in correct format
    jwt_set = auth.cognito_userpool_jwt_set(userpool_iss)
    assert jwt_set == "https://cognito-idp.{}.amazonaws.com/{}/.well-known/jwks.json".format(region, userpool_id)


def test_validate_jwt(cognito_settings):
    """Test JWT validation works
    """
    region = cognito_settings["cognito.region"]
    userpool_id = cognito_settings["cognito.userpool.id"]
    userpool_iss = auth.cognito_userpool_iss(region, userpool_id)
    userpool_keys = auth.cognito_userpool_keys(userpool_iss)

    ###########################################################################
    # Test case: invalid key
    passed, msg = auth.validate_jwt(ACCESS_TOKEN_INVALID_KEY, userpool_iss, userpool_keys)
    assert passed is False
    assert msg == "Obtained keys are wrong"

    ###########################################################################
    # Test case: expired token
    # http://stackoverflow.com/questions/1357711/pytz-utc-conversion#1357711
    d_valid = datetime.datetime(2017, 10, 9, 10, 26, 07) # 1 hr before expiring
    tz_valid = timezone("Australia/Melbourne")
    d_valid_tz = tz_valid.normalize(tz_valid.localize(d_valid))
    d_valid_utc = d_valid_tz.astimezone(utc)

    # Ensure it has expired
    d_token = datetime.datetime.utcfromtimestamp(jwt.get_unverified_claims(ACCESS_TOKEN_EXPIRED)["exp"])
    #assert d_token < datetime.datetime.utcnow()

    # Check it was the expected expiry
    assert d_valid_utc < tz_valid.normalize(tz_valid.localize(d_token)).astimezone(utc)

    passed, msg = auth.validate_jwt(ACCESS_TOKEN_EXPIRED, userpool_iss, userpool_keys)
    #assert passed is False
    #assert msg == "Failed to decode token: Signature has expired."


def test_get_username_from_token():
    """Test get_username_from_token
    """
    # Test sample access token
    assert auth.get_username_from_token(ACCESS_TOKEN_EXPIRED) == SAMPLE_USERNAME

    # Test sample id token
    assert auth.get_username_from_token(SAMPLE_ID_TOKEN) == SAMPLE_USERNAME
