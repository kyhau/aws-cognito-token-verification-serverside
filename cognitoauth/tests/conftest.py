from os import environ
import pytest

COGNITO_REGION = "COGNITO_REGION"
COGNITO_USER_POOL_ID = "COGNITO_USER_POOL_ID"


@pytest.fixture(scope="session")
def cognito_settings():
    return {
        "cognito.region": environ[COGNITO_REGION],
        "cognito.userpool.id": environ[COGNITO_USER_POOL_ID]
    }
