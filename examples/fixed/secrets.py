"""Safer configuration example using environment variables."""

import os

password = os.environ["AEGIS_DEMO_PASSWORD"]
api_key = os.environ["AEGIS_DEMO_API_KEY"]
aws_access_key = os.environ["AEGIS_DEMO_AWS_ACCESS_KEY"]
github_token = os.environ["AEGIS_DEMO_GITHUB_TOKEN"]
jwt_secret = os.environ["AEGIS_DEMO_JWT_SECRET"]
database_url = os.environ["AEGIS_DEMO_DATABASE_URL"]
private_key = os.environ["AEGIS_DEMO_PRIVATE_KEY"]
