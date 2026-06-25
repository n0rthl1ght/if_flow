import os

from cachelib.redis import RedisCache

SECRET_KEY = os.environ.get("SUPERSET_SECRET_KEY", "if_flow_superset_secret_key_change_me")
SUPERSET_HOME = os.environ.get("SUPERSET_HOME", "/app/superset_home")
SQLALCHEMY_DATABASE_URI = f"sqlite:///{SUPERSET_HOME}/superset.db"

REDIS_HOST = os.environ.get("REDIS_HOST")
REDIS_PORT = os.environ.get("REDIS_PORT")

if REDIS_HOST and REDIS_PORT:
    RESULTS_BACKEND = RedisCache(
        host=REDIS_HOST,
        port=int(REDIS_PORT),
        key_prefix="superset_results",
    )

FEATURE_FLAGS = {
    "DASHBOARD_RBAC": True,
    "ENABLE_TEMPLATE_PROCESSING": True,
}
