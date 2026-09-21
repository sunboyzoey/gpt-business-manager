from __future__ import annotations

from logging.config import fileConfig
import os

from alembic import context
from sqlalchemy import engine_from_config, pool
from sqlmodel import SQLModel

from bootstrap import configure

configure()

# Register every table owned by the standalone application. Imports are kept
# explicit so removing a legacy compatibility module is visible in review.
import core.config_store  # noqa: E402,F401
import core.db  # noqa: E402,F401
import core.proxy_pool  # noqa: E402,F401
import services.business_child_batch_action_store  # noqa: E402,F401
import services.device_hosting_store  # noqa: E402,F401
import services.gmail_app_password_store  # noqa: E402,F401
import services.gmail_store  # noqa: E402,F401
import services.gpt_plan_preparation_store  # noqa: E402,F401
import services.nv_automation_store  # noqa: E402,F401
import services.nv_listing_renewal  # noqa: E402,F401
import services.nv_order_history  # noqa: E402,F401
import services.nv_price_batch  # noqa: E402,F401
import services.nv_refunds  # noqa: E402,F401
import services.prepared_batch_invite_store  # noqa: E402,F401
import services.sms_gateway  # noqa: E402,F401

config = context.config
if config.config_file_name:
    fileConfig(config.config_file_name)

database_url = os.getenv("GBM_DATABASE_URL") or os.getenv("DATABASE_URL")
if database_url:
    config.set_main_option("sqlalchemy.url", database_url.replace("%", "%%"))

target_metadata = SQLModel.metadata


def run_migrations_offline() -> None:
    context.configure(
        url=config.get_main_option("sqlalchemy.url"),
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        compare_type=True,
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    connectable = engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )
    with connectable.connect() as connection:
        context.configure(connection=connection, target_metadata=target_metadata, compare_type=True)
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
