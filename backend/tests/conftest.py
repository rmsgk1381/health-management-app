import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from database import database_url

@pytest.fixture
def postgres_db():
    engine = create_engine(database_url.set(database="hma_migrations"))
    try:
        with engine.connect() as connection:
            transaction = connection.begin()
            try:
                with Session(
                    bind=connection, join_transaction_mode="create_savepoint"
                ) as db:
                    yield db
            finally:
                transaction.rollback()
    finally:
        engine.dispose()