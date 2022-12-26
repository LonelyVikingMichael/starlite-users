from datetime import datetime
from typing import List, Optional
from uuid import uuid4

import uvicorn
from pydantic import SecretStr
from sqlalchemy import Column, DateTime, Integer, String
from sqlalchemy.orm import declarative_base
from starlite import Starlite
from starlite.middleware.session.memory_backend import MemoryBackendConfig
from starlite.plugins.sql_alchemy import SQLAlchemyConfig, SQLAlchemyPlugin

from starlite_users import StarliteUsers, StarliteUsersConfig
from starlite_users.adapter.sqlalchemy.guid import GUID
from starlite_users.adapter.sqlalchemy.models import (
    SQLAlchemyRoleModel,
    SQLAlchemyUserModel,
    UserRoleAssociation,
)
from starlite_users.config import (
    AuthHandlerConfig,
    CurrentUserHandlerConfig,
    PasswordResetHandlerConfig,
    RegisterHandlerConfig,
    RoleManagementHandlerConfig,
    UserManagementHandlerConfig,
    VerificationHandlerConfig,
)
from starlite_users.password import PasswordManager
from starlite_users.schema import (
    BaseRoleCreateDTO,
    BaseRoleReadDTO,
    BaseRoleUpdateDTO,
    BaseUserCreateDTO,
    BaseUserReadDTO,
    BaseUserUpdateDTO,
)
from starlite_users.service import BaseUserService

ENCODING_SECRET = "1234567890abcdef"
DATABASE_URL = "sqlite+aiosqlite:///"
password_manager = PasswordManager()


class _Base:
    """Base for all SQLAlchemy models."""

    id = Column(
        GUID(),
        primary_key=True,
        default=uuid4,
        unique=True,
        nullable=False,
    )


Base = declarative_base(cls=_Base)


class User(Base, SQLAlchemyUserModel):
    title = Column(String(20))
    login_count = Column(Integer(), default=0)


class Role(Base, SQLAlchemyRoleModel):
    created_at = Column(DateTime(), default=datetime.now)


class UserRole(Base, UserRoleAssociation):
    pass


class RoleCreateDTO(BaseRoleCreateDTO):
    pass


class RoleReadDTO(BaseRoleReadDTO):
    created_at: datetime


class RoleUpdateDTO(BaseRoleUpdateDTO):
    pass


class UserCreateDTO(BaseUserCreateDTO):
    title: str


class UserReadDTO(BaseUserReadDTO):
    title: str
    login_count: int
    roles: List[Optional[RoleReadDTO]]  # we need to set this to display our custom RoleDTO fields


class UserUpdateDTO(BaseUserUpdateDTO):
    title: Optional[str]
    # we'll update `login_count` in the UserService.post_login_hook


class UserService(BaseUserService[User, UserCreateDTO, UserUpdateDTO]):
    user_model = User
    role_model = Role
    secret = SecretStr(ENCODING_SECRET)

    async def post_login_hook(self, user: User) -> None:  # This will properly increment the user's `login_count`
        user.login_count += 1
        await self.repository.session.commit()


sqlalchemy_config = SQLAlchemyConfig(
    connection_string=DATABASE_URL,
    dependency_key="session",
)


async def on_startup() -> None:
    """Initialize the database."""
    async with sqlalchemy_config.engine.begin() as conn:  # type: ignore
        await conn.run_sync(Base.metadata.create_all)

    admin_role = Role(name="administrator", description="Top admin")
    admin_user = User(
        email="admin@example.com",
        password_hash=password_manager.get_hash(SecretStr("iamsuperadmin")),
        is_active=True,
        is_verified=True,
        title="Exemplar",
        roles=[admin_role],
    )

    async with sqlalchemy_config.session_maker() as session:
        async with session.begin():
            session.add_all([admin_role, admin_user])


starlite_users = StarliteUsers(
    config=StarliteUsersConfig(
        auth_backend="session",
        secret=ENCODING_SECRET,
        session_backend_config=MemoryBackendConfig(),
        user_model=User,
        user_read_dto=UserReadDTO,
        user_create_dto=UserCreateDTO,
        user_update_dto=UserUpdateDTO,
        role_model=Role,
        role_create_dto=RoleCreateDTO,
        role_read_dto=RoleReadDTO,
        role_update_dto=RoleUpdateDTO,
        user_service_class=UserService,
        auth_handler_config=AuthHandlerConfig(),
        current_user_handler_config=CurrentUserHandlerConfig(),
        password_reset_handler_config=PasswordResetHandlerConfig(),
        register_handler_config=RegisterHandlerConfig(),
        role_management_handler_config=RoleManagementHandlerConfig(),
        user_management_handler_config=UserManagementHandlerConfig(),
        verification_handler_config=VerificationHandlerConfig(),
    )
)

app = Starlite(
    debug=True,
    on_app_init=[starlite_users.on_app_init],
    on_startup=[on_startup],
    plugins=[SQLAlchemyPlugin(config=sqlalchemy_config)],
    route_handlers=[],
)

if __name__ == "__main__":
    uvicorn.run(app="main:app", reload=True)
