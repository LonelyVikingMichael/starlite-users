from typing import Any, Callable, List, Generic, Literal, Optional, Type, Union

from starlite import HTTPRouteHandler, Router
from starlite.middleware.session.base import BaseBackendConfig
from pydantic import BaseModel, root_validator

from .models import UserModelType


class StarliteUsersConfig(BaseModel, Generic[UserModelType]):
    """Configuration for StarliteUsersPlugin."""

    class Config:
        arbitrary_types_allowed = True

    auth_strategy: Literal['session', 'jwt']
    session_backend_config: Optional[BaseBackendConfig] = None
    route_handlers: List[Union[HTTPRouteHandler, Router]]
    user_model: Type[UserModelType]
    auth_exclude_paths: List[str] = []
    retrieve_user_handler: Callable

    @root_validator
    def validate_auth_backend(cls, values: Any):
        if values.get('auth_strategy') == 'session' and not values.get('session_backend_config'):
            raise ValueError('session_backend_config must be set when auth_strategy is set to "session"')
        return values