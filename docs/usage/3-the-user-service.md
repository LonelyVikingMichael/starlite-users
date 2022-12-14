# The user service class

The [`UserService`][starlite_users.service.BaseUserService] class is the interface for all user and role related operations. The service must be subclassed and registered on the config.

## Suggested method overrides

* `send_verification_token`
You must define your own logic to email/sms the verification token to newly registered users.
* `send_password_reset_token`
You must define your own logic to email/sms password reset tokens to users.

## Optional method overrides

* `pre_login_hook`
Optional. You may verify status against external sources such as an exclusive membership database in order to proceed with authentication. Must return a bool or raise custom exception.
* `post_login_hook`
Optional. Useful for example updating a user's login count, or sending 'online' notifications to friends, etc.
* `pre_registration_hook`
Optional. You may authorize the request against external sources such as an exclusive membership database in order to proceed with registration. Must return a bool or raise custom exception.
* `post_registration_hook`
Optional. Useful to set up sending of welcome messages, etc.
* `post_verification_hook`
Optional. Useful to update external sources after a user has verified their details.

## Example

```python
from pydantic import SecretStr
from starlite_users.service import BaseUserService

from my.local.models import User
from my.local.schema import UserCreateDTO, UserUpdateDTO
from my.local.services import CustomEmailService


class UserService(BaseUserService[User, UserCreateDTO, UserUpdateDTO]):
    user_model = User
    secret = SecretStr("abcdefg")

    async def send_verification_token(self, user: User, token: str) -> None:
        email_service = CustomEmailService()
        email_service.send(
            email=user.email,
            message=f"Thanks! Your verification link is https://mysite.com/verify?token={token}",
        )
```

Or, if you're making use of roles:

```python
from pydantic import SecretStr
from starlite_users.service import BaseUserRoleService

from my.local.models import User, Role
from my.local.schema import UserCreateDTO, UserUpdateDTO
from my.local.services import CustomEmailService


class UserService(BaseUserRoleService[User, UserCreateDTO, UserUpdateDTO, Role]):
    user_model = User
    role_model = Role
    secret = SecretStr("abcdefg")

    async def send_verification_token(self, user: User, token: str) -> None:
        email_service = CustomEmailService()
        email_service.send(
            email=user.email,
            message=f"Thanks! Your verification link is https://mysite.com/verify?token={token}",
        )
```
