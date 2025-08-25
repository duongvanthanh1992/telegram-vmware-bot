from __future__ import annotations
import json
import logging
from typing import Dict, List, Optional, Union
from functools import wraps
from pathlib import Path

logger = logging.getLogger(__name__)

# Default user config file path
USER_CONFIG_FILE = Path("users.json")

# Role hierarchy (higher number = more privileges)
ROLE_LEVELS = {"viewer": 1, "user": 2, "admin": 3}


class UserConfig:
    """Manages user configuration and role-based access control."""

    def __init__(self, config_file: Union[str, Path] = USER_CONFIG_FILE):
        self.config_file = Path(config_file)
        self._users = {}
        self._load_config()

    def _load_config(self) -> None:
        """Load user configuration from JSON file."""
        try:
            if self.config_file.exists():
                with open(self.config_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    self._users = data.get("users", {})
                logger.info(f"Loaded {len(self._users)} users from {self.config_file}")
            else:
                logger.warning(
                    f"User config file {self.config_file} not found. Creating sample config."
                )
                self._create_sample_config()
        except Exception as e:
            logger.error(f"Error loading user config: {e}")
            self._users = {}

    def _create_sample_config(self) -> None:
        """Create a sample user configuration file."""
        sample_config = {
            "users": {
                "123456789": {
                    "username": "admin_user",
                    "role": "admin",
                    "name": "Admin User",
                    "enabled": True,
                },
                "987654321": {
                    "username": "regular_user",
                    "role": "user",
                    "name": "Regular User",
                    "enabled": True,
                },
                "555666777": {
                    "username": "view_only",
                    "role": "viewer",
                    "name": "View Only User",
                    "enabled": True,
                },
            },
            "config": {"allow_unknown_users": False, "default_role": "viewer"},
        }

        try:
            with open(self.config_file, "w", encoding="utf-8") as f:
                json.dump(sample_config, f, indent=2)
            logger.info(f"Created sample config at {self.config_file}")
            self._users = sample_config["users"]
        except Exception as e:
            logger.error(f"Error creating sample config: {e}")

    def reload_config(self) -> None:
        """Reload user configuration from file."""
        self._load_config()

    def get_user_role(
        self, user_id: Optional[int] = None, username: Optional[str] = None
        ) -> Optional[str]:
        """Get user role by user_id or username."""
        if not user_id and not username:
            return None

        # Search by user_id first (more reliable)
        if user_id:
            user_data = self._users.get(str(user_id))
            if user_data and user_data.get("enabled", True):
                return user_data.get("role")

        # Fallback to username search
        if username:
            username = username.lstrip("@").lower()
            for uid, user_data in self._users.items():
                if user_data.get("username", "").lower() == username and user_data.get(
                    "enabled", True
                ):
                    return user_data.get("role")

        return None

    def has_role_level(
        self,
        user_id: Optional[int] = None,
        username: Optional[str] = None,
        required_level: str = "viewer",
    ) -> bool:
        """Check if user has required role level or higher."""
        user_role = self.get_user_role(user_id, username)
        if not user_role or required_level not in ROLE_LEVELS:
            return False

        return ROLE_LEVELS.get(user_role, 0) >= ROLE_LEVELS.get(required_level, 0)

    def is_admin(
        self, user_id: Optional[int] = None, username: Optional[str] = None
    ) -> bool:
        """Check if user is admin."""
        return self.get_user_role(user_id, username) == "admin"

    def is_user(
        self, user_id: Optional[int] = None, username: Optional[str] = None
    ) -> bool:
        """Check if user has 'user' role (not admin or viewer)."""
        return self.get_user_role(user_id, username) == "user"

    def is_viewer(
        self, user_id: Optional[int] = None, username: Optional[str] = None
    ) -> bool:
        """Check if user has 'viewer' role."""
        return self.get_user_role(user_id, username) == "viewer"

    def has_access(
        self, user_id: Optional[int] = None, username: Optional[str] = None
    ) -> bool:
        """Check if user has any access (any valid role)."""
        return self.get_user_role(user_id, username) is not None

    def get_user_info(
        self, user_id: Optional[int] = None, username: Optional[str] = None
    ) -> Optional[Dict]:
        """Get complete user information."""
        if user_id:
            user_data = self._users.get(str(user_id))
            if user_data and user_data.get("enabled", True):
                return {**user_data, "user_id": str(user_id)}

        if username:
            username = username.lstrip("@").lower()
            for uid, user_data in self._users.items():
                if user_data.get("username", "").lower() == username and user_data.get(
                    "enabled", True
                ):
                    return {**user_data, "user_id": uid}

        return None


# Global user config instance
_user_config = UserConfig()

# Core user functions (for backward compatibility)
def load_user_config(config_file: Union[str, Path] = USER_CONFIG_FILE) -> UserConfig:
    """Load users from JSON file and return UserConfig instance."""
    global _user_config
    _user_config = UserConfig(config_file)
    return _user_config


def get_user_role(
    user_id: Optional[int] = None, username: Optional[str] = None
) -> Optional[str]:
    """Get role by user_id OR username."""
    return _user_config.get_user_role(user_id, username)


def is_admin(user_id: Optional[int] = None, username: Optional[str] = None) -> bool:
    """Check if user is admin."""
    return _user_config.is_admin(user_id, username)


def is_user(user_id: Optional[int] = None, username: Optional[str] = None) -> bool:
    """Check if user has user role."""
    return _user_config.is_user(user_id, username)


def is_viewer(user_id: Optional[int] = None, username: Optional[str] = None) -> bool:
    """Check if user is viewer."""
    return _user_config.is_viewer(user_id, username)


def has_access(user_id: Optional[int] = None, username: Optional[str] = None) -> bool:
    """Check if user has any access."""
    return _user_config.has_access(user_id, username)


def has_role_level(
    user_id: Optional[int] = None,
    username: Optional[str] = None,
    required_level: str = "viewer",
) -> bool:
    """Check if user has required role level or higher."""
    return _user_config.has_role_level(user_id, username, required_level)


# Decorator functions
def require_role(required_role: str):
    """Decorator to require specific role level."""

    def decorator(func):
        @wraps(func)
        async def wrapper(update, context, *args, **kwargs):
            user_id = update.effective_user.id if update.effective_user else None
            username = update.effective_user.username if update.effective_user else None

            if not has_role_level(user_id, username, required_role):
                user_role = get_user_role(user_id, username)
                if user_role is None:
                    await update.message.reply_text(
                        "❌ Access denied. You are not authorized to use this bot."
                    )
                else:
                    await update.message.reply_text(
                        f"❌ Insufficient permissions. Required: {required_role}, Your role: {user_role}"
                    )

                log_unauthorized_access(
                    {"user_id": user_id, "username": username, "role": user_role},
                    func.__name__,
                )
                return

            return await func(update, context, *args, **kwargs)

        return wrapper

    return decorator


def require_user_or_admin(func):
    """Decorator for user + admin commands."""
    return require_role("user")(func)


def require_any_access(func):
    """Decorator for any authorized user (including viewer)."""
    return require_role("viewer")(func)


def require_admin(func):
    """Decorator for admin-only commands."""
    return require_role("admin")(func)


# Authorization helper functions
def check_user_permission(update, required_role: str = "viewer") -> bool:
    """Check if user can execute command."""
    if not update.effective_user:
        return False

    user_id = update.effective_user.id
    username = update.effective_user.username

    return has_role_level(user_id, username, required_role)


def get_user_info_from_update(update) -> Dict[str, Union[str, int, None]]:
    """Extract user_id and username from update."""
    if not update.effective_user:
        return {"user_id": None, "username": None, "role": None}

    user_id = update.effective_user.id
    username = update.effective_user.username
    role = get_user_role(user_id, username)

    return {
        "user_id": user_id,
        "username": username,
        "role": role,
        "first_name": update.effective_user.first_name,
        "last_name": update.effective_user.last_name,
    }


def log_unauthorized_access(user_info: Dict, command: str) -> None:
    """Log unauthorized attempts."""
    logger.warning(
        f"Unauthorized access attempt - User: {user_info.get('user_id')} "
        f"(@{user_info.get('username', 'unknown')}) "
        f"Role: {user_info.get('role', 'none')} "
        f"Command: {command}"
    )


def get_user_commands(
    user_id: Optional[int] = None, username: Optional[str] = None
) -> List[str]:
    """Get list of available commands for user based on role."""
    role = get_user_role(user_id, username)

    if not role:
        return []

    # Base commands for all users
    commands = ["/start", "/help"]

    # Viewer and above
    if has_role_level(user_id, username, "viewer"):
        commands.extend([])  # Add viewer-specific commands here if any

    # User and above
    if has_role_level(user_id, username, "user"):
        commands.extend(["/find", "/vm_name", "/vm_ip", "/vm_events", "/host_name"])

    # Admin only
    if has_role_level(user_id, username, "admin"):
        commands.extend(["/flush", "/ai_linux_basic", "/ai_linux_sec"])

    return sorted(commands)
