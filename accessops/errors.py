"""Error types. Every message is meant to be shown to the user as is."""


class AccessOpsError(Exception):
    """Base class for expected, user-facing errors."""


class ConfigError(AccessOpsError):
    """Missing or invalid configuration (.env, database setup)."""


class CatalogError(AccessOpsError):
    """The role catalog (roles.yaml) is missing or invalid."""


class InvalidInputError(AccessOpsError):
    """A command argument is invalid (user name, role name, ...)."""


class PolicyDeniedError(AccessOpsError):
    """A security rule forbids the request."""


class ConflictError(AccessOpsError):
    """The current state of a system does not allow the operation."""


class BusyError(AccessOpsError):
    """The same job is already running elsewhere (e.g. another cleanup)."""
