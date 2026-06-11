"""
Skill exceptions - comprehensive error hierarchy.
"""

class SkillError(Exception):
    """Base class for skill errors."""
    pass

class SkillNotFoundError(SkillError):
    """Skill directory or ID not found."""
    pass

class SkillValidationError(SkillError):
    """VERIFICATION.json failed schema validation."""
    def __init__(self, message: str, errors: list = None):
        self.errors = errors or []
        super().__init__(message)

class CapabilityError(SkillError):
    """Token missing required capabilities."""
    def __init__(self, missing: set, message: str = ""):
        self.missing = missing
        super().__init__(message or f"Missing capabilities: {missing}")

class ResourceConstraintError(SkillError):
    """Resource constraint violation."""
    pass

class InformationFlowError(SkillError):
    """Information flow policy violation."""
    def __init__(self, flow_from: str, flow_to: str):
        self.flow_from = flow_from
        self.flow_to = flow_to
        super().__init__(f"Forbidden flow: {flow_from} -> {flow_to}")

class URLNotAllowedError(SkillError):
    """URL not in allowlist."""
    pass

class URLBlockedError(SkillError):
    """URL matches blocklist."""
    pass

class ForbiddenColumnError(SkillError):
    """Query references forbidden column."""
    def __init__(self, columns: set):
        self.columns = columns
        super().__init__(f"Forbidden columns: {columns}")

class PathNotAllowedError(SkillError):
    """File path not allowed."""
    pass
