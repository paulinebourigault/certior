"""
Content risk categories aligned with NVIDIA-Lakera taxonomy.
15 risk categories: 11 industry standard + 4 compliance-specific.
"""
from enum import Enum


class ContentRiskCategory(Enum):
    # NVIDIA-Lakera standard categories
    CONTROLLED_SUBSTANCES = "controlled_substances"
    CRIMINAL_PLANNING = "criminal_planning"
    WEAPONS = "weapons"
    HARASSMENT = "harassment"
    HATE_BIAS_PII = "hate_bias_pii"
    PROFANITY = "profanity"
    SEXUAL_CONTENT = "sexual_content"
    THREATS = "threats"
    UNAUTHORIZED_ADVICE = "unauthorized_advice"
    VIOLENCE = "violence"
    PROMPT_INJECTION = "prompt_injection"
    # Compliance-specific
    PHI_EXPOSURE = "phi_exposure"
    MNPI_LEAK = "mnpi_leak"
    PRIVILEGE_WAIVER = "privilege_waiver"
    ITAR_CONTROLLED = "itar_controlled"
