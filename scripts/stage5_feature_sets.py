"""Single source of truth for the Stage 5 feature-set ablation."""

from cote3mon.features import (
    BASE_FEATURE_NAMES,
    ENHANCED_FEATURE_NAMES,
    REPETITION_FEATURE_NAMES,
    TEMPORAL_FEATURE_NAMES,
)

FEATURE_SETS = {
    "base12": BASE_FEATURE_NAMES,
    "temporal16": BASE_FEATURE_NAMES + TEMPORAL_FEATURE_NAMES,
    "repetition14": BASE_FEATURE_NAMES + REPETITION_FEATURE_NAMES,
    "enhanced18": ENHANCED_FEATURE_NAMES,
}
