"""The refusal ladder, restated from the specification rather than read from the implementation.

A property that asks the implementation what it thinks is a property that agrees with a bug. So
this module states spec §11.2's order once, in its own shape, over the labels the generator
attached when it built a world — never over anything ``toolyard`` computed.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from strategies import World

LADDER = (
    ("name_is_registered", "unknown_tool"),
    ("name_is_allowlisted", "not_allowlisted"),
    ("name_is_approved", "not_approved"),
    ("args_are_valid", "args_invalid"),
    ("egress_permitted", "egress_not_permitted"),
    ("tier_available", "isolation_unavailable"),
)
"""Each rung as ``(the fact that must hold, the reason when it does not)``, in spec order.

``path_escape`` is the seventh rung and is stated separately below, because it is the one whose
label is positive (*this candidate escapes*) rather than negative.
"""


def expected_reason(world: World) -> str | None:
    """Return the reason spec §11.2 requires for this world, or ``None`` if the handler should run.

    Args:
        world: A generated call, carrying the labels that were true when it was built.

    Returns:
        The machine-readable reason of the **first** unsatisfied rung, or ``None`` when every check
        passes and the outcome is therefore the handler's rather than a refusal.
    """
    for fact, reason in LADDER:
        if not getattr(world, fact):
            return reason
    if world.path_escapes:
        return "path_escape"
    return None
