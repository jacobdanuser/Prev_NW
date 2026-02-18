"""
Philosophical Framework Module
Theoretical underpinnings for restricting metaphysical capabilities.

This module explores how various philosophical and physical principles
can naturally limit magical and supernatural abilities.
"""

from enum import Enum
from dataclasses import dataclass
from typing import List, Dict


class PhilosophicalPrinciple(Enum):
    """Core philosophical principles limiting metaphysical abilities."""
    
    CONSERVATION = "conservation_of_energy"
    """Energy cannot be created or destroyed, only transformed."""
    
    ENTROPY = "thermodynamic_entropy"
    """All systems tend toward disorder. Order-creating acts cost energy."""
    
    CAUSALITY = "causality"
    """Causes must precede effects. Temporal loops are forbidden."""
    
    CONSCIOUSNESS = "consciousness_anchor"
    """Metaphysical acts require conscious will and mental focus."""
    
    IDENTITY = "personal_identity"
    """The self is continuous. Mind transfers violate personal continuity."""
    
    INFORMATION = "conservation_of_information"
    """Information cannot be truly destroyed or created ex nihilo."""
    
    LOCALITY = "locality_principle"
    """Mind/consciousness is anchored to a specific location or body."""
    
    WAVE_PARTICLE_DUALITY = "quantum_uncertainty"
    """Observation affects reality. Total knowledge of a system is impossible."""


@dataclass
class PhilosophicalFrameworkTheory:
    """Theoretical justification for restriction types."""
    
    principle: PhilosophicalPrinciple
    description: str
    applied_to: List[str]  # Capability types affected
    severity_justification: str
    exceptions: List[str] = None
    
    def __post_init__(self):
        if self.exceptions is None:
            self.exceptions = []


# == CONSERVATION-BASED RESTRICTIONS ==

ENERGY_CONSERVATION = PhilosophicalFrameworkTheory(
    principle=PhilosophicalPrinciple.CONSERVATION,
    description=(
        "The First Law of Thermodynamics states that energy cannot be "
        "created or destroyed, only transformed. Every metaphysical act "
        "must draw power from somewhere—either the practitioner's internal "
        "reserves, external sources, or conversion of matter."
    ),
    applied_to=[
        "telekinesis", "energy_projection", "reality_warping",
        "telepathy", "dimensional_travel"
    ],
    severity_justification=(
        "Power level determines energy consumption. A 50-point ability "
        "requires 25 energy units. Without sufficient energy reserves, "
        "the ability cannot be used."
    ),
    exceptions=[
        "Passive abilities that simply maintain a state require no energy",
        "Channeled abilities can draw unlimited power if connected to external source"
    ]
)

MATTER_MASS_EQUIVALENCE = PhilosophicalFrameworkTheory(
    principle=PhilosophicalPrinciple.CONSERVATION,
    description=(
        "Mass and energy are interchangeable (E=mc²). Creating matter "
        "from nothing requires an impossible amount of energy. "
        "Transmutation must conserve matter—you cannot create mass."
    ),
    applied_to=[
        "reality_warping", "matter_creation", "resurrection"
    ],
    severity_justification=(
        "Transmutation is limited by matter conservation. You can reshape "
        "existing matter but cannot create new mass from energy without "
        "extraordinary power sources."
    )
)


# == ENTROPY-BASED RESTRICTIONS ==

THERMODYNAMIC_ENTROPY = PhilosophicalFrameworkTheory(
    principle=PhilosophicalPrinciple.ENTROPY,
    description=(
        "The Second Law of Thermodynamics states that entropy in a closed "
        "system always increases. Order-creating acts (magic) are "
        "fundamentally working against entropy. They require energy to "
        "impose order on chaos."
    ),
    applied_to=[
        "reality_warping", "regeneration", "resurrection",
        "telekinesis", "time_manipulation"
    ],
    severity_justification=(
        "The more ordered and improbable the effect, the higher entropy cost. "
        "Resurrecting the dead (creating extreme order) has a catastrophic "
        "entropy cost. Simple telekinesis (local reordering) has lower cost."
    ),
    exceptions=[
        "Entropy-increasing acts (destruction) have negative cost",
        "Chaos magic harnesses entropy and may have reduced cost"
    ]
)


# == CAUSALITY-BASED RESTRICTIONS ==

CAUSALITY_CONSTRAINT = PhilosophicalFrameworkTheory(
    principle=PhilosophicalPrinciple.CAUSALITY,
    description=(
        "The philosophical principle of causality states that causes must "
        "precede their effects in time. This prevents paradoxes and maintains "
        "logical consistency. Time travel that creates grandfather paradoxes "
        "violates causality."
    ),
    applied_to=[
        "time_manipulation", "prophecy", "resurrection", "memory_alteration"
    ],
    severity_justification=(
        "Abilities that alter the past are forbidden entirely (severity 1.0) "
        "unless an exception is granted. Prophecy is restricted because perfect "
        "foresight creates causal loops."
    ),
    exceptions=[
        "Time dilation (slowing time locally) doesn't violate causality",
        "Multiverse branching interpretations allow limited time travel",
        "Prophecy is allowed if futures remain probabilistic and uncertain"
    ]
)


# == CONSCIOUSNESS-BASED RESTRICTIONS ==

CONSCIOUSNESS_ANCHOR = PhilosophicalFrameworkTheory(
    principle=PhilosophicalPrinciple.CONSCIOUSNESS,
    description=(
        "Metaphysical abilities require conscious intention and mental focus. "
        "Unconsciousness, drugs, meditation-induced dissociation, or mental "
        "damage impair the ability to project will onto reality."
    ),
    applied_to=[
        "all_abilities"
    ],
    severity_justification=(
        "Each ability has a minimum consciousness threshold. A 70-point ability "
        "requires 70% consciousness. Below that, it cannot be used. Sleep and "
        "unconsciousness (0% consciousness) disable all abilities."
    )
)

WILL_CONSISTENCY = PhilosophicalFrameworkTheory(
    principle=PhilosophicalPrinciple.CONSCIOUSNESS,
    description=(
        "Metaphysical projections of will require consistency of intent. "
        "Paradoxical commands (trying to both teleport and stay still) "
        "cancel out. Self-doubt creates internal conflicts that weaken effects."
    ),
    applied_to=[
        "reality_warping", "telekinesis", "telepathy"
    ],
    severity_justification=(
        "Conflicted intent reduces effectiveness. Clear, unwavering will "
        "grants full power. Doubt or hesitation reduces effective power level."
    )
)


# == IDENTITY-BASED RESTRICTIONS ==

PERSONAL_IDENTITY = PhilosophicalFrameworkTheory(
    principle=PhilosophicalPrinciple.IDENTITY,
    description=(
        "Philosophy of mind suggests personal identity is continuous. "
        "Consciousness transfer, mind uploading, and resurrection via copied "
        "consciousness may create duplicates rather than restore the original. "
        "The original consciousness/soul cannot be moved without death."
    ),
    applied_to=[
        "consciousness_transfer", "resurrection", "memory_alteration"
    ],
    severity_justification=(
        "Perfect consciousness transfer (restoring the SAME consciousness) "
        "is impossible. You can copy consciousness (creating a duplicate) "
        "but the original is lost. Resurrection always involves creating "
        "a near-duplicate, never true restoration."
    ),
    exceptions=[
        "Magical souls are metaphysical entities that can persist unchanged",
        "If consciousness is non-physical, perfect transfer may be possible"
    ]
)


# == INFORMATION-BASED RESTRICTIONS ==

INFORMATION_CONSERVATION = PhilosophicalFrameworkTheory(
    principle=PhilosophicalPrinciple.INFORMATION,
    description=(
        "In quantum mechanics, information is never truly destroyed "
        "(black hole no-loss principle). All information that ever existed "
        "leaves traces in the universe's quantum state. This prevents true "
        "creation or complete destruction."
    ),
    applied_to=[
        "reality_warping", "matter_annihilation", "memory_erasure"
    ],
    severity_justification=(
        "You cannot truly destroy matter without creating radiation/energy. "
        "You cannot erase memories without leaving traces. The universe "
        "'remembers' everything."
    )
)

KNOWLEDGE_UNCERTAINTY = PhilosophicalFrameworkTheory(
    principle=PhilosophicalPrinciple.INFORMATION,
    description=(
        "The quantum uncertainty principle and epistemological limits "
        "prevent perfect knowledge. You cannot know both position and "
        "momentum perfectly. You cannot read minds and bodies perfectly."
    ),
    applied_to=[
        "telepathy", "prophecy", "perfect_scrying"
    ],
    severity_justification=(
        "Telepathy gets weaker with mental complexity. Prophecy cannot "
        "achieve perfect accuracy. Scrying cannot penetrate all barriers."
    )
)


# == LOCALITY-BASED RESTRICTIONS ==

CONSCIOUSNESS_LOCALITY = PhilosophicalFrameworkTheory(
    principle=PhilosophicalPrinciple.LOCALITY,
    description=(
        "Consciousness appears to be localized to the brain/nervous system. "
        "Projecting consciousness at range requires energy to maintain that "
        "connection. Extreme range causes degradation or link loss."
    ),
    applied_to=[
        "telekinesis", "telepathy", "remote_viewing", "dimensional_travel"
    ],
    severity_justification=(
        "Telepathy strength decreases with distance. Telekinesis has a "
        "maximum range. Remote viewing becomes blurry at extreme range. "
        "Dimensional travel must anchor back to origin point."
    )
)


# == QUANTUM UNCERTAINTY RESTRICTIONS ==

OBSERVER_EFFECT = PhilosophicalFrameworkTheory(
    principle=PhilosophicalPrinciple.WAVE_PARTICLE_DUALITY,
    description=(
        "In quantum mechanics, observation affects the observed system. "
        "Measuring a particle's position changes its momentum. Attempting "
        "perfect perception of reality collapses quantum states, changing "
        "what you perceive."
    ),
    applied_to=[
        "reality_warping", "perfect_scrying", "prophecy"
    ],
    severity_justification=(
        "The act of observing changes the observed. Perfect prophecy is "
        "impossible because observing the future collapses it to a specific "
        "timeline, preventing alternate outcomes."
    )
)


# == PRACTICAL RESTRICTION GUIDELINES ==

RESTRICTION_SEVERITY_SCALE = {
    0.0: "No restriction - ability works at full effectiveness",
    0.1: "Negligible - restricts 10% of power",
    0.2: "Minor - restricts 20% of power, easily overcome",
    0.3: "Moderate - restricts 30%, noticeable impact",
    0.4: "Significant - ability only 60% as effective",
    0.5: "Heavy - splits power in half",
    0.7: "Severe - ability 30% effective, mostly unusable",
    0.9: "Near-total - ability barely works",
    1.0: "Complete prohibition - ability cannot be used"
}


def get_framework_for_capability(capability_type: str) -> List[PhilosophicalFrameworkTheory]:
    """Get all philosophical frameworks that restrict a given capability."""
    frameworks = [
        ENERGY_CONSERVATION, MATTER_MASS_EQUIVALENCE,
        THERMODYNAMIC_ENTROPY,
        CAUSALITY_CONSTRAINT,
        CONSCIOUSNESS_ANCHOR, WILL_CONSISTENCY,
        PERSONAL_IDENTITY,
        INFORMATION_CONSERVATION, KNOWLEDGE_UNCERTAINTY,
        CONSCIOUSNESS_LOCALITY,
        OBSERVER_EFFECT
    ]
    
    applicable = [f for f in frameworks if capability_type in f.applied_to
                 or "all_abilities" in f.applied_to]
    return applicable


def print_framework_analysis(capability_type: str):
    """Print detailed analysis of restrictions on a capability."""
    print(f"\n{'='*70}")
    print(f"PHILOSOPHICAL RESTRICTIONS: {capability_type.upper()}")
    print(f"{'='*70}\n")
    
    frameworks = get_framework_for_capability(capability_type)
    
    if not frameworks:
        print(f"No restrictions found for {capability_type}")
        return
    
    for framework in frameworks:
        print(f"\n{framework.principle.value.upper()}")
        print(f"{'-'*70}")
        print(f"Description: {framework.description}")
        print(f"\nSeverity Justification: {framework.severity_justification}")
        
        if framework.exceptions:
            print(f"\nExceptions:")
            for exc in framework.exceptions:
                print(f"  • {exc}")


# Example usage
if __name__ == "__main__":
    print("Philosophical Framework Examples:")
    print_framework_analysis("reality_warping")
    print_framework_analysis("telekinesis")
    print_framework_analysis("telepathy")
    print_framework_analysis("time_manipulation")
