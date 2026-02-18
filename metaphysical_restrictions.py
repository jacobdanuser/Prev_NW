"""
Metaphysical Capabilities Restriction System

A combined game mechanics and philosophical framework for restricting
supernatural, magical, and metaphysical abilities.
"""

from enum import Enum
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Callable
from abc import ABC, abstractmethod
import json


class CapabilityType(Enum):
    """Categories of metaphysical capabilities."""
    TELEKINESIS = "telekinesis"
    TELEPATHY = "telepathy"
    TIME_MANIPULATION = "time_manipulation"
    REALITY_WARPING = "reality_warping"
    SOUL_MANIPULATION = "soul_manipulation"
    DIMENSIONAL_TRAVEL = "dimensional_travel"
    ENERGY_PROJECTION = "energy_projection"
    PROPHESY = "prophesy"
    RESURRECTION = "resurrection"
    CONSCIOUSNESS_TRANSFER = "consciousness_transfer"


class RestrictionType(Enum):
    """Types of restrictions that can be applied."""
    ENERGY_COST = "energy_cost"
    TIME_COOLDOWN = "time_cooldown"
    RANGE_LIMIT = "range_limit"
    DURATION_LIMIT = "duration_limit"
    SIDE_EFFECTS = "side_effects"
    PHILOSOPHICAL_PARADOX = "philosophical_paradox"
    CONSERVATION_LAW = "conservation_law"
    ENTROPY_COST = "entropy_cost"
    CONSCIOUSNESS_REQUIREMENT = "consciousness_requirement"
    MATERIAL_ANCHOR = "material_anchor"


@dataclass
class RestrictionRule:
    """A single restriction rule applied to a capability."""
    restriction_type: RestrictionType
    severity: float  # 0.0 (mild) to 1.0 (severe)
    description: str
    parameters: Dict = field(default_factory=dict)

    def apply(self, base_value: float) -> float:
        """Apply restriction multiplier to a base value."""
        return base_value * (1.0 - self.severity)

    def __str__(self) -> str:
        return f"{self.restriction_type.value}: {self.description} (severity: {self.severity:.1%})"


@dataclass
class MetaphysicalCapability:
    """Represents a metaphysical or magical capability."""
    name: str
    capability_type: CapabilityType
    base_power_level: float  # 0.0 to 100.0
    restrictions: List[RestrictionRule] = field(default_factory=list)
    is_usable: bool = True
    use_count: int = 0
    last_used_timestamp: Optional[float] = None

    def get_effective_power(self) -> float:
        """Calculate effective power after applying all restrictions."""
        power = self.base_power_level
        for restriction in self.restrictions:
            power = restriction.apply(power)
        return power

    def get_total_restriction_severity(self) -> float:
        """Get cumulative restriction severity."""
        if not self.restrictions:
            return 0.0
        # Multiplicative effect of restrictions
        cumulative = 1.0
        for restriction in self.restrictions:
            cumulative *= (1.0 - restriction.severity)
        return 1.0 - cumulative

    def add_restriction(self, restriction: RestrictionRule) -> None:
        """Add a new restriction to this capability."""
        self.restrictions.append(restriction)

    def remove_restriction(self, restriction_type: RestrictionType) -> bool:
        """Remove a restriction by type. Returns True if removed."""
        original_len = len(self.restrictions)
        self.restrictions = [r for r in self.restrictions 
                           if r.restriction_type != restriction_type]
        return len(self.restrictions) < original_len

    def __str__(self) -> str:
        return (f"{self.name} ({self.capability_type.value}): "
                f"Power {self.get_effective_power():.1f}/100 "
                f"(base: {self.base_power_level:.1f}, "
                f"restricted: {self.get_total_restriction_severity():.1%})")


class PhilosophicalFramework(ABC):
    """Abstract base for philosophical frameworks limiting metaphysical abilities."""

    @abstractmethod
    def evaluate_restriction(self, capability: MetaphysicalCapability) -> bool:
        """Determine if a capability violates this philosophical framework."""
        pass

    @abstractmethod
    def get_restriction_reason(self) -> str:
        """Explain why this framework restricts capabilities."""
        pass


class ConservationOfEnergyFramework(PhilosophicalFramework):
    """Framework based on energy conservation principle."""

    def __init__(self, total_available_energy: float = 100.0):
        self.total_available_energy = total_available_energy
        self.used_energy = 0.0

    def evaluate_restriction(self, capability: MetaphysicalCapability) -> bool:
        """Energy cannot be created or destroyed, only transformed."""
        energy_cost = capability.base_power_level * 0.5
        return self.used_energy + energy_cost <= self.total_available_energy

    def get_restriction_reason(self) -> str:
        return ("Energy conservation: All metaphysical actions must draw from "
                "a finite energy pool. Energy cannot be created or destroyed.")


class EntropicDecayFramework(PhilosophicalFramework):
    """Framework based on entropy and thermodynamic principles."""

    def __init__(self, entropy_tolerance: float = 0.8):
        self.entropy_tolerance = entropy_tolerance  # 0.0 to 1.0
        self.current_entropy = 0.0

    def evaluate_restriction(self, capability: MetaphysicalCapability) -> bool:
        """Reality-altering abilities increase entropy."""
        entropy_increase = capability.base_power_level / 100.0 * 0.3
        return self.current_entropy + entropy_increase <= self.entropy_tolerance

    def get_restriction_reason(self) -> str:
        return ("Entropic decay: All metaphysical manipulations increase "
                "universal entropy. Reality resists extreme violations of entropy.")


class CausalityFramework(PhilosophicalFramework):
    """Framework that restricts causality violations."""

    def __init__(self, allow_time_travel: bool = False):
        self.allow_time_travel = allow_time_travel
        self.causal_violations = 0

    def evaluate_restriction(self, capability: MetaphysicalCapability) -> bool:
        """Causality violations are restricted unless specifically allowed."""
        causal_violations = [
            CapabilityType.TIME_MANIPULATION,
            CapabilityType.RESURRECTION,
            CapabilityType.PROPHESY
        ]
        
        if capability.capability_type in causal_violations:
            if capability.capability_type == CapabilityType.TIME_MANIPULATION:
                return self.allow_time_travel
            return True
        return True

    def get_restriction_reason(self) -> str:
        return ("Causality principle: Effects cannot precede causes. "
                "Abilities that violate causality are restricted.")


class ConsciousnessAnchorFramework(PhilosophicalFramework):
    """Framework requiring consciousness maintenance for metaphysical actions."""

    def __init__(self, consciousness_threshold: float = 0.5):
        self.consciousness_threshold = consciousness_threshold
        self.practitioner_consciousness_level = 1.0

    def evaluate_restriction(self, capability: MetaphysicalCapability) -> bool:
        """Metaphysical abilities require sufficient consciousness."""
        required_consciousness = capability.base_power_level / 100.0
        return self.practitioner_consciousness_level >= required_consciousness

    def get_restriction_reason(self) -> str:
        return ("Consciousness anchor: Metaphysical capabilities require "
                "mental clarity and awareness. Altered consciousness impairs abilities.")


@dataclass
class MetaphysicalPractitioner:
    """An entity capable of using metaphysical abilities."""
    name: str
    capabilities: List[MetaphysicalCapability] = field(default_factory=list)
    philosophical_frameworks: List[PhilosophicalFramework] = field(default_factory=list)
    consciousness_level: float = 1.0  # 0.0 to 1.0
    energy_pool: float = 100.0
    max_energy: float = 100.0

    def add_capability(self, capability: MetaphysicalCapability) -> None:
        """Add a new capability."""
        self.capabilities.append(capability)

    def add_framework(self, framework: PhilosophicalFramework) -> None:
        """Bind a philosophical framework to this practitioner."""
        self.philosophical_frameworks.append(framework)

    def can_use_capability(self, capability: MetaphysicalCapability) -> tuple[bool, str]:
        """Check if a capability can be used given all restrictions."""
        # Check if capability is enabled
        if not capability.is_usable:
            return False, "Capability is disabled."

        # Check energy
        energy_cost = capability.base_power_level * 0.5
        if self.energy_pool < energy_cost:
            return False, f"Insufficient energy. Need {energy_cost:.1f}, have {self.energy_pool:.1f}"

        # Check consciousness
        if self.consciousness_level < 0.5:
            return False, "Consciousness level too low to maintain metaphysical connection."

        # Check all philosophical frameworks
        for framework in self.philosophical_frameworks:
            if not framework.evaluate_restriction(capability):
                return False, f"Violates {type(framework).__name__}: {framework.get_restriction_reason()}"

        return True, "Capability can be used."

    def use_capability(self, capability: MetaphysicalCapability) -> Dict:
        """Attempt to use a capability. Returns result details."""
        can_use, reason = self.can_use_capability(capability)
        
        result = {
            "success": can_use,
            "capability": capability.name,
            "reason": reason,
            "power_used": 0.0,
            "energy_consumed": 0.0
        }

        if can_use:
            power_used = capability.get_effective_power()
            energy_consumed = capability.base_power_level * 0.5
            
            self.energy_pool -= energy_consumed
            capability.use_count += 1
            
            result["power_used"] = power_used
            result["energy_consumed"] = energy_consumed
            result["remaining_energy"] = self.energy_pool

        return result

    def get_status(self) -> str:
        """Get current status of the practitioner."""
        status = f"\n=== {self.name} ===\n"
        status += f"Consciousness: {self.consciousness_level:.1%}\n"
        status += f"Energy: {self.energy_pool:.1f}/{self.max_energy:.1f}\n"
        status += f"Active Frameworks: {len(self.philosophical_frameworks)}\n"
        status += f"\nCapabilities:\n"
        
        for cap in self.capabilities:
            status += f"  • {cap}\n"
            if cap.restrictions:
                for restriction in cap.restrictions:
                    status += f"    - {restriction}\n"
        
        return status


# Utility functions for common restriction setups

def create_balanced_magic_system() -> MetaphysicalPractitioner:
    """Create a well-balanced magic system with standard restrictions."""
    practitioner = MetaphysicalPractitioner("Balanced Mage")
    
    # Add frameworks
    practitioner.add_framework(ConservationOfEnergyFramework(200.0))
    practitioner.add_framework(EntropicDecayFramework(0.9))
    practitioner.add_framework(ConsciousnessAnchorFramework(0.6))
    
    # Add capabilities with restrictions
    telekinesis = MetaphysicalCapability(
        "Telekinesis",
        CapabilityType.TELEKINESIS,
        base_power_level=45.0
    )
    telekinesis.add_restriction(RestrictionRule(
        RestrictionType.RANGE_LIMIT,
        severity=0.3,
        description="Limited to 100 meters"
    ))
    telekinesis.add_restriction(RestrictionRule(
        RestrictionType.TIME_COOLDOWN,
        severity=0.2,
        description="5-second cooldown between uses"
    ))
    
    telepathy = MetaphysicalCapability(
        "Telepathy",
        CapabilityType.TELEPATHY,
        base_power_level=35.0
    )
    telepathy.add_restriction(RestrictionRule(
        RestrictionType.CONSCIOUSNESS_REQUIREMENT,
        severity=0.4,
        description="Target must have some consciousness"
    ))
    
    practitioner.add_capability(telekinesis)
    practitioner.add_capability(telepathy)
    
    return practitioner


def create_restricted_reality_warper() -> MetaphysicalPractitioner:
    """Create a reality warper with heavy restrictions."""
    practitioner = MetaphysicalPractitioner("Reality Warper", 
                                           consciousness_level=0.95,
                                           energy_pool=500.0,
                                           max_energy=500.0)
    
    # Add strict frameworks
    practitioner.add_framework(CausalityFramework(allow_time_travel=False))
    practitioner.add_framework(EntropicDecayFramework(entropy_tolerance=0.7))
    
    reality_warp = MetaphysicalCapability(
        "Reality Warping",
        CapabilityType.REALITY_WARPING,
        base_power_level=85.0
    )
    reality_warp.add_restriction(RestrictionRule(
        RestrictionType.PHILOSOPHICAL_PARADOX,
        severity=0.6,
        description="Cannot create logical contradictions"
    ))
    reality_warp.add_restriction(RestrictionRule(
        RestrictionType.ENTROPY_COST,
        severity=0.5,
        description="Massive entropy increase per use"
    ))
    reality_warp.add_restriction(RestrictionRule(
        RestrictionType.MATERIAL_ANCHOR,
        severity=0.4,
        description="Requires ritual components to ground the effect"
    ))
    
    practitioner.add_capability(reality_warp)
    
    return practitioner
