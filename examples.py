"""
Example usage demonstrating the metaphysical capabilities restriction system.
Shows both game mechanics and philosophical frameworks in action.
"""

from metaphysical_restrictions import (
    MetaphysicalCapability, MetaphysicalPractitioner,
    RestrictionRule, RestrictionType, CapabilityType,
    ConservationOfEnergyFramework, EntropicDecayFramework,
    CausalityFramework, ConsciousnessAnchorFramework,
    create_balanced_magic_system, create_restricted_reality_warper
)


def example_1_basic_capability_restriction():
    """Example 1: Basic capability with multiple restrictions."""
    print("\n" + "="*70)
    print("EXAMPLE 1: Basic Capability Restriction")
    print("="*70)
    
    # Create a simple telekinesis ability
    telekinesis = MetaphysicalCapability(
        name="Advanced Telekinesis",
        capability_type=CapabilityType.TELEKINESIS,
        base_power_level=60.0
    )
    
    print(f"\nOriginal capability: {telekinesis}")
    print(f"Effective power: {telekinesis.get_effective_power():.1f}")
    
    # Add restrictions one by one
    restrictions = [
        RestrictionRule(
            RestrictionType.ENERGY_COST,
            severity=0.3,
            description="High energy consumption"
        ),
        RestrictionRule(
            RestrictionType.RANGE_LIMIT,
            severity=0.2,
            description="Limited to 50 meters"
        ),
        RestrictionRule(
            RestrictionType.DURATION_LIMIT,
            severity=0.15,
            description="Effect lasts only 10 seconds"
        ),
    ]
    
    for restriction in restrictions:
        telekinesis.add_restriction(restriction)
        print(f"\nAfter adding {restriction.restriction_type.value}:")
        print(f"  Effective power: {telekinesis.get_effective_power():.1f}")
        print(f"  Total restriction: {telekinesis.get_total_restriction_severity():.1%}")
    
    print(f"\nFinal capability:\n  {telekinesis}")


def example_2_balanced_magic_system():
    """Example 2: Using a pre-built balanced magic system."""
    print("\n" + "="*70)
    print("EXAMPLE 2: Balanced Magic System")
    print("="*70)
    
    practitioner = create_balanced_magic_system()
    print(practitioner.get_status())
    
    # Try to use the first capability
    capability = practitioner.capabilities[0]
    print(f"\n--- Attempting to use {capability.name} ---")
    result = practitioner.use_capability(capability)
    
    print(f"Success: {result['success']}")
    print(f"Reason: {result['reason']}")
    if result['success']:
        print(f"Power discharged: {result['power_used']:.1f}")
        print(f"Energy consumed: {result['energy_consumed']:.1f}")
        print(f"Remaining energy: {result['remaining_energy']:.1f}")


def example_3_philosophical_frameworks():
    """Example 3: Demonstrating philosophical constraints."""
    print("\n" + "="*70)
    print("EXAMPLE 3: Philosophical Framework Constraints")
    print("="*70)
    
    # Create a practitioner with strict rules
    practitioner = MetaphysicalPractitioner("Philosopher Mage")
    
    # Add strict frameworks
    practitioner.add_framework(CausalityFramework(allow_time_travel=False))
    practitioner.add_framework(EntropicDecayFramework(entropy_tolerance=0.5))
    practitioner.add_framework(ConservationOfEnergyFramework(total_available_energy=150.0))
    
    # Create various capabilities
    capabilities = [
        MetaphysicalCapability("Time Rewind", CapabilityType.TIME_MANIPULATION, 70.0),
        MetaphysicalCapability("Minor Telekinesis", CapabilityType.TELEKINESIS, 30.0),
        MetaphysicalCapability("Resurrection", CapabilityType.RESURRECTION, 95.0),
    ]
    
    for cap in capabilities:
        practitioner.add_capability(cap)
    
    print("\nTesting capabilities against philosophical frameworks:")
    for capability in capabilities:
        can_use, reason = practitioner.can_use_capability(capability)
        status = "✓ ALLOWED" if can_use else "✗ RESTRICTED"
        print(f"\n{capability.name}: {status}")
        print(f"  Reason: {reason}")


def example_4_reality_warper():
    """Example 4: Heavily restricted reality warping."""
    print("\n" + "="*70)
    print("EXAMPLE 4: Reality Warper with Heavy Restrictions")
    print("="*70)
    
    practitioner = create_restricted_reality_warper()
    print(practitioner.get_status())
    
    # Attempt to use reality warping
    reality_warp = practitioner.capabilities[0]
    
    print("\n--- Attempting Reality Warp ---")
    can_use, reason = practitioner.can_use_capability(reality_warp)
    print(f"Can use: {can_use}")
    print(f"Reason: {reason}")
    
    if can_use:
        result = practitioner.use_capability(reality_warp)
        print(f"\nResult:")
        print(f"  Success: {result['success']}")
        print(f"  Power used: {result['power_used']:.1f}")
        print(f"  Energy consumed: {result['energy_consumed']:.1f}")


def example_5_consciousness_degradation():
    """Example 5: How consciousness level affects ability usage."""
    print("\n" + "="*70)
    print("EXAMPLE 5: Consciousness-Dependent Restrictions")
    print("="*70)
    
    practitioner = MetaphysicalPractitioner(
        "Meditation Master",
        consciousness_level=1.0,
        max_energy=200.0,
        energy_pool=200.0
    )
    practitioner.add_framework(ConsciousnessAnchorFramework(consciousness_threshold=0.5))
    
    # Add a high-level telepathy ability
    telepathy = MetaphysicalCapability(
        "Mind Meld",
        CapabilityType.TELEPATHY,
        base_power_level=70.0
    )
    practitioner.add_capability(telepathy)
    
    # Test at different consciousness levels
    consciousness_levels = [1.0, 0.8, 0.6, 0.4, 0.2, 0.0]
    
    print(f"\nAbility power level: {telepathy.base_power_level}")
    print("\nTesting ability at different consciousness levels:")
    print("-" * 50)
    
    for level in consciousness_levels:
        practitioner.consciousness_level = level
        can_use, reason = practitioner.can_use_capability(telepathy)
        status = "✓" if can_use else "✗"
        print(f"Consciousness {level:.0%}: {status} - {reason}")


def example_6_multiple_uses_and_cooldown():
    """Example 6: Tracking usage with cooldowns and side effects."""
    print("\n" + "="*70)
    print("EXAMPLE 6: Usage Tracking and Resource Management")
    print("="*70)
    
    practitioner = MetaphysicalPractitioner(
        "Energy Monk",
        max_energy=100.0,
        energy_pool=100.0
    )
    
    # Create an ability with mild restrictions
    ability = MetaphysicalCapability(
        "Energy Bolt",
        CapabilityType.ENERGY_PROJECTION,
        base_power_level=25.0
    )
    ability.add_restriction(RestrictionRule(
        RestrictionType.ENERGY_COST,
        severity=0.2,
        description="Moderate energy drain"
    ))
    
    practitioner.add_capability(ability)
    
    print(f"Starting energy: {practitioner.energy_pool}/{practitioner.max_energy}")
    print(f"Ability effective power: {ability.get_effective_power():.1f}")
    
    # Use the ability multiple times
    print("\n--- Sequential Uses ---")
    for i in range(5):
        result = practitioner.use_capability(ability)
        if result['success']:
            print(f"Use {i+1}: SUCCESS - Energy remaining: {result['remaining_energy']:.1f}")
        else:
            print(f"Use {i+1}: FAILED - {result['reason']}")
            break
    
    print(f"\nTotal uses completed: {ability.use_count}")


def example_7_restriction_modification():
    """Example 7: Dynamically adding and removing restrictions."""
    print("\n" + "="*70)
    print("EXAMPLE 7: Dynamic Restriction Modification")
    print("="*70)
    
    ability = MetaphysicalCapability(
        "Dimensional Portal",
        CapabilityType.DIMENSIONAL_TRAVEL,
        base_power_level=75.0
    )
    
    print(f"Initial power: {ability.get_effective_power():.1f}")
    
    # Add restrictions due to environmental factors
    print("\n--- Adding Environmental Restrictions ---")
    
    restriction1 = RestrictionRule(
        RestrictionType.ENTROPY_COST,
        severity=0.2,
        description="Dimensional instability in area"
    )
    ability.add_restriction(restriction1)
    print(f"After restriction 1: {ability.get_effective_power():.1f}")
    
    restriction2 = RestrictionRule(
        RestrictionType.MATERIAL_ANCHOR,
        severity=0.3,
        description="Requires rare materials to stabilize"
    )
    ability.add_restriction(restriction2)
    print(f"After restriction 2: {ability.get_effective_power():.1f}")
    
    # Remove a restriction
    print("\n--- Removing Restrictions ---")
    if ability.remove_restriction(RestrictionType.ENTROPY_COST):
        print(f"Removed entropy cost restriction")
    print(f"After removal: {ability.get_effective_power():.1f}")


def main():
    """Run all examples."""
    print("\n" + "="*70)
    print("METAPHYSICAL CAPABILITIES RESTRICTION SYSTEM")
    print("Game Mechanics & Philosophical Framework Examples")
    print("="*70)
    
    example_1_basic_capability_restriction()
    example_2_balanced_magic_system()
    example_3_philosophical_frameworks()
    example_4_reality_warper()
    example_5_consciousness_degradation()
    example_6_multiple_uses_and_cooldown()
    example_7_restriction_modification()
    
    print("\n" + "="*70)
    print("Examples completed!")
    print("="*70 + "\n")


if __name__ == "__main__":
    main()
