"""
Advanced Integration Guide
Real-world patterns for using the metaphysical restriction system
in games, stories, and theoretical models.
"""

from metaphysical_restrictions import (
    MetaphysicalPractitioner, MetaphysicalCapability,
    RestrictionRule, RestrictionType, CapabilityType,
    ConservationOfEnergyFramework, EntropicDecayFramework,
    CausalityFramework, ConsciousnessAnchorFramework
)


# ============================================================================
# PATTERN 1: RPG SPELL SYSTEM
# ============================================================================

class RPGSpellSystem:
    """Integration pattern for traditional RPG magic systems (D&D-style)."""
    
    def __init__(self, player_name: str, spell_slots: int = 10):
        self.practitioner = MetaphysicalPractitioner(
            name=player_name,
            energy_pool=float(spell_slots * 10),
            max_energy=float(spell_slots * 10)
        )
        self.practitioner.add_framework(ConservationOfEnergyFramework(spell_slots * 10))
        self.spell_slots = spell_slots
        self.cast_history = []
    
    def add_spell(self, name: str, level: int, effect: str) -> MetaphysicalCapability:
        """Add a standard RPG spell to the spellbook."""
        # Spell power = spell level * 10
        spell = MetaphysicalCapability(
            name=name,
            capability_type=self._effect_to_capability(effect),
            base_power_level=float(level * 10)
        )
        
        # Add standard restrictions based on spell level
        spell.add_restriction(RestrictionRule(
            RestrictionType.ENERGY_COST,
            severity=level / 10.0,  # Higher level spells cost more
            description=f"Level {level} spell component cost"
        ))
        
        # Cantrips have no cooldown, higher spells have cooldowns
        if level > 0:
            spell.add_restriction(RestrictionRule(
                RestrictionType.TIME_COOLDOWN,
                severity=level / 20.0,
                description=f"{level} round cooldown"
            ))
        
        self.practitioner.add_capability(spell)
        return spell
    
    def cast_spell(self, spell_name: str) -> dict:
        """Cast a spell from the spellbook."""
        spell = next((s for s in self.practitioner.capabilities 
                     if s.name == spell_name), None)
        
        if not spell:
            return {"success": False, "message": f"Spell '{spell_name}' not found"}
        
        can_use, reason = self.practitioner.can_use_capability(spell)
        if not can_use:
            return {"success": False, "message": reason, "spell": spell_name}
        
        result = self.practitioner.use_capability(spell)
        self.cast_history.append({
            "spell": spell_name,
            "power": result["power_used"],
            "success": result["success"]
        })
        
        return {
            "success": result["success"],
            "spell": spell_name,
            "power": result["power_used"],
            "slots_remaining": result["remaining_energy"] / 10,
            "total_slots": self.practitioner.max_energy / 10
        }
    
    def long_rest(self):
        """Restore all spell slots (simulate D&D long rest)."""
        self.practitioner.energy_pool = self.practitioner.max_energy
        self.practitioner.consciousness_level = 1.0
    
    def _effect_to_capability(self, effect: str) -> CapabilityType:
        """Map spell effect type to capability type."""
        effect_map = {
            "damage": CapabilityType.ENERGY_PROJECTION,
            "healing": CapabilityType.ENERGY_PROJECTION,
            "movement": CapabilityType.TELEKINESIS,
            "mind": CapabilityType.TELEPATHY,
            "time": CapabilityType.TIME_MANIPULATION,
            "reality": CapabilityType.REALITY_WARPING,
        }
        return effect_map.get(effect.lower(), CapabilityType.ENERGY_PROJECTION)


# ============================================================================
# PATTERN 2: SUPERHERO POWER SYSTEM
# ============================================================================

class SuperheroPowerSystem:
    """Integration pattern for superhero/superpowers systems."""
    
    def __init__(self, hero_name: str, power_level: float = 50.0):
        self.hero = MetaphysicalPractitioner(
            name=hero_name,
            consciousness_level=1.0,  # Superheros maintain focus
            energy_pool=100.0,
            max_energy=100.0
        )
        self.hero.add_framework(ConservationOfEnergyFramework(100.0))
        self.power_level = power_level
        self.active_powers = []
    
    def add_power(self, name: str, activation_type: str) -> MetaphysicalCapability:
        """Add a superhero power."""
        power = MetaphysicalCapability(
            name=name,
            capability_type=CapabilityType.TELEKINESIS,  # Generic for powers
            base_power_level=self.power_level
        )
        
        if activation_type == "passive":
            # Passive powers have no cost
            pass
        elif activation_type == "active":
            # Active powers cost energy
            power.add_restriction(RestrictionRule(
                RestrictionType.ENERGY_COST,
                severity=0.2,
                description="Active power requires sustained energy"
            ))
        elif activation_type == "ultimate":
            # Ultimate powers cost a lot of energy and have cooldown
            power.add_restriction(RestrictionRule(
                RestrictionType.ENERGY_COST,
                severity=0.5,
                description="Ultimate power requires maximum energy"
            ))
            power.add_restriction(RestrictionRule(
                RestrictionType.TIME_COOLDOWN,
                severity=0.4,
                description="Ultimate power needs recharge time"
            ))
        
        self.hero.add_capability(power)
        return power
    
    def use_power(self, power_name: str) -> dict:
        """Use a superhero power in combat."""
        power = next((p for p in self.hero.capabilities 
                     if p.name == power_name), None)
        
        if not power:
            return {"success": False, "error": f"Power '{power_name}' not found"}
        
        can_use, reason = self.hero.can_use_capability(power)
        if not can_use:
            return {
                "success": False,
                "error": reason,
                "power": power_name,
                "energy_percent": (self.hero.energy_pool / self.hero.max_energy) * 100
            }
        
        result = self.hero.use_capability(power)
        return {
            "success": result["success"],
            "power": power_name,
            "power_level": result["power_used"],
            "energy_remaining": result["remaining_energy"],
            "cooldown_active": True if power.restrictions else False
        }
    
    def rest_recovery(self, seconds: int = 60):
        """Recover energy between battles."""
        # Each minute restores 10 energy
        recovery = (seconds / 60.0) * 10.0
        self.hero.energy_pool = min(
            self.hero.energy_pool + recovery,
            self.hero.max_energy
        )


# ============================================================================
# PATTERN 3: GAME BALANCE TEMPLATE
# ============================================================================

class GameBalancer:
    """Tools for balancing abilities in game design."""
    
    @staticmethod
    def calculate_balance_score(practitioner: MetaphysicalPractitioner) -> float:
        """
        Calculate a balance score (0-100) for a practitioner.
        Higher score = more balanced, less overpowered.
        """
        if not practitioner.capabilities:
            return 0.0
        
        total_power = 0.0
        total_restrictions = 0.0
        
        for capability in practitioner.capabilities:
            base = capability.base_power_level
            total_power += base
            restriction_severity = capability.get_total_restriction_severity()
            total_restrictions += restriction_severity
        
        avg_power = total_power / len(practitioner.capabilities)
        avg_restriction = total_restrictions / len(practitioner.capabilities)
        
        # Balance score: restriction severity should be 40-60% for balance
        ideal_restriction = 0.5
        restriction_balance = 100.0 - (abs(avg_restriction - ideal_restriction) * 100)
        
        # Power shouldn't exceed 60 on average
        power_balance = min(100.0, (60.0 / avg_power) * 100) if avg_power > 0 else 0.0
        
        overall_balance = (restriction_balance + power_balance) / 2.0
        return max(0.0, min(100.0, overall_balance))
    
    @staticmethod
    def suggest_rebalance(practitioner: MetaphysicalPractitioner) -> str:
        """Suggest how to rebalance a practitioner."""
        balance = GameBalancer.calculate_balance_score(practitioner)
        
        if balance > 80:
            return "✓ Well balanced"
        elif balance > 60:
            return "⚠ Slightly overpowered - consider adding restrictions"
        elif balance > 40:
            return "⚠ Moderately overpowered - add 1-2 more restrictions per ability"
        elif balance > 20:
            return "✗ Very overpowered - add significant restrictions"
        else:
            return "✗ Severely overpowered - redesign restrictions completely"
    
    @staticmethod
    def power_audit(practitioner: MetaphysicalPractitioner) -> str:
        """Generate a detailed power audit."""
        audit = f"\nPower Audit for {practitioner.name}\n"
        audit += "=" * 50 + "\n"
        
        audit += f"Balance Score: {GameBalancer.calculate_balance_score(practitioner):.1f}/100\n"
        audit += f"Recommendation: {GameBalancer.suggest_rebalance(practitioner)}\n\n"
        
        audit += "Capability Analysis:\n"
        audit += "-" * 50 + "\n"
        
        for cap in practitioner.capabilities:
            audit += f"\n{cap.name}:\n"
            audit += f"  Base Power: {cap.base_power_level:.1f}\n"
            audit += f"  Effective Power: {cap.get_effective_power():.1f}\n"
            audit += f"  Restriction Severity: {cap.get_total_restriction_severity():.1%}\n"
            audit += f"  Number of Restrictions: {len(cap.restrictions)}\n"
            
            if cap.get_effective_power() > 50:
                audit += f"  ⚠ WARNING: High effective power\n"
            if len(cap.restrictions) == 0:
                audit += f"  ⚠ WARNING: No restrictions\n"
        
        return audit


# ============================================================================
# PATTERN 4: NARRATIVE SYSTEM
# ============================================================================

class NarrativeAbilitySystem:
    """Integration for storytelling and narrative games."""
    
    def __init__(self, character_name: str):
        self.character = MetaphysicalPractitioner(
            name=character_name,
            consciousness_level=1.0,
            energy_pool=100.0,
            max_energy=100.0
        )
        self.events = []
        self.story_beats = []
    
    def traumatic_event(self):
        """Traumatic event reduces consciousness (narrative consequence)."""
        reduction = 0.2
        self.character.consciousness_level = max(
            0.0,
            self.character.consciousness_level - reduction
        )
        self.events.append({
            "type": "trauma",
            "consciousness_change": -reduction,
            "new_level": self.character.consciousness_level
        })
        return f"{self.character.name} suffers trauma. Consciousness: {self.character.consciousness_level:.0%}"
    
    def healing_scene(self):
        """Healing scene restores consciousness (narrative recovery)."""
        restoration = 0.1
        self.character.consciousness_level = min(
            1.0,
            self.character.consciousness_level + restoration
        )
        self.events.append({
            "type": "healing",
            "consciousness_change": restoration,
            "new_level": self.character.consciousness_level
        })
        return f"{self.character.name} finds peace. Consciousness: {self.character.consciousness_level:.0%}"
    
    def ritual_power_boost(self, power_name: str, boost_amount: float = 20.0):
        """Ritual grants temporary power boost (narrative moment)."""
        power = next((p for p in self.character.capabilities 
                     if p.name == power_name), None)
        
        if not power:
            return f"Power '{power_name}' not found"
        
        original = power.base_power_level
        power.base_power_level += boost_amount
        
        self.events.append({
            "type": "power_boost",
            "power": power_name,
            "boost": boost_amount,
            "original": original,
            "new": power.base_power_level
        })
        
        return f"{self.character.name}'s {power_name} increased from {original:.1f} to {power.base_power_level:.1f}!"
    
    def get_narrative_status(self) -> str:
        """Get character status for narrative description."""
        status = f"\n{self.character.name}'s Condition:\n"
        status += "-" * 40 + "\n"
        
        consciousness_desc = {
            (0.8, 1.0): "Sharp and focused",
            (0.6, 0.8): "Slightly distracted",
            (0.4, 0.6): "Struggling to concentrate",
            (0.2, 0.4): "Severely weakened",
            (0.0, 0.2): "Nearly broken",
        }
        
        for (low, high), desc in consciousness_desc.items():
            if low <= self.character.consciousness_level < high:
                status += f"Mental State: {desc} ({self.character.consciousness_level:.0%})\n"
                break
        
        energy_desc = {
            (0.8, 1.0): "Full of energy",
            (0.6, 0.8): "Moderately tired",
            (0.4, 0.6): "Quite exhausted",
            (0.2, 0.4): "Nearly drained",
            (0.0, 0.2): "On the verge of collapse",
        }
        
        energy_ratio = self.character.energy_pool / self.character.max_energy
        for (low, high), desc in energy_desc.items():
            if low <= energy_ratio < high:
                status += f"Physical State: {desc} ({energy_ratio:.0%})\n"
                break
        
        status += f"\nAbilities Available: "
        available = sum(1 for p in self.character.capabilities 
                       if self.character.can_use_capability(p)[0])
        status += f"{available}/{len(self.character.capabilities)}\n"
        
        return status


# ============================================================================
# DEMONSTRATION
# ============================================================================

def demo_patterns():
    """Demonstrate all integration patterns."""
    
    print("\n" + "="*70)
    print("INTEGRATION PATTERNS DEMONSTRATION")
    print("="*70)
    
    # Pattern 1: RPG Spell System
    print("\n--- PATTERN 1: RPG Spell System ---")
    spellbook = RPGSpellSystem("Gandalf", spell_slots=15)
    spellbook.add_spell("Fireball", 3, "damage")
    spellbook.add_spell("Magic Missile", 1, "damage")
    spellbook.add_spell("Shield", 1, "defense")
    
    result = spellbook.cast_spell("Fireball")
    print(f"Cast Fireball: {result['spell']} | Power: {result['power']:.1f}")
    print(f"Spell Slots: {result['slots_remaining']:.0f}/{result['total_slots']:.0f}")
    
    # Pattern 2: Superhero System
    print("\n--- PATTERN 2: Superhero Power System ---")
    hero = SuperheroPowerSystem("Superman", power_level=75.0)
    hero.add_power("Flight", "passive")
    hero.add_power("Heat Vision", "active")
    hero.add_power("Solar Flare", "ultimate")
    
    result = hero.use_power("Heat Vision")
    print(f"Used {result['power']}: Power {result['power_level']:.1f}")
    print(f"Energy: {result['energy_remaining']:.1f}/100")
    
    # Pattern 3: Game Balance
    print("\n--- PATTERN 3: Game Balance Analysis ---")
    print(GameBalancer.power_audit(spellbook.practitioner))
    
    # Pattern 4: Narrative System
    print("\n--- PATTERN 4: Narrative System ---")
    character = NarrativeAbilitySystem("Frodo")
    character.character.add_capability(
        MetaphysicalCapability("Ring Power", CapabilityType.REALITY_WARPING, 60.0)
    )
    
    print("Starting story...")
    print(character.character.get_status())
    
    print("\nTrauma occurs...")
    print(character.traumatic_event())
    print(character.get_narrative_status())
    
    print("\nHealing and recovery...")
    print(character.healing_scene())
    print(character.get_narrative_status())


if __name__ == "__main__":
    demo_patterns()
