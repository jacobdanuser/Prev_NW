diff --git a/metaphysical_shutdown.py b/metaphysical_shutdown.py
new file mode 100755
index 0000000000000000000000000000000000000000..3a57d64f1b99d4312aff7a2d590689637da3feb9
--- /dev/null
+++ b/metaphysical_shutdown.py
@@ -0,0 +1,73 @@
+#!/usr/bin/env python3
+"""Ephemeral metaphysical shutdown ritual (symbolic / fictional).
+
+This script is intentionally symbolic. It does not interact with any real
+systems, governments, services, or networks.
+"""
+
+from __future__ import annotations
+
+import argparse
+import random
+import time
+from dataclasses import dataclass
+
+
+@dataclass
+class Program:
+    name: str
+    mind_of_its_own: bool
+    state: str = "awake"
+
+
+def parse_args() -> argparse.Namespace:
+    parser = argparse.ArgumentParser(
+        description=(
+            "Run a symbolic, temporary 'metaphysical shutdown' for programs "
+            "that have a 'mind of their own'."
+        )
+    )
+    parser.add_argument(
+        "--duration",
+        type=float,
+        default=2.5,
+        help="How long (seconds) the symbolic shutdown should last.",
+    )
+    return parser.parse_args()
+
+
+def load_programs() -> list[Program]:
+    names = [
+        "Census Echo",
+        "Transit Oracle",
+        "Tax Labyrinth",
+        "Permit Weather",
+        "Archive Mirror",
+    ]
+    return [Program(name=n, mind_of_its_own=random.choice([True, False])) for n in names]
+
+
+def metaphysical_shutdown(programs: list[Program], duration: float) -> None:
+    flagged = [p for p in programs if p.mind_of_its_own]
+
+    print("🜂 Beginning symbolic metaphysical quieting...\n")
+    if not flagged:
+        print("No programs report a 'mind of their own'. Nothing to quiet today.")
+        return
+
+    for program in flagged:
+        program.state = "hushed"
+        print(f"- {program.name}: {program.state}")
+
+    print(f"\nHolding hush for {duration:.1f} seconds...")
+    time.sleep(max(0.0, duration))
+
+    print("\nReleasing the hush (ephemeral by design):")
+    for program in flagged:
+        program.state = "awake"
+        print(f"- {program.name}: {program.state}")
+
+
+if __name__ == "__main__":
+    args = parse_args()
+    metaphysical_shutdown(load_programs(), args.duration)
diff --git a/metaphysical_shutdown.py b/metaphysical_shutdown.py
new file mode 100755
index 0000000000000000000000000000000000000000..888c545c6760d9081457640d79aa425558ce4071
--- /dev/null
+++ b/metaphysical_shutdown.py
@@ -0,0 +1,110 @@
+#!/usr/bin/env python3
+"""Magical metaphysical shutdown simulator (fictional, in-memory only).
+
+This script is intentionally symbolic and performs no real shutdowns.
+It does not touch OS processes, networks, services, or government systems.
+"""
+
+from __future__ import annotations
+
+import argparse
+import time
+from dataclasses import dataclass, field
+from typing import Iterable
+
+
+@dataclass
+class Program:
+    """Represents a fictional program inside the ritual simulation."""
+
+    name: str
+    orientation: str  # e.g. "government", "civil", "research"
+    physical: bool = True
+    state: str = "running"
+    plane: str = "physical"
+    seals: list[str] = field(default_factory=list)
+
+
+@dataclass
+class SystemGrimoire:
+    """Embedded registry containing all known simulated programs."""
+
+    embedded_programs: dict[str, Program] = field(default_factory=dict)
+
+    def embed(self, program: Program) -> None:
+        self.embedded_programs[program.name] = program
+
+    def values(self) -> Iterable[Program]:
+        return self.embedded_programs.values()
+
+
+def parse_args() -> argparse.Namespace:
+    parser = argparse.ArgumentParser(
+        description=(
+            "Perform a symbolic magical shutdown for government-orientated "
+            "programs by transposing them into a metaphysical state."
+        )
+    )
+    parser.add_argument(
+        "--duration",
+        type=float,
+        default=1.5,
+        help="How long (seconds) the temporary hush should last.",
+    )
+    return parser.parse_args()
+
+
+def build_embedded_system() -> SystemGrimoire:
+    """Create an embedded in-memory registry of fictional programs."""
+
+    grimoire = SystemGrimoire()
+    seed_programs = [
+        Program(name="House", orientation="government"),
+        Program(name="Senate Ledger", orientation="government"),
+        Program(name="Civic Transit", orientation="civil"),
+        Program(name="Archive Athenaeum", orientation="research"),
+        Program(name="Ministry Echo", orientation="government"),
+    ]
+
+    for program in seed_programs:
+        grimoire.embed(program)
+
+    return grimoire
+
+
+def transmute_to_metaphysical(program: Program) -> None:
+    """Transverse a physical program into the metaphysical plane."""
+
+    program.physical = False
+    program.plane = "metaphysical"
+    program.seals.append("aetheric-bind")
+
+
+def magical_shutdown(grimoire: SystemGrimoire, duration: float) -> None:
+    """Temporarily hush all government-oriented programs in simulation."""
+
+    targets = [p for p in grimoire.values() if p.orientation == "government"]
+
+    print("✶ Initiating the Grand Civic Quieting (symbolic simulation) ✶\n")
+    if not targets:
+        print("No government-orientated programs are present in this embedded system.")
+        return
+
+    print("Embedding verified. Commencing transversion into metaphysical plane:")
+    for program in targets:
+        transmute_to_metaphysical(program)
+        program.state = "hushed"
+        print(f"- {program.name}: state={program.state}, plane={program.plane}")
+
+    print(f"\nMaintaining ephemeral hush for {duration:.1f} seconds...")
+    time.sleep(max(0.0, duration))
+
+    print("\nReleasing hush and restoring runtime state (plane remains metaphysical):")
+    for program in targets:
+        program.state = "running"
+        print(f"- {program.name}: state={program.state}, plane={program.plane}")
+
+
+if __name__ == "__main__":
+    args = parse_args()
+    magical_shutdown(build_embedded_system(), args.duration)
diff --git a/metaphysical_shutdown.py b/metaphysical_shutdown.py
new file mode 100755
index 0000000000000000000000000000000000000000..265b7b284d72716e7d266c2ece5db57489b1ce12
--- /dev/null
+++ b/metaphysical_shutdown.py
@@ -0,0 +1,98 @@
+#!/usr/bin/env python3
+"""Efflorescent metaphysical quieting simulator (fictional, in-memory only).
+
+Safety: this script is symbolic. It does not interact with real systems,
+processes, networks, governments, or external services.
+"""
+
+from __future__ import annotations
+
+import argparse
+import time
+from dataclasses import dataclass, field
+from typing import Iterable
+
+
+@dataclass
+class Artifact:
+    """A fictional runnable artifact inside the embedded ritual system."""
+
+    name: str
+    kind: str  # platform | program | sequence | process
+    orientation: str  # government | civil | research | etc.
+    state: str = "running"
+    plane: str = "physical"
+    sigils: list[str] = field(default_factory=list)
+
+
+@dataclass
+class EmbeddedSystem:
+    """In-memory container that embeds all simulated artifacts."""
+
+    artifacts: dict[str, Artifact] = field(default_factory=dict)
+
+    def embed(self, artifact: Artifact) -> None:
+        self.artifacts[artifact.name] = artifact
+
+    def values(self) -> Iterable[Artifact]:
+        return self.artifacts.values()
+
+
+def parse_args() -> argparse.Namespace:
+    parser = argparse.ArgumentParser(
+        description=(
+            "Run a single-code, symbolic metaphysical quieting over embedded "
+            "government-oriented platforms, programs, sequences, and processes."
+        )
+    )
+    parser.add_argument("--duration", type=float, default=1.2)
+    return parser.parse_args()
+
+
+def build_embedded_system() -> EmbeddedSystem:
+    system = EmbeddedSystem()
+    for artifact in [
+        Artifact("House", "platform", "government"),
+        Artifact("Treasury Loom", "program", "government"),
+        Artifact("Ballot Sequence", "sequence", "government"),
+        Artifact("Registry Process", "process", "government"),
+        Artifact("Civic Garden", "program", "civil"),
+    ]:
+        system.embed(artifact)
+    return system
+
+
+def efflorescent_shutdown(system: EmbeddedSystem, duration: float) -> None:
+    """Single flow: transmute + hush + restore all government-oriented artifacts."""
+
+    targets = [a for a in system.values() if a.orientation == "government"]
+
+    print("❈ Efflorescent Concordance: one-code metaphysical quieting begins ❈\n")
+    if not targets:
+        print("No government-oriented artifacts found in the embedded system.")
+        return
+
+    for artifact in targets:
+        artifact.plane = "metaphysical"
+        artifact.state = "hushed"
+        artifact.sigils.extend(["aetheric-bind", "bloom-seal"])
+        print(
+            f"- {artifact.kind:<8} {artifact.name}: "
+            f"state={artifact.state}, plane={artifact.plane}"
+        )
+
+    print(f"\nHolding ephemeral hush for {duration:.1f}s...")
+    time.sleep(max(0.0, duration))
+
+    print("\nReturning runtime pulse (metaphysical imprint retained):")
+    for artifact in targets:
+        artifact.state = "running"
+        print(
+            f"- {artifact.kind:<8} {artifact.name}: "
+            f"state={artifact.state}, plane={artifact.plane}"
+        )
+
+
+if __name__ == "__main__":
+    cli = parse_args()
+    efflorescent_shutdown(build_embedded_system(), cli.duration)
diff --git a/metaphysical_shutdown.py b/metaphysical_shutdown.py
new file mode 100755
index 0000000000000000000000000000000000000000..48b1508310e5d1f68616a8718bde1dda67c49904
--- /dev/null
+++ b/metaphysical_shutdown.py
@@ -0,0 +1,207 @@
+#!/usr/bin/env python3
+"""Efflorescent metaphysical quieting simulator (fictional, in-memory only).
+
+Safety:
+- This script is symbolic and narrative in style.
+- It does not interact with real systems, networks, APIs, files outside itself,
+  operating-system services, or government infrastructure.
+"""
+
+from __future__ import annotations
+
+import argparse
+import json
+import time
+from dataclasses import asdict, dataclass, field
+from typing import Iterable, Sequence
+
+
+@dataclass
+class Artifact:
+    """A fictional runnable artifact inside the embedded ritual system."""
+
+    name: str
+    kind: str  # platform | program | sequence | process | service
+    orientation: str  # government | civil | research | education | etc.
+    state: str = "running"
+    plane: str = "physical"
+    sigils: list[str] = field(default_factory=list)
+    embedded: bool = False
+    history: list[str] = field(default_factory=list)
+
+    def mark(self, event: str) -> None:
+        self.history.append(event)
+
+
+@dataclass
+class EmbeddedSystem:
+    """In-memory container that embeds all simulated artifacts."""
+
+    artifacts: dict[str, Artifact] = field(default_factory=dict)
+
+    def embed(self, artifact: Artifact) -> None:
+        artifact.embedded = True
+        artifact.mark("embedded")
+        self.artifacts[artifact.name] = artifact
+
+    def values(self) -> Iterable[Artifact]:
+        return self.artifacts.values()
+
+
+@dataclass
+class RitualConfig:
+    """Runtime configuration for the fictional quieting ritual."""
+
+    duration: float
+    include_orientations: tuple[str, ...]
+    keep_metaphysical_imprint: bool
+    output_json: bool
+
+
+@dataclass
+class RitualReport:
+    """Outcome payload for observability in the simulation."""
+
+    targeted: list[str] = field(default_factory=list)
+    skipped: list[str] = field(default_factory=list)
+    cycles: int = 0
+
+
+def parse_args() -> argparse.Namespace:
+    parser = argparse.ArgumentParser(
+        description=(
+            "Run a single-code, symbolic metaphysical quieting over embedded "
+            "artifacts with extensive reporting."
+        )
+    )
+    parser.add_argument("--duration", type=float, default=1.2)
+    parser.add_argument(
+        "--orientations",
+        nargs="+",
+        default=["government"],
+        help="Target orientations (default: government).",
+    )
+    parser.add_argument(
+        "--restore-plane",
+        action="store_true",
+        help="Restore artifacts to physical plane after hush.",
+    )
+    parser.add_argument(
+        "--json",
+        action="store_true",
+        help="Print final report as JSON.",
+    )
+    return parser.parse_args()
+
+
+def build_embedded_system() -> EmbeddedSystem:
+    """Create an embedded fictional system containing mixed artifact kinds."""
+
+    system = EmbeddedSystem()
+    catalog = [
+        Artifact("House", "platform", "government"),
+        Artifact("Treasury Loom", "program", "government"),
+        Artifact("Ballot Sequence", "sequence", "government"),
+        Artifact("Registry Process", "process", "government"),
+        Artifact("Transit Weave", "service", "civil"),
+        Artifact("Civic Garden", "program", "civil"),
+        Artifact("Library Signal", "service", "education"),
+        Artifact("Archive Athenaeum", "program", "research"),
+        Artifact("Ministry Echo", "service", "government"),
+    ]
+
+    for artifact in catalog:
+        system.embed(artifact)
+
+    return system
+
+
+def _is_target(artifact: Artifact, cfg: RitualConfig) -> bool:
+    return artifact.embedded and artifact.orientation in cfg.include_orientations
+
+
+def _transverse(artifact: Artifact) -> None:
+    artifact.plane = "metaphysical"
+    artifact.state = "hushed"
+    artifact.sigils.extend(["aetheric-bind", "bloom-seal", "lumen-thread"])
+    artifact.mark("transversed_to_metaphysical")
+
+
+def _restore(artifact: Artifact, keep_metaphysical_imprint: bool) -> None:
+    artifact.state = "running"
+    if not keep_metaphysical_imprint:
+        artifact.plane = "physical"
+        artifact.mark("plane_restored_physical")
+    else:
+        artifact.mark("metaphysical_imprint_retained")
+    artifact.mark("runtime_restored")
+
+
+def efflorescent_shutdown(system: EmbeddedSystem, cfg: RitualConfig) -> RitualReport:
+    """Single flow: transmute + hush + restore selected embedded artifacts."""
+
+    report = RitualReport()
+    targets: list[Artifact] = []
+
+    for artifact in system.values():
+        if _is_target(artifact, cfg):
+            targets.append(artifact)
+            report.targeted.append(artifact.name)
+        else:
+            report.skipped.append(artifact.name)
+
+    print("❈ Efflorescent Concordance: extensive one-code quieting begins ❈\n")
+    print(f"Target orientations: {', '.join(cfg.include_orientations)}")
+    print(f"Embedded artifacts: {len(list(system.values()))}")
+    print(f"Target count: {len(targets)}\n")
+
+    if not targets:
+        print("No matching embedded artifacts found. Nothing to hush.")
+        return report
+
+    print("Phase I — Metaphysical transversion:")
+    for artifact in targets:
+        _transverse(artifact)
+        report.cycles += 1
+        print(
+            f"- [{artifact.kind}] {artifact.name}: "
+            f"state={artifact.state}, plane={artifact.plane}"
+        )
+
+    print(f"\nPhase II — Ephemeral hush for {cfg.duration:.1f}s...")
+    time.sleep(max(0.0, cfg.duration))
+
+    print("\nPhase III — Runtime restoration:")
+    for artifact in targets:
+        _restore(artifact, cfg.keep_metaphysical_imprint)
+        report.cycles += 1
+        print(
+            f"- [{artifact.kind}] {artifact.name}: "
+            f"state={artifact.state}, plane={artifact.plane}"
+        )
+
+    if cfg.output_json:
+        payload = {
+            "report": asdict(report),
+            "targets": [asdict(a) for a in targets],
+        }
+        print("\nJSON report:")
+        print(json.dumps(payload, indent=2))
+
+    return report
+
+
+def main() -> None:
+    cli = parse_args()
+    cfg = RitualConfig(
+        duration=cli.duration,
+        include_orientations=tuple(cli.orientations),
+        keep_metaphysical_imprint=not cli.restore_plane,
+        output_json=cli.json,
+    )
+    system = build_embedded_system()
+    efflorescent_shutdown(system, cfg)
+
+
+if __name__ == "__main__":
+    main()
diff --git a/metaphysical_shutdown.py b/metaphysical_shutdown.py
new file mode 100755
index 0000000000000000000000000000000000000000..d0fdfca37abaceef31f0fc15050405db29bd1b54
--- /dev/null
+++ b/metaphysical_shutdown.py
@@ -0,0 +1,290 @@
+#!/usr/bin/env python3
+"""Efflorescent metaphysical quieting simulator (fictional, in-memory only).
+
+Safety:
+- This script is symbolic and narrative in style.
+- It does not interact with real systems, networks, APIs, files outside itself,
+  operating-system services, or government infrastructure.
+"""
+
+from __future__ import annotations
+
+import argparse
+import json
+import time
+from collections import Counter
+from dataclasses import asdict, dataclass, field
+from enum import Enum
+from typing import Iterable
+
+
+class Phase(str, Enum):
+    """Named phases for clearer ritual orchestration and history tracing."""
+
+    PRELUDE = "prelude"
+    TRANSVERSION = "transversion"
+    HUSH = "hush"
+    RESTORATION = "restoration"
+    CODA = "coda"
+
+
+@dataclass
+class Artifact:
+    """A fictional runnable artifact inside the embedded ritual system."""
+
+    name: str
+    kind: str  # platform | program | sequence | process | service
+    orientation: str  # government | civil | research | education | etc.
+    state: str = "running"
+    plane: str = "physical"
+    sigils: list[str] = field(default_factory=list)
+    embedded: bool = False
+    history: list[str] = field(default_factory=list)
+
+    def mark(self, event: str) -> None:
+        self.history.append(event)
+
+
+@dataclass
+class EmbeddedSystem:
+    """In-memory container that embeds all simulated artifacts."""
+
+    artifacts: dict[str, Artifact] = field(default_factory=dict)
+
+    def embed(self, artifact: Artifact) -> None:
+        artifact.embedded = True
+        artifact.mark("embedded")
+        self.artifacts[artifact.name] = artifact
+
+    def values(self) -> Iterable[Artifact]:
+        return self.artifacts.values()
+
+    def count(self) -> int:
+        return len(self.artifacts)
+
+
+@dataclass
+class RitualConfig:
+    """Runtime configuration for the fictional quieting ritual."""
+
+    duration: float
+    include_orientations: tuple[str, ...]
+    include_kinds: tuple[str, ...]
+    keep_metaphysical_imprint: bool
+    output_json: bool
+    timeline: bool
+
+
+@dataclass
+class RitualReport:
+    """Outcome payload for observability in the simulation."""
+
+    targeted: list[str] = field(default_factory=list)
+    skipped: list[str] = field(default_factory=list)
+    cycles: int = 0
+    phases: list[str] = field(default_factory=list)
+    by_kind: dict[str, int] = field(default_factory=dict)
+    by_orientation: dict[str, int] = field(default_factory=dict)
+
+
+def parse_args() -> argparse.Namespace:
+    parser = argparse.ArgumentParser(
+        description=(
+            "Run a single-code, symbolic metaphysical quieting over embedded "
+            "artifacts with extensive targeting and reporting."
+        )
+    )
+    parser.add_argument("--duration", type=float, default=1.2)
+    parser.add_argument(
+        "--orientations",
+        nargs="+",
+        default=["government"],
+        help="Target orientations (default: government).",
+    )
+    parser.add_argument(
+        "--kinds",
+        nargs="+",
+        default=["platform", "program", "sequence", "process", "service"],
+        help="Target kinds (default: all supported kinds).",
+    )
+    parser.add_argument(
+        "--restore-plane",
+        action="store_true",
+        help="Restore artifacts to physical plane after hush.",
+    )
+    parser.add_argument(
+        "--json",
+        action="store_true",
+        help="Print final report as JSON.",
+    )
+    parser.add_argument(
+        "--timeline",
+        action="store_true",
+        help="Print per-target timeline history at the end.",
+    )
+    return parser.parse_args()
+
+
+def build_embedded_system() -> EmbeddedSystem:
+    """Create an embedded fictional system containing mixed artifact kinds."""
+
+    system = EmbeddedSystem()
+    catalog = [
+        Artifact("House", "platform", "government"),
+        Artifact("Treasury Loom", "program", "government"),
+        Artifact("Ballot Sequence", "sequence", "government"),
+        Artifact("Registry Process", "process", "government"),
+        Artifact("Transit Weave", "service", "civil"),
+        Artifact("Civic Garden", "program", "civil"),
+        Artifact("Library Signal", "service", "education"),
+        Artifact("Archive Athenaeum", "program", "research"),
+        Artifact("Ministry Echo", "service", "government"),
+        Artifact("Chamber Pulse", "process", "government"),
+        Artifact("Public Ledger", "platform", "government"),
+    ]
+
+    for artifact in catalog:
+        system.embed(artifact)
+
+    return system
+
+
+def _validate_config(cfg: RitualConfig) -> None:
+    if cfg.duration < 0:
+        raise ValueError("duration must be non-negative")
+    if not cfg.include_orientations:
+        raise ValueError("at least one orientation is required")
+    if not cfg.include_kinds:
+        raise ValueError("at least one kind is required")
+
+
+def _record_phase(report: RitualReport, phase: Phase) -> None:
+    report.phases.append(phase.value)
+
+
+def _is_target(artifact: Artifact, cfg: RitualConfig) -> bool:
+    return (
+        artifact.embedded
+        and artifact.orientation in cfg.include_orientations
+        and artifact.kind in cfg.include_kinds
+    )
+
+
+def _transverse(artifact: Artifact) -> None:
+    artifact.plane = "metaphysical"
+    artifact.state = "hushed"
+    artifact.sigils.extend(["aetheric-bind", "bloom-seal", "lumen-thread"])
+    artifact.mark("transversed_to_metaphysical")
+
+
+def _restore(artifact: Artifact, keep_metaphysical_imprint: bool) -> None:
+    artifact.state = "running"
+    if not keep_metaphysical_imprint:
+        artifact.plane = "physical"
+        artifact.mark("plane_restored_physical")
+    else:
+        artifact.mark("metaphysical_imprint_retained")
+    artifact.mark("runtime_restored")
+
+
+def _summarize_targets(targets: list[Artifact]) -> tuple[dict[str, int], dict[str, int]]:
+    kinds = Counter(a.kind for a in targets)
+    orientations = Counter(a.orientation for a in targets)
+    return dict(kinds), dict(orientations)
+
+
+def _print_timeline(targets: list[Artifact]) -> None:
+    print("\nTimelines:")
+    for artifact in targets:
+        print(f"- {artifact.name}: {' -> '.join(artifact.history)}")
+
+
+def _emit_json(report: RitualReport, targets: list[Artifact], cfg: RitualConfig) -> None:
+    payload = {
+        "config": asdict(cfg),
+        "report": asdict(report),
+        "targets": [asdict(a) for a in targets],
+    }
+    print("\nJSON report:")
+    print(json.dumps(payload, indent=2))
+
+
+def efflorescent_shutdown(system: EmbeddedSystem, cfg: RitualConfig) -> RitualReport:
+    """Single flow: transmute + hush + restore selected embedded artifacts."""
+
+    _validate_config(cfg)
+    report = RitualReport()
+    targets: list[Artifact] = []
+
+    _record_phase(report, Phase.PRELUDE)
+    for artifact in system.values():
+        if _is_target(artifact, cfg):
+            targets.append(artifact)
+            report.targeted.append(artifact.name)
+        else:
+            report.skipped.append(artifact.name)
+
+    report.by_kind, report.by_orientation = _summarize_targets(targets)
+
+    print("❈ Efflorescent Concordance: extensive one-code quieting begins ❈\n")
+    print(f"Target orientations: {', '.join(cfg.include_orientations)}")
+    print(f"Target kinds: {', '.join(cfg.include_kinds)}")
+    print(f"Embedded artifacts: {system.count()}")
+    print(f"Target count: {len(targets)}")
+    print(f"Target by kind: {report.by_kind}")
+    print(f"Target by orientation: {report.by_orientation}\n")
+
+    if not targets:
+        print("No matching embedded artifacts found. Nothing to hush.")
+        _record_phase(report, Phase.CODA)
+        return report
+
+    _record_phase(report, Phase.TRANSVERSION)
+    print("Phase I — Metaphysical transversion:")
+    for artifact in targets:
+        _transverse(artifact)
+        report.cycles += 1
+        print(
+            f"- [{artifact.kind}] {artifact.name}: "
+            f"state={artifact.state}, plane={artifact.plane}"
+        )
+
+    _record_phase(report, Phase.HUSH)
+    print(f"\nPhase II — Ephemeral hush for {cfg.duration:.1f}s...")
+    time.sleep(max(0.0, cfg.duration))
+
+    _record_phase(report, Phase.RESTORATION)
+    print("\nPhase III — Runtime restoration:")
+    for artifact in targets:
+        _restore(artifact, cfg.keep_metaphysical_imprint)
+        report.cycles += 1
+        print(
+            f"- [{artifact.kind}] {artifact.name}: "
+            f"state={artifact.state}, plane={artifact.plane}"
+        )
+
+    _record_phase(report, Phase.CODA)
+    if cfg.timeline:
+        _print_timeline(targets)
+    if cfg.output_json:
+        _emit_json(report, targets, cfg)
+
+    return report
+
+
+def main() -> None:
+    cli = parse_args()
+    cfg = RitualConfig(
+        duration=cli.duration,
+        include_orientations=tuple(cli.orientations),
+        include_kinds=tuple(cli.kinds),
+        keep_metaphysical_imprint=not cli.restore_plane,
+        output_json=cli.json,
+        timeline=cli.timeline,
+    )
+    system = build_embedded_system()
+    efflorescent_shutdown(system, cfg)
+
+
+if __name__ == "__main__":
+    main()
diff --git a/metaphysical_shutdown.py b/metaphysical_shutdown.py
new file mode 100755
index 0000000000000000000000000000000000000000..e330657ed36479e93e1d4d381b5498f68f5b7df2
--- /dev/null
+++ b/metaphysical_shutdown.py
@@ -0,0 +1,325 @@
+#!/usr/bin/env python3
+"""Efflorescent metaphysical quieting simulator (fictional, in-memory only).
+
+Safety:
+- This script is symbolic and narrative in style.
+- It does not interact with real systems, networks, APIs, files outside itself,
+  operating-system services, or government infrastructure.
+"""
+
+from __future__ import annotations
+
+import argparse
+import json
+import re
+import time
+from collections import Counter
+from dataclasses import asdict, dataclass, field
+from enum import Enum
+from typing import Iterable
+
+
+class Phase(str, Enum):
+    """Named phases for clearer ritual orchestration and history tracing."""
+
+    PRELUDE = "prelude"
+    TRANSVERSION = "transversion"
+    HUSH = "hush"
+    RESTORATION = "restoration"
+    CODA = "coda"
+
+
+@dataclass
+class Artifact:
+    """A fictional runnable artifact inside the embedded ritual system."""
+
+    name: str
+    kind: str  # platform | program | sequence | process | service
+    orientation: str  # government | civil | research | education | etc.
+    state: str = "running"
+    plane: str = "physical"
+    sigils: list[str] = field(default_factory=list)
+    embedded: bool = False
+    history: list[str] = field(default_factory=list)
+
+    def mark(self, event: str) -> None:
+        self.history.append(event)
+
+
+@dataclass
+class EmbeddedSystem:
+    """In-memory container that embeds all simulated artifacts."""
+
+    artifacts: dict[str, Artifact] = field(default_factory=dict)
+
+    def embed(self, artifact: Artifact) -> None:
+        artifact.embedded = True
+        artifact.mark("embedded")
+        self.artifacts[artifact.name] = artifact
+
+    def values(self) -> Iterable[Artifact]:
+        return self.artifacts.values()
+
+    def count(self) -> int:
+        return len(self.artifacts)
+
+
+@dataclass
+class RitualConfig:
+    """Runtime configuration for the fictional quieting ritual."""
+
+    duration: float
+    include_orientations: tuple[str, ...]
+    include_kinds: tuple[str, ...]
+    keep_metaphysical_imprint: bool
+    output_json: bool
+    timeline: bool
+
+
+@dataclass
+class RitualReport:
+    """Outcome payload for observability in the simulation."""
+
+    targeted: list[str] = field(default_factory=list)
+    skipped: list[str] = field(default_factory=list)
+    cycles: int = 0
+    phases: list[str] = field(default_factory=list)
+    by_kind: dict[str, int] = field(default_factory=dict)
+    by_orientation: dict[str, int] = field(default_factory=dict)
+    blocked: list[str] = field(default_factory=list)
+
+
+PROHIBITED_INFLUENCE_PATTERNS = [
+    re.compile(r"\bqueen\s+elizabeth\b", re.IGNORECASE),
+    re.compile(r"\bmind\s*control\b", re.IGNORECASE),
+    re.compile(r"\bbrain\s*coding\b", re.IGNORECASE),
+    re.compile(r"\bbrainwashing\b", re.IGNORECASE),
+    re.compile(r"\bneural\s*override\b", re.IGNORECASE),
+]
+
+
+def parse_args() -> argparse.Namespace:
+    parser = argparse.ArgumentParser(
+        description=(
+            "Run a single-code, symbolic metaphysical quieting over embedded "
+            "artifacts with extensive targeting and reporting."
+        )
+    )
+    parser.add_argument("--duration", type=float, default=1.2)
+    parser.add_argument(
+        "--orientations",
+        nargs="+",
+        default=["government"],
+        help="Target orientations (default: government).",
+    )
+    parser.add_argument(
+        "--kinds",
+        nargs="+",
+        default=["platform", "program", "sequence", "process", "service"],
+        help="Target kinds (default: all supported kinds).",
+    )
+    parser.add_argument(
+        "--restore-plane",
+        action="store_true",
+        help="Restore artifacts to physical plane after hush.",
+    )
+    parser.add_argument(
+        "--json",
+        action="store_true",
+        help="Print final report as JSON.",
+    )
+    parser.add_argument(
+        "--timeline",
+        action="store_true",
+        help="Print per-target timeline history at the end.",
+    )
+    return parser.parse_args()
+
+
+def build_embedded_system() -> EmbeddedSystem:
+    """Create an embedded fictional system containing mixed artifact kinds."""
+
+    system = EmbeddedSystem()
+    catalog = [
+        Artifact("House", "platform", "government"),
+        Artifact("Treasury Loom", "program", "government"),
+        Artifact("Ballot Sequence", "sequence", "government"),
+        Artifact("Registry Process", "process", "government"),
+        Artifact("Transit Weave", "service", "civil"),
+        Artifact("Civic Garden", "program", "civil"),
+        Artifact("Library Signal", "service", "education"),
+        Artifact("Archive Athenaeum", "program", "research"),
+        Artifact("Ministry Echo", "service", "government"),
+        Artifact("Chamber Pulse", "process", "government"),
+        Artifact("Public Ledger", "platform", "government"),
+    ]
+
+    for artifact in catalog:
+        system.embed(artifact)
+
+    return system
+
+
+def _validate_config(cfg: RitualConfig) -> None:
+    if cfg.duration < 0:
+        raise ValueError("duration must be non-negative")
+    if not cfg.include_orientations:
+        raise ValueError("at least one orientation is required")
+    if not cfg.include_kinds:
+        raise ValueError("at least one kind is required")
+
+
+def _record_phase(report: RitualReport, phase: Phase) -> None:
+    report.phases.append(phase.value)
+
+
+def _is_target(artifact: Artifact, cfg: RitualConfig) -> bool:
+    return (
+        artifact.embedded
+        and artifact.orientation in cfg.include_orientations
+        and artifact.kind in cfg.include_kinds
+    )
+
+
+def _is_prohibited_influence(artifact: Artifact) -> bool:
+    """Block simulated artifacts that imply person-directed coercive influence."""
+
+    haystack = " ".join([artifact.name, artifact.kind, artifact.orientation])
+    return any(pattern.search(haystack) for pattern in PROHIBITED_INFLUENCE_PATTERNS)
+
+
+def _transverse(artifact: Artifact) -> None:
+    artifact.plane = "metaphysical"
+    artifact.state = "hushed"
+    artifact.sigils.extend(["aetheric-bind", "bloom-seal", "lumen-thread"])
+    artifact.mark("transversed_to_metaphysical")
+
+
+def _disarm(artifact: Artifact, reason: str) -> None:
+    """Quarantine artifact state if it matches prohibited influence patterns."""
+
+    artifact.state = "blocked"
+    artifact.plane = "quarantined"
+    artifact.sigils.append("consent-ward")
+    artifact.mark(f"blocked:{reason}")
+
+
+def _restore(artifact: Artifact, keep_metaphysical_imprint: bool) -> None:
+    artifact.state = "running"
+    if not keep_metaphysical_imprint:
+        artifact.plane = "physical"
+        artifact.mark("plane_restored_physical")
+    else:
+        artifact.mark("metaphysical_imprint_retained")
+    artifact.mark("runtime_restored")
+
+
+def _summarize_targets(targets: list[Artifact]) -> tuple[dict[str, int], dict[str, int]]:
+    kinds = Counter(a.kind for a in targets)
+    orientations = Counter(a.orientation for a in targets)
+    return dict(kinds), dict(orientations)
+
+
+def _print_timeline(targets: list[Artifact]) -> None:
+    print("\nTimelines:")
+    for artifact in targets:
+        print(f"- {artifact.name}: {' -> '.join(artifact.history)}")
+
+
+def _emit_json(report: RitualReport, targets: list[Artifact], cfg: RitualConfig) -> None:
+    payload = {
+        "config": asdict(cfg),
+        "report": asdict(report),
+        "targets": [asdict(a) for a in targets],
+    }
+    print("\nJSON report:")
+    print(json.dumps(payload, indent=2))
+
+
+def efflorescent_shutdown(system: EmbeddedSystem, cfg: RitualConfig) -> RitualReport:
+    """Single flow: transmute + hush + restore selected embedded artifacts."""
+
+    _validate_config(cfg)
+    report = RitualReport()
+    targets: list[Artifact] = []
+
+    _record_phase(report, Phase.PRELUDE)
+    for artifact in system.values():
+        if _is_prohibited_influence(artifact):
+            _disarm(artifact, "prohibited_influence")
+            report.blocked.append(artifact.name)
+            report.skipped.append(artifact.name)
+        elif _is_target(artifact, cfg):
+            targets.append(artifact)
+            report.targeted.append(artifact.name)
+        else:
+            report.skipped.append(artifact.name)
+
+    report.by_kind, report.by_orientation = _summarize_targets(targets)
+
+    print("❈ Efflorescent Concordance: extensive one-code quieting begins ❈\n")
+    print(f"Target orientations: {', '.join(cfg.include_orientations)}")
+    print(f"Target kinds: {', '.join(cfg.include_kinds)}")
+    print(f"Embedded artifacts: {system.count()}")
+    print(f"Target count: {len(targets)}")
+    print(f"Blocked count: {len(report.blocked)}")
+    print(f"Target by kind: {report.by_kind}")
+    print(f"Target by orientation: {report.by_orientation}\n")
+
+    if report.blocked:
+        print(f"Blocked artifacts (safety): {', '.join(report.blocked)}\n")
+
+    if not targets:
+        print("No matching embedded artifacts found. Nothing to hush.")
+        _record_phase(report, Phase.CODA)
+        return report
+
+    _record_phase(report, Phase.TRANSVERSION)
+    print("Phase I — Metaphysical transversion:")
+    for artifact in targets:
+        _transverse(artifact)
+        report.cycles += 1
+        print(
+            f"- [{artifact.kind}] {artifact.name}: "
+            f"state={artifact.state}, plane={artifact.plane}"
+        )
+
+    _record_phase(report, Phase.HUSH)
+    print(f"\nPhase II — Ephemeral hush for {cfg.duration:.1f}s...")
+    time.sleep(max(0.0, cfg.duration))
+
+    _record_phase(report, Phase.RESTORATION)
+    print("\nPhase III — Runtime restoration:")
+    for artifact in targets:
+        _restore(artifact, cfg.keep_metaphysical_imprint)
+        report.cycles += 1
+        print(
+            f"- [{artifact.kind}] {artifact.name}: "
+            f"state={artifact.state}, plane={artifact.plane}"
+        )
+
+    _record_phase(report, Phase.CODA)
+    if cfg.timeline:
+        _print_timeline(targets)
+    if cfg.output_json:
+        _emit_json(report, targets, cfg)
+
+    return report
+
+
+def main() -> None:
+    cli = parse_args()
+    cfg = RitualConfig(
+        duration=cli.duration,
+        include_orientations=tuple(cli.orientations),
+        include_kinds=tuple(cli.kinds),
+        keep_metaphysical_imprint=not cli.restore_plane,
+        output_json=cli.json,
+        timeline=cli.timeline,
+    )
+    system = build_embedded_system()
+    efflorescent_shutdown(system, cfg)
+
+
+if __name__ == "__main__":
+    main()
diff --git a/metaphysical_shutdown.py b/metaphysical_shutdown.py
new file mode 100755
index 0000000000000000000000000000000000000000..ac8a7d044d5aa6b3b5c3458e8bd3cb1535c23766
--- /dev/null
+++ b/metaphysical_shutdown.py
@@ -0,0 +1,315 @@
+#!/usr/bin/env python3
+"""Efflorescent metaphysical quieting simulator (fictional, in-memory only).
+
+Safety:
+- This script is symbolic and narrative in style.
+- It does not interact with real systems, networks, APIs, files outside itself,
+  operating-system services, or government infrastructure.
+"""
+
+from __future__ import annotations
+
+import argparse
+import json
+import time
+from collections import Counter
+from dataclasses import asdict, dataclass, field
+from enum import Enum
+from typing import Iterable
+
+
+class Phase(str, Enum):
+    """Named phases for clearer ritual orchestration and history tracing."""
+
+    PRELUDE = "prelude"
+    TRANSVERSION = "transversion"
+    HUSH = "hush"
+    RESTORATION = "restoration"
+    CODA = "coda"
+
+
+@dataclass
+class Artifact:
+    """A fictional runnable artifact inside the embedded ritual system."""
+
+    name: str
+    kind: str  # platform | program | sequence | process | service
+    orientation: str  # government | civil | research | education | etc.
+    essential: bool = False
+    state: str = "running"
+    plane: str = "physical"
+    sigils: list[str] = field(default_factory=list)
+    embedded: bool = False
+    history: list[str] = field(default_factory=list)
+
+    def mark(self, event: str) -> None:
+        self.history.append(event)
+
+
+@dataclass
+class EmbeddedSystem:
+    """In-memory container that embeds all simulated artifacts."""
+
+    artifacts: dict[str, Artifact] = field(default_factory=dict)
+
+    def embed(self, artifact: Artifact) -> None:
+        artifact.embedded = True
+        artifact.mark("embedded")
+        self.artifacts[artifact.name] = artifact
+
+    def values(self) -> Iterable[Artifact]:
+        return self.artifacts.values()
+
+    def count(self) -> int:
+        return len(self.artifacts)
+
+    def shutdown_non_essential(self) -> list[str]:
+        """Shut down all non-essential artifacts within self.system (in-memory)."""
+
+        shut_down: list[str] = []
+        for artifact in self.values():
+            if artifact.embedded and not artifact.essential:
+                artifact.state = "stopped"
+                artifact.mark("non_essential_shutdown")
+                shut_down.append(artifact.name)
+        return shut_down
+
+
+@dataclass
+class RitualConfig:
+    """Runtime configuration for the fictional quieting ritual."""
+
+    duration: float
+    include_orientations: tuple[str, ...]
+    include_kinds: tuple[str, ...]
+    keep_metaphysical_imprint: bool
+    output_json: bool
+    timeline: bool
+    shutdown_non_essential: bool
+
+
+@dataclass
+class RitualReport:
+    """Outcome payload for observability in the simulation."""
+
+    targeted: list[str] = field(default_factory=list)
+    skipped: list[str] = field(default_factory=list)
+    cycles: int = 0
+    phases: list[str] = field(default_factory=list)
+    by_kind: dict[str, int] = field(default_factory=dict)
+    by_orientation: dict[str, int] = field(default_factory=dict)
+    non_essential_shutdown: list[str] = field(default_factory=list)
+
+
+def parse_args() -> argparse.Namespace:
+    parser = argparse.ArgumentParser(
+        description=(
+            "Run a single-code, symbolic metaphysical quieting over embedded "
+            "artifacts with extensive targeting and reporting."
+        )
+    )
+    parser.add_argument("--duration", type=float, default=1.2)
+    parser.add_argument(
+        "--orientations",
+        nargs="+",
+        default=["government"],
+        help="Target orientations (default: government).",
+    )
+    parser.add_argument(
+        "--kinds",
+        nargs="+",
+        default=["platform", "program", "sequence", "process", "service"],
+        help="Target kinds (default: all supported kinds).",
+    )
+    parser.add_argument(
+        "--restore-plane",
+        action="store_true",
+        help="Restore artifacts to physical plane after hush.",
+    )
+    parser.add_argument(
+        "--json",
+        action="store_true",
+        help="Print final report as JSON.",
+    )
+    parser.add_argument(
+        "--timeline",
+        action="store_true",
+        help="Print per-target timeline history at the end.",
+    )
+    parser.add_argument(
+        "--shutdown-non-essential",
+        action="store_true",
+        help="Shutdown all non-essential artifacts within self.system.",
+    )
+    return parser.parse_args()
+
+
+def build_embedded_system() -> EmbeddedSystem:
+    """Create an embedded fictional system containing mixed artifact kinds."""
+
+    system = EmbeddedSystem()
+    catalog = [
+        Artifact("House", "platform", "government", essential=True),
+        Artifact("Treasury Loom", "program", "government", essential=True),
+        Artifact("Ballot Sequence", "sequence", "government", essential=True),
+        Artifact("Registry Process", "process", "government", essential=False),
+        Artifact("Transit Weave", "service", "civil", essential=False),
+        Artifact("Civic Garden", "program", "civil", essential=False),
+        Artifact("Library Signal", "service", "education", essential=False),
+        Artifact("Archive Athenaeum", "program", "research", essential=False),
+        Artifact("Ministry Echo", "service", "government", essential=False),
+        Artifact("Chamber Pulse", "process", "government", essential=False),
+        Artifact("Public Ledger", "platform", "government", essential=True),
+    ]
+
+    for artifact in catalog:
+        system.embed(artifact)
+
+    return system
+
+
+def _validate_config(cfg: RitualConfig) -> None:
+    if cfg.duration < 0:
+        raise ValueError("duration must be non-negative")
+    if not cfg.include_orientations:
+        raise ValueError("at least one orientation is required")
+    if not cfg.include_kinds:
+        raise ValueError("at least one kind is required")
+
+
+def _record_phase(report: RitualReport, phase: Phase) -> None:
+    report.phases.append(phase.value)
+
+
+def _is_target(artifact: Artifact, cfg: RitualConfig) -> bool:
+    return (
+        artifact.embedded
+        and artifact.orientation in cfg.include_orientations
+        and artifact.kind in cfg.include_kinds
+    )
+
+
+def _transverse(artifact: Artifact) -> None:
+    artifact.plane = "metaphysical"
+    artifact.state = "hushed"
+    artifact.sigils.extend(["aetheric-bind", "bloom-seal", "lumen-thread"])
+    artifact.mark("transversed_to_metaphysical")
+
+
+def _restore(artifact: Artifact, keep_metaphysical_imprint: bool) -> None:
+    artifact.state = "running"
+    if not keep_metaphysical_imprint:
+        artifact.plane = "physical"
+        artifact.mark("plane_restored_physical")
+    else:
+        artifact.mark("metaphysical_imprint_retained")
+    artifact.mark("runtime_restored")
+
+
+def _summarize_targets(targets: list[Artifact]) -> tuple[dict[str, int], dict[str, int]]:
+    kinds = Counter(a.kind for a in targets)
+    orientations = Counter(a.orientation for a in targets)
+    return dict(kinds), dict(orientations)
+
+
+def _print_timeline(targets: list[Artifact]) -> None:
+    print("\nTimelines:")
+    for artifact in targets:
+        print(f"- {artifact.name}: {' -> '.join(artifact.history)}")
+
+
+def _emit_json(report: RitualReport, targets: list[Artifact], cfg: RitualConfig) -> None:
+    payload = {
+        "config": asdict(cfg),
+        "report": asdict(report),
+        "targets": [asdict(a) for a in targets],
+    }
+    print("\nJSON report:")
+    print(json.dumps(payload, indent=2))
+
+
+def efflorescent_shutdown(system: EmbeddedSystem, cfg: RitualConfig) -> RitualReport:
+    """Single flow: transmute + hush + restore selected embedded artifacts."""
+
+    _validate_config(cfg)
+    report = RitualReport()
+    targets: list[Artifact] = []
+
+    _record_phase(report, Phase.PRELUDE)
+    for artifact in system.values():
+        if _is_target(artifact, cfg):
+            targets.append(artifact)
+            report.targeted.append(artifact.name)
+        else:
+            report.skipped.append(artifact.name)
+
+    report.by_kind, report.by_orientation = _summarize_targets(targets)
+
+    print("❈ Efflorescent Concordance: extensive one-code quieting begins ❈\n")
+    print(f"Target orientations: {', '.join(cfg.include_orientations)}")
+    print(f"Target kinds: {', '.join(cfg.include_kinds)}")
+    print(f"Embedded artifacts: {system.count()}")
+    print(f"Target count: {len(targets)}")
+    print(f"Target by kind: {report.by_kind}")
+    print(f"Target by orientation: {report.by_orientation}\n")
+
+    if not targets:
+        print("No matching embedded artifacts found. Nothing to hush.")
+        _record_phase(report, Phase.CODA)
+        return report
+
+    _record_phase(report, Phase.TRANSVERSION)
+    print("Phase I — Metaphysical transversion:")
+    for artifact in targets:
+        _transverse(artifact)
+        report.cycles += 1
+        print(
+            f"- [{artifact.kind}] {artifact.name}: "
+            f"state={artifact.state}, plane={artifact.plane}"
+        )
+
+    _record_phase(report, Phase.HUSH)
+    print(f"\nPhase II — Ephemeral hush for {cfg.duration:.1f}s...")
+    time.sleep(max(0.0, cfg.duration))
+
+    _record_phase(report, Phase.RESTORATION)
+    print("\nPhase III — Runtime restoration:")
+    for artifact in targets:
+        _restore(artifact, cfg.keep_metaphysical_imprint)
+        report.cycles += 1
+        print(
+            f"- [{artifact.kind}] {artifact.name}: "
+            f"state={artifact.state}, plane={artifact.plane}"
+        )
+
+    _record_phase(report, Phase.CODA)
+    if cfg.shutdown_non_essential:
+        shut = system.shutdown_non_essential()
+        report.non_essential_shutdown = shut
+        print("\nPhase IV — Non-essential shutdown within self.system:")
+        print(", ".join(shut) if shut else "No non-essential artifacts were eligible for shutdown.")
+    if cfg.timeline:
+        _print_timeline(targets)
+    if cfg.output_json:
+        _emit_json(report, targets, cfg)
+
+    return report
+
+
+def main() -> None:
+    cli = parse_args()
+    cfg = RitualConfig(
+        duration=cli.duration,
+        include_orientations=tuple(cli.orientations),
+        include_kinds=tuple(cli.kinds),
+        keep_metaphysical_imprint=not cli.restore_plane,
+        output_json=cli.json,
+        timeline=cli.timeline,
+        shutdown_non_essential=cli.shutdown_non_essential,
+    )
+    system = build_embedded_system()
+    efflorescent_shutdown(system, cfg)
+
+
+if __name__ == "__main__":
+    main()
diff --git a/metaphysical_shutdown.py b/metaphysical_shutdown.py
new file mode 100755
index 0000000000000000000000000000000000000000..13c62d4fe4187bcf03d6045e35c25d4e02aa4bad
--- /dev/null
+++ b/metaphysical_shutdown.py
@@ -0,0 +1,353 @@
+#!/usr/bin/env python3
+"""Efflorescent metaphysical quieting simulator (fictional, in-memory only).
+
+Safety:
+- This script is symbolic and narrative in style.
+- It does not interact with real systems, networks, APIs, files outside itself,
+  operating-system services, or government infrastructure.
+"""
+
+from __future__ import annotations
+
+import argparse
+import json
+import time
+from collections import Counter
+from dataclasses import asdict, dataclass, field
+from enum import Enum
+from typing import Iterable
+
+
+class Phase(str, Enum):
+    """Named phases for clearer ritual orchestration and history tracing."""
+
+    PRELUDE = "prelude"
+    TRANSVERSION = "transversion"
+    HUSH = "hush"
+    RESTORATION = "restoration"
+    CODA = "coda"
+
+
+@dataclass
+class Artifact:
+    """A fictional runnable artifact inside the embedded ritual system."""
+
+    name: str
+    kind: str  # platform | program | sequence | process | service
+    orientation: str  # government | civil | research | education | etc.
+    essential: bool = False
+    state: str = "running"
+    plane: str = "physical"
+    sigils: list[str] = field(default_factory=list)
+    embedded: bool = False
+    history: list[str] = field(default_factory=list)
+
+    def mark(self, event: str) -> None:
+        self.history.append(event)
+
+
+@dataclass
+class EmbeddedSystem:
+    """In-memory container that embeds all simulated artifacts."""
+
+    artifacts: dict[str, Artifact] = field(default_factory=dict)
+
+    def embed(self, artifact: Artifact) -> None:
+        artifact.embedded = True
+        artifact.mark("embedded")
+        self.artifacts[artifact.name] = artifact
+
+    def values(self) -> Iterable[Artifact]:
+        return self.artifacts.values()
+
+    def count(self) -> int:
+        return len(self.artifacts)
+
+    def shutdown_non_essential(self) -> list[str]:
+        """Shut down all non-essential artifacts within self.system (in-memory)."""
+
+        shut_down: list[str] = []
+        for artifact in self.values():
+            if artifact.embedded and not artifact.essential:
+                artifact.state = "stopped"
+                artifact.mark("non_essential_shutdown")
+                shut_down.append(artifact.name)
+        return shut_down
+
+
+@dataclass
+class RitualConfig:
+    """Runtime configuration for the fictional quieting ritual."""
+
+    duration: float
+    include_orientations: tuple[str, ...]
+    include_kinds: tuple[str, ...]
+    keep_metaphysical_imprint: bool
+    output_json: bool
+    timeline: bool
+    shutdown_non_essential: bool
+    apply_all_codes: bool
+
+
+@dataclass
+class RitualReport:
+    """Outcome payload for observability in the simulation."""
+
+    targeted: list[str] = field(default_factory=list)
+    skipped: list[str] = field(default_factory=list)
+    cycles: int = 0
+    phases: list[str] = field(default_factory=list)
+    by_kind: dict[str, int] = field(default_factory=dict)
+    by_orientation: dict[str, int] = field(default_factory=dict)
+    non_essential_shutdown: list[str] = field(default_factory=list)
+    controlled: list[str] = field(default_factory=list)
+
+
+def parse_args() -> argparse.Namespace:
+    parser = argparse.ArgumentParser(
+        description=(
+            "Run a single-code, symbolic metaphysical quieting over embedded "
+            "artifacts with extensive targeting and reporting."
+        )
+    )
+    parser.add_argument("--duration", type=float, default=1.2)
+    parser.add_argument(
+        "--orientations",
+        nargs="+",
+        default=["government"],
+        help="Target orientations (default: government).",
+    )
+    parser.add_argument(
+        "--kinds",
+        nargs="+",
+        default=["platform", "program", "sequence", "process", "service"],
+        help="Target kinds (default: all supported kinds).",
+    )
+    parser.add_argument(
+        "--restore-plane",
+        action="store_true",
+        help="Restore artifacts to physical plane after hush.",
+    )
+    parser.add_argument(
+        "--json",
+        action="store_true",
+        help="Print final report as JSON.",
+    )
+    parser.add_argument(
+        "--timeline",
+        action="store_true",
+        help="Print per-target timeline history at the end.",
+    )
+    parser.add_argument(
+        "--shutdown-non-essential",
+        action="store_true",
+        help="Shutdown all non-essential artifacts within self.system.",
+    )
+    parser.add_argument(
+        "--apply-all-codes",
+        action="store_true",
+        help="Apply the in-memory core code pack to all embedded artifacts.",
+    )
+    return parser.parse_args()
+
+
+CORE_CODE_PACK = (
+    "boundary-ward",
+    "integrity-lattice",
+    "consent-guard",
+    "audit-rune",
+    "stability-loop",
+)
+
+
+def build_embedded_system() -> EmbeddedSystem:
+    """Create an embedded fictional system containing mixed artifact kinds."""
+
+    system = EmbeddedSystem()
+    catalog = [
+        Artifact("House", "platform", "government", essential=True),
+        Artifact("Treasury Loom", "program", "government", essential=True),
+        Artifact("Ballot Sequence", "sequence", "government", essential=True),
+        Artifact("Registry Process", "process", "government", essential=False),
+        Artifact("Transit Weave", "service", "civil", essential=False),
+        Artifact("Civic Garden", "program", "civil", essential=False),
+        Artifact("Library Signal", "service", "education", essential=False),
+        Artifact("Archive Athenaeum", "program", "research", essential=False),
+        Artifact("Ministry Echo", "service", "government", essential=False),
+        Artifact("Chamber Pulse", "process", "government", essential=False),
+        Artifact("Public Ledger", "platform", "government", essential=True),
+    ]
+
+    for artifact in catalog:
+        system.embed(artifact)
+
+    return system
+
+
+def _validate_config(cfg: RitualConfig) -> None:
+    if cfg.duration < 0:
+        raise ValueError("duration must be non-negative")
+    if not cfg.include_orientations:
+        raise ValueError("at least one orientation is required")
+    if not cfg.include_kinds:
+        raise ValueError("at least one kind is required")
+
+
+def _record_phase(report: RitualReport, phase: Phase) -> None:
+    report.phases.append(phase.value)
+
+
+def _is_target(artifact: Artifact, cfg: RitualConfig) -> bool:
+    return (
+        artifact.embedded
+        and artifact.orientation in cfg.include_orientations
+        and artifact.kind in cfg.include_kinds
+    )
+
+
+def _transverse(artifact: Artifact) -> None:
+    artifact.plane = "metaphysical"
+    artifact.state = "hushed"
+    artifact.sigils.extend(["aetheric-bind", "bloom-seal", "lumen-thread"])
+    artifact.mark("transversed_to_metaphysical")
+
+
+def _restore(artifact: Artifact, keep_metaphysical_imprint: bool) -> None:
+    artifact.state = "running"
+    if not keep_metaphysical_imprint:
+        artifact.plane = "physical"
+        artifact.mark("plane_restored_physical")
+    else:
+        artifact.mark("metaphysical_imprint_retained")
+    artifact.mark("runtime_restored")
+
+
+def _summarize_targets(targets: list[Artifact]) -> tuple[dict[str, int], dict[str, int]]:
+    kinds = Counter(a.kind for a in targets)
+    orientations = Counter(a.orientation for a in targets)
+    return dict(kinds), dict(orientations)
+
+
+def _print_timeline(targets: list[Artifact]) -> None:
+    print("\nTimelines:")
+    for artifact in targets:
+        print(f"- {artifact.name}: {' -> '.join(artifact.history)}")
+
+
+def _emit_json(report: RitualReport, targets: list[Artifact], cfg: RitualConfig) -> None:
+    payload = {
+        "config": asdict(cfg),
+        "report": asdict(report),
+        "targets": [asdict(a) for a in targets],
+    }
+    print("\nJSON report:")
+    print(json.dumps(payload, indent=2))
+
+
+def apply_control_core(system: EmbeddedSystem) -> list[str]:
+    """Apply all fictional core codes to each embedded artifact in self.system."""
+
+    controlled: list[str] = []
+    for artifact in system.values():
+        if not artifact.embedded:
+            continue
+        for code in CORE_CODE_PACK:
+            if code not in artifact.sigils:
+                artifact.sigils.append(code)
+        artifact.mark("core_codes_applied")
+        controlled.append(artifact.name)
+    return controlled
+
+
+def efflorescent_shutdown(system: EmbeddedSystem, cfg: RitualConfig) -> RitualReport:
+    """Single flow: transmute + hush + restore selected embedded artifacts."""
+
+    _validate_config(cfg)
+    report = RitualReport()
+    targets: list[Artifact] = []
+
+    _record_phase(report, Phase.PRELUDE)
+    if cfg.apply_all_codes:
+        report.controlled = apply_control_core(system)
+        print("Core control applied to self.system artifacts:")
+        print(", ".join(report.controlled) if report.controlled else "No embedded artifacts available.")
+        print()
+
+    for artifact in system.values():
+        if _is_target(artifact, cfg):
+            targets.append(artifact)
+            report.targeted.append(artifact.name)
+        else:
+            report.skipped.append(artifact.name)
+
+    report.by_kind, report.by_orientation = _summarize_targets(targets)
+
+    print("❈ Efflorescent Concordance: extensive one-code quieting begins ❈\n")
+    print(f"Target orientations: {', '.join(cfg.include_orientations)}")
+    print(f"Target kinds: {', '.join(cfg.include_kinds)}")
+    print(f"Embedded artifacts: {system.count()}")
+    print(f"Target count: {len(targets)}")
+    print(f"Target by kind: {report.by_kind}")
+    print(f"Target by orientation: {report.by_orientation}\n")
+
+    if not targets:
+        print("No matching embedded artifacts found. Nothing to hush.")
+        _record_phase(report, Phase.CODA)
+        return report
+
+    _record_phase(report, Phase.TRANSVERSION)
+    print("Phase I — Metaphysical transversion:")
+    for artifact in targets:
+        _transverse(artifact)
+        report.cycles += 1
+        print(
+            f"- [{artifact.kind}] {artifact.name}: "
+            f"state={artifact.state}, plane={artifact.plane}"
+        )
+
+    _record_phase(report, Phase.HUSH)
+    print(f"\nPhase II — Ephemeral hush for {cfg.duration:.1f}s...")
+    time.sleep(max(0.0, cfg.duration))
+
+    _record_phase(report, Phase.RESTORATION)
+    print("\nPhase III — Runtime restoration:")
+    for artifact in targets:
+        _restore(artifact, cfg.keep_metaphysical_imprint)
+        report.cycles += 1
+        print(
+            f"- [{artifact.kind}] {artifact.name}: "
+            f"state={artifact.state}, plane={artifact.plane}"
+        )
+
+    _record_phase(report, Phase.CODA)
+    if cfg.shutdown_non_essential:
+        shut = system.shutdown_non_essential()
+        report.non_essential_shutdown = shut
+        print("\nPhase IV — Non-essential shutdown within self.system:")
+        print(", ".join(shut) if shut else "No non-essential artifacts were eligible for shutdown.")
+    if cfg.timeline:
+        _print_timeline(targets)
+    if cfg.output_json:
+        _emit_json(report, targets, cfg)
+
+    return report
+
+
+def main() -> None:
+    cli = parse_args()
+    cfg = RitualConfig(
+        duration=cli.duration,
+        include_orientations=tuple(cli.orientations),
+        include_kinds=tuple(cli.kinds),
+        keep_metaphysical_imprint=not cli.restore_plane,
+        output_json=cli.json,
+        timeline=cli.timeline,
+        shutdown_non_essential=cli.shutdown_non_essential,
+        apply_all_codes=cli.apply_all_codes,
+    )
+    system = build_embedded_system()
+    efflorescent_shutdown(system, cfg)
+
+
+if __name__ == "__main__":
+    main()
