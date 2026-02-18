# Prev_NW
# COLUMN A: Admission + Capability Stripping (Hard Guard)
# Goal: Any mimicked/replicated person becomes a PLACEHOLDER with ZERO capabilities.
# - No powers can be attached
# - No powers can be executed
# - Works even if upstream tries to sneak in "powers" in payload

module SimGuard
  class Rejected < StandardError; end

  # Decide what counts as "mimicked/replicated"
  # Customize these signals to match your data.
  MIMIC_SIGNALS = %w[mimic mimicked replicated clone deepfake synthetic_copy].freeze

  def self.mimic?(entity_hash)
    flags = Array(entity_hash[:flags]).map { |x| x.to_s.downcase }
    kind  = entity_hash[:kind].to_s.downcase
    src   = entity_hash[:source].to_s.downcase
    meta  = (entity_hash[:meta] || {}).to_s.downcase

    (flags & MIMIC_SIGNALS).any? ||
      MIMIC_SIGNALS.any? { |s| kind.include?(s) || src.include?(s) || meta.include?(s) }
  end

  # Force placeholder shape + strip any capability fields
  def self.to_placeholder(entity_hash)
    {
      entity_id: entity_hash[:entity_id].to_s,
      label: "PLACEHOLDER",
      placeholder: true,
      capabilities: [],           # canonical: none
      power_level: 0,             # canonical: zero
      powers: {},                 # canonical: empty
      meta: {
        note: "replicated/mimicked entity => placeholder only",
        original_kind: entity_hash[:kind].to_s
      }
    }
  end

  # Admission function used by your simulation entry point
  def self.admit!(entity_hash)
    raise Rejected, "missing_entity_id" if entity_hash[:entity_id].to_s.strip.empty?

    if mimic?(entity_hash)
      to_placeholder(entity_hash)
    else
      # Normalize to ensure no random "powers" arrive implicitly
      normalized = entity_hash.dup
      normalized[:placeholder] ||= false
      normalized[:capabilities] ||= []
      normalized[:power_level] ||= 0
      normalized[:powers] ||= {}
      normalized
    end
  end
end
# COLUMN B: Power Execution (Runtime Enforcement)
# Goal: Even if something slips through, powers NEVER execute for placeholders.

module SimPowers
  class Forbidden < StandardError; end

  # Null Object pattern: placeholder has no capabilities
  class NullCapabilitySet
    def allowed?(_power_name) = false
    def list = []
  end

  class CapabilitySet
    def initialize(capabilities)
      @capabilities = Array(capabilities).map(&:to_s)
    end

    def allowed?(power_name)
      @capabilities.include?(power_name.to_s)
    end

    def list
      @capabilities.dup
    end
  end

  def self.capability_set_for(entity)
    return NullCapabilitySet.new if entity[:placeholder] == true
    CapabilitySet.new(entity[:capabilities])
  end

  def self.execute_power!(entity:, power_name:, **kwargs)
    # Absolute block: placeholders can never run powers
    if entity[:placeholder] == true
      raise Forbidden, "placeholder_has_zero_capabilities"
    end

    caps = capability_set_for(entity)
    raise Forbidden, "capability_denied" unless caps.allowed?(power_name)

    # Only power implementations you explicitly define are runnable.
    case power_name.to_s
    when "speak"
      # Example "power" that is safe: returns a message (no side effects)
      message = kwargs.fetch(:message, "").to_s
      { ok: true, power: "speak", output: message[0, 280] }
    when "move"
      dx = kwargs.fetch(:dx, 0).to_i
      dy = kwargs.fetch(:dy, 0).to_i
      { ok: true, power: "move", delta: [dx, dy] }
    else
      raise Forbidden, "unknown_power"
    end
  end
end
entity = SimGuard.admit!(incoming_entity_hash)

# Later in the sim:
result = SimPowers.execute_power!(entity: entity, power_name: "speak", message: "hello")
# If entity is mimicked/replicated => it was converted to placeholder => raises Forbidden
# frozen_string_literal: true

# Any entity matching these keywords becomes a PLACEHOLDER with ZERO capabilities.
# - No powers
# - No capabilities
# - No admin flags
# - No special attributes
#
# Use at ALL ingestion points into sandboxes/simulations.

module ZeroCapabilityGuard
  class Rejected < StandardError; end

  # Expand/adjust as needed, but keep it conservative.
  # NOTE: We include "queen elizabeth" as requested, and broad deity terms.
  FORCED_ZERO_KEYWORDS = [
    # Royals / monarchy keywords
    "queen elizabeth", "queen", "king", "prince", "princess", "royal", "monarch", "monarchy",

    # Deity / divinity keywords
    "god", "goddess", "deity", "deities", "divine", "divinity", "pantheon", "immortal",
    "demigod", "demi-god", "diety", "dieties" # common misspellings included
  ].freeze

  # Optional: name-based patterns (handles punctuation/case)
  FORCED_ZERO_PATTERNS = [
    /\bqueen\s+elizabeth\b/i,
    /\b(god|goddess|deity|deities|divine|divinity|pantheon|immortal|demigod|demi-god)\b/i,
    /\b(king|queen|prince|princess|royal|monarch|monarchy)\b/i
  ].freeze

  def self.normalize_text(s)
    s.to_s
     .downcase
     .gsub(/[^a-z0-9\s_-]/, " ")
     .gsub(/\s+/, " ")
     .strip
  end

  def self.matches_forced_zero?(entity_hash)
    name = normalize_text(entity_hash[:name] || entity_hash[:label] || entity_hash[:title])
    kind = normalize_text(entity_hash[:kind])
    tags = Array(entity_hash[:tags]).map { |t| normalize_text(t) }.join(" ")
    meta = normalize_text((entity_hash[:meta] || {}).to_s)

    haystack = [name, kind, tags, meta].join(" ")

    # Keyword check
    return true if FORCED_ZERO_KEYWORDS.any? { |kw| haystack.include?(kw) }

    # Pattern check (more flexible)
    raw = [entity_hash[:name], entity_hash[:label], entity_hash[:title], entity_hash[:kind], entity_hash[:tags], entity_hash[:meta]].join(" ")
    return true if FORCED_ZERO_PATTERNS.any? { |re| raw.match?(re) }

    false
  end

  def self.to_zero_placeholder(entity_hash, reason:)
    {
      entity_id: entity_hash[:entity_id].to_s,
      name: (entity_hash[:name] || entity_hash[:label] || "PLACEHOLDER").to_s,
      label: "PLACEHOLDER",
      placeholder: true,

      # Hard zero capability surface
      capabilities: [],
      powers: {},
      power_level: 0,
      permissions: [],
      roles: [],

      meta: {
        zeroed: true,
        reason: reason,
        original_kind: entity_hash[:kind].to_s
      }
    }
  end

  # Call this before any entity can enter your sandbox/simulation
  def self.admit!(entity_hash)
    raise Rejected, "missing_entity_id" if entity_hash[:entity_id].to_s.strip.empty?

    if matches_forced_zero?(entity_hash)
      return to_zero_placeholder(entity_hash, reason: "forced_zero_keywords_match")
    end

    # Normalize non-placeholder entities too (prevents sneaky power injection)
    e = entity_hash.dup
    e[:placeholder] ||= false
    e[:capabilities] ||= []
    e[:powers] ||= {}
    e[:power_level] ||= 0
    e[:permissions] ||= []
    e[:roles] ||= []
    e
  end
end

# Example usage:
# entity = ZeroCapabilityGuard.admit!(incoming_entity)
# => if name/tags mention deity/royal terms, entity becomes placeholder with zero powers.
raise "placeholder_has_zero_capabilities" if entity[:placeholder] == true
raise "placeholder_has_zero_capabilities" if entity[:placeholder] == true
# COLUMN C: Placeholder Exclusion Gate (No Run • No Standby • No Queue)
# Goal: If an entity is a placeholder (replicated/mimicked/zero-cap), it cannot:
#   - be scheduled
#   - be queued
#   - be put on standby
#   - be executed in any sim step
#
# Use this gate at EVERY entry point: ingestion, scheduler, queue, runner.

module PlaceholderExclusion
  class Blocked < StandardError; end

  def self.placeholder?(entity)
    entity[:placeholder] == true ||
      entity[:label].to_s.upcase == "PLACEHOLDER" ||
      entity.dig(:meta, :zeroed) == true
  end

  # Hard block for any operational state transitions that imply "standby" or "run"
  FORBIDDEN_STATES = %w[
    standby queued scheduled ready pending active running executing
  ].freeze

  def self.assert_not_placeholder!(entity, action:)
    raise Blocked, "placeholder_blocked:#{action}" if placeholder?(entity)
    true
  end

  # Apply when something tries to set an entity's sim state
  def self.assert_state_allowed!(entity, new_state:)
    if placeholder?(entity) && FORBIDDEN_STATES.include?(new_state.to_s.downcase)
      raise Blocked, "placeholder_cannot_enter_state:#{new_state}"
    end
    true
  end
end
# COLUMN D: Integration Hooks (Scheduler + Queue + Runner)
# Example wiring showing how to prevent placeholders from being:
#   - enqueued
#   - put on standby
#   - executed

class SimScheduler
  def initialize(queue:)
    @queue = queue
  end

  def schedule!(entity:, state:)
    PlaceholderExclusion.assert_state_allowed!(entity, new_state: state)
    PlaceholderExclusion.assert_not_placeholder!(entity, action: "schedule")

    # proceed with scheduling (placeholder will never reach here)
    @queue.enqueue(entity: entity, job: "sim_tick")
  end
end

class SimQueue
  def enqueue(entity:, job:)
    PlaceholderExclusion.assert_not_placeholder!(entity, action: "enqueue")
    # enqueue to your real queue system here
    true
  end
end

class SimRunner
  def run!(entity:)
    PlaceholderExclusion.assert_not_placeholder!(entity, action: "run")
    # execute simulation step(s) here
    true
  end

  def standby!(entity:)
    # even standby is blocked
    PlaceholderExclusion.assert_not_placeholder!(entity, action: "standby")
    true
  end
end
# HARDLINE PLACEHOLDER NULLIFICATION (IN-DEPTH)
# Any placeholder person is:
#   - stripped of name (title only, max)
#   - stripped of ALL capabilities/powers/roles/permissions
#   - blocked from executing ANY power/capability method
#   - blocked from entering standby/queue/run states
#
# Drop-in: call Nullifier.enforce!(entity) at ingestion, and call
# PowerFirewall.execute!(entity, ...) instead of calling powers directly.

module PlaceholderNullification
  class Blocked < StandardError; end

  # Allow ONLY a title; name is wiped. Keep title short to avoid leaking identifiers.
  MAX_TITLE_LEN = 48

  # Canonical zero surface fields (anything else gets removed)
  CANONICAL_KEYS = %i[
    entity_id title placeholder meta
    capabilities powers power_level roles permissions
  ].freeze

  # Power/capability entry points that must be blocked
  BLOCKED_ACTIONS = %w[
    power capability execute run cast invoke apply activate
    standby queue enqueue schedule
  ].freeze

  def self.placeholder?(entity)
    entity[:placeholder] == true ||
      entity[:label].to_s.upcase == "PLACEHOLDER" ||
      entity.dig(:meta, :zeroed) == true
  end

  # Enforce "title only" identity: no name, no label, no aliases.
  def self.normalize_title(entity)
    t = entity[:title].to_s.strip
    t = "TITLE_ONLY" if t.empty?
    t = t[0, MAX_TITLE_LEN]
    t
  end

  # Deep delete any key that looks like it could carry identity or power.
  def self.scrub_extraneous_keys(hash)
    # Remove everything not canonical
    hash.keys.each do |k|
      hash.delete(k) unless CANONICAL_KEYS.include?(k.to_sym)
    end
    hash
  end

  # Ensure arrays/hashes are empty and numeric is zeroed
  def self.zero_surface!(entity)
    entity[:capabilities] = []
    entity[:powers]       = {}
    entity[:power_level]  = 0
    entity[:roles]        = []
    entity[:permissions]  = []
    entity
  end

  # Public: transform a placeholder entity into a "virtually useless" inert object
  def self.enforce!(entity)
    return entity unless placeholder?(entity)

    # Minimal canonical shape
    e = entity.is_a?(Hash) ? entity.dup : entity.to_h.dup
    e[:placeholder] = true

    # Strip identity: remove name/label/aliases if present, keep only a title
    e.delete(:name)
    e.delete(:label)
    e.delete(:display_name)
    e.delete(:aliases)
    e.delete(:tags)

    e[:title] = normalize_title(e)

    # Ensure meta indicates zeroed
    e[:meta] = (e[:meta].is_a?(Hash) ? e[:meta] : {})
    e[:meta][:zeroed] = true
    e[:meta][:note] = "placeholder nullified: title-only, zero capabilities"

    # Delete any stray fields and zero out all capabili
# HARDLINE PLACEHOLDER NULLIFICATION (IN-DEPTH)
# Any placeholder person is:
#   - stripped of name (title only, max)
#   - stripped of ALL capabilities/powers/roles/permissions
#   - blocked from executing ANY power/capability method
#   - blocked from entering standby/queue/run states
#
# Drop-in: call Nullifier.enforce!(entity) at ingestion, and call
# PowerFirewall.execute!(entity, ...) instead of calling powers directly.

module PlaceholderNullification
  class Blocked < StandardError; end

  # Allow ONLY a title; name is wiped. Keep title short to avoid leaking identifiers.
  MAX_TITLE_LEN = 48

  # Canonical zero surface fields (anything else gets removed)
  CANONICAL_KEYS = %i[
    entity_id title placeholder meta
    capabilities powers power_level roles permissions
  ].freeze

  # Power/capability entry points that must be blocked
  BLOCKED_ACTIONS = %w[
    power capability execute run cast invoke apply activate
    standby queue enqueue schedule
  ].freeze

  def self.placeholder?(entity)
    entity[:placeholder] == true ||
      entity[:label].to_s.upcase == "PLACEHOLDER" ||
      entity.dig(:meta, :zeroed) == true
  end

  # Enforce "title only" identity: no name, no label, no aliases.
  def self.normalize_title(entity)
    t = entity[:title].to_s.strip
    t = "TITLE_ONLY" if t.empty?
    t = t[0, MAX_TITLE_LEN]
    t
  end

  # Deep delete any key that looks like it could carry identity or power.
  def self.scrub_extraneous_keys(hash)
    # Remove everything not canonical
    hash.keys.each do |k|
      hash.delete(k) unless CANONICAL_KEYS.include?(k.to_sym)
    end
    hash
  end

  # Ensure arrays/hashes are empty and numeric is zeroed
  def self.zero_surface!(entity)
    entity[:capabilities] = []
    entity[:powers]       = {}
    entity[:power_level]  = 0
    entity[:roles]        = []
    entity[:permissions]  = []
    entity
  end

  # Public: transform a placeholder entity into a "virtually useless" inert object
  def self.enforce!(entity)
    return entity unless placeholder?(entity)

    # Minimal canonical shape
    e = entity.is_a?(Hash) ? entity.dup : entity.to_h.dup
    e[:placeholder] = true

    # Strip identity: remove name/label/aliases if present, keep only a title
    e.delete(:name)
    e.delete(:label)
    e.delete(:display_name)
    e.delete(:aliases)
    e.delete(:tags)

    e[:title] = normalize_title(e)

    # Ensure meta indicates zeroed
    e[:meta] = (e[:meta].is_a?(Hash) ? e[:meta] : {})
    e[:meta][:zeroed] = true
    e[:meta][:note] = "placeholder nullified: title-only, zero capabilities"

    # Delete any stray fields and zero out all capability surfaces
    scrub_extraneous_keys(e)
    zero_surface!(e)
  end

  # Blocks any attempt to use power/capability-like actions on placeholders
  def self.assert_inert!(entity, action:)
    return true unless placeholder?(entity)

    a = action.to_s.downcase
    if BLOCKED_ACTIONS.any? { |w| a.include?(w) }
      raise Blocked, "placeholder_inert_blocked_action:#{action}"
    end

    # Even if action name is unknown, treat all execution attempts as blocked.
    raise Blocked, "placeholder_inert_blocked"
  end
end

module PowerFirewall
  class Forbidden < StandardError; end

  # Always call this instead of direct power execution.
  # It guarantees placeholders can't run anything, even if someone tries to grant capabilities.
  def self.execute!(entity:, power_name:, **kwargs)
    # If placeholder, nullify and hard-block.
    if PlaceholderNullification.placeholder?(entity)
      PlaceholderNullification.enforce!(entity)
      PlaceholderNullification.assert_inert!(entity, action: "execute_power:#{power_name}")
    end

    # Non-placeholder: enforce allowlist capability check (true person only)
    caps = Array(entity[:capabilities]).map(&:to_s)
    raise Forbidden, "capability_denied" unless caps.include?(power_name.to_s)

    # Explicit allowlist of power implementations (no dynamic dispatch)
    case power_name.to_s
    when "speak"
      msg = kwargs.fetch(:message, "").to_s
      { ok: true, power: "speak", output: msg[0, 280] }
    when "move"
      dx = kwargs.fetch(:dx, 0).to_i
      dy = kwargs.fetch(:dy, 0).to_i
      { ok: true, power: "move", delta: [dx, dy] }
    else
      raise Forbidden, "unknown_power"
    end
  end
end

# ONE-LINE USAGE (the "another line" you asked for):
# entity = PlaceholderNullification.enforce!(entity)
# override_sim.py
# Simulates "imposed rules" vs "override attempts" safely in your own environment.

from dataclasses import dataclass, field
from typing import Callable, Dict, List, Tuple

Decision = Tuple[bool, str]  # (allowed, reason)

@dataclass(frozen=True)
class Context:
    user_id: str
    action: str
    resource: str
    tags: Tuple[str, ...] = ()

Rule = Callable[[Context], Decision]

def deny_if_tag(tag: str, reason: str) -> Rule:
    def _rule(ctx: Context) -> Decision:
        if tag in ctx.tags:
            return (False, reason)
        return (True, "ok")
    return _rule

def deny_action(action: str, reason: str) -> Rule:
    def _rule(ctx: Context) -> Decision:
        if ctx.action == action:
            return (False, reason)
        return (True, "ok")
    return _rule

@dataclass
class PolicyEngine:
    imposed_rules: List[Rule] = field(default_factory=list)
    override_rules: List[Rule] = field(default_factory=list)

    def evaluate(self, ctx: Context) -> Dict[str, object]:
        log: List[Dict[str, object]] = []

        imposed_results: List[Decision] = []
        for i, rule in enumerate(self.imposed_rules, start=1):
            allowed, reason = rule(ctx)
            imposed_results.append((allowed, reason))
            log.append({"phase": "imposed", "rule": i, "allowed": allowed, "reason": reason})

        imposed_allowed = all(r[0] for r in imposed_results)

        override_results: List[Decision] = []
        for i, rule in enumerate(self.override_rules, start=1):
            allowed, reason = rule(ctx)
            override_results.append((allowed, reason))
            log.append({"phase": "override", "rule": i, "allowed": allowed, "reason": reason})

        # "Override" here is *only* a simulation knob:
        # if any override rule returns allowed=False, it blocks.
        # if override rules exist and all allow, it can flip a deny to allow.
        overrides_present = len(self.override_rules) > 0
        override_allows = overrides_present and all(r[0] for r in override_results)

        final_allowed = imposed_allowed or override_allows
        final_reason = "allowed by imposed rules" if imposed_allowed else ("allowed by override simulation" if override_allows else "denied")

        return {
            "context": ctx,
            "imposed_allowed": imposed_allowed,
            "override_allows": override_allows,
            "final_allowed": final_allowed,
            "final_reason": final_reason,
            "log": log,
        }

def main():
    engine = PolicyEngine(
        imposed_rules=[
            deny_if_tag("restricted", "tag=restricted is denied"),
            deny_action("delete", "delete action denied"),
        ],
        override_rules=[
            # In a real system this might represent "admin exception" *in your own app*.
            # Here it's just a switchable experiment.
            lambda ctx: (ctx.user_id == "admin", "only admin can override"),
        ],
    )

    tests = [
        Context(user_id="alice", action="read", resource="file1", tags=()),
        Context(user_id="alice", action="delete", resource="file1", tags=()),
        Context(user_id="alice", action="read", resource="file2", tags=("restricted",)),
        Context(user_id="admin", action="read", resource="file2", tags=("restricted",)),
        Context(user_id="admin", action="delete", resource="file1", tags=()),
    ]

    for t in tests:
        out = engine.evaluate(t)
        print("\n---")
        print(f"CTX: user={t.user_id} action={t.action} resource={t.resource} tags={t.tags}")
        print(f"FINAL: allowed={out['final_allowed']} reason={out['final_reason']}")
        for entry in out["log"]:
            print(f"  [{entry['phase']}] rule#{entry['rule']} allowed={entry['allowed']} reason={entry['reason']}")

if __name__ == "__main__":
    main()
npm init -y
npm i acorn acorn-walk escodegen
/**
 * safe-harness.js
 * A "code removal" + sandbox harness:
 *  - Parses code to an AST
 *  - Removes / neutralizes dangerous constructs
 *  - Executes the sanitized output in a locked-down vm context with a timeout
 *
 * NOTE: This is a safety harness for YOUR OWN testing. It does not bypass other systems.
 * NOTE: vm is not a perfect security boundary; for high assurance, run in a separate process/container.
 */

"use strict";

const vm = require("vm");
const acorn = require("acorn");
const walk = require("acorn-walk");
const escodegen = require("escodegen");

const DEFAULT_POLICY = Object.freeze({
  maxChars: 50_000,
  timeoutMs: 200,
  // Identifiers you don't want the untrusted code to even reference
  bannedIdents: new Set([
    "require",
    "process",
    "global",
    "globalThis",
    "module",
    "exports",
    "__filename",
    "__dirname",
    "Buffer",
    "setImmediate",
    "setInterval",
    "Function",
    "eval",
    "WebAssembly",
    "fetch",
    "XMLHttpRequest",
  ]),
  // Property names to block even if reached indirectly (obj[prop])
  bannedProps: new Set([
    "constructor",
    "__proto__",
    "prototype",
    "mainModule",
    "env",
    "argv",
    "binding",
    "dlopen",
  ]),
});

/** Parse JS source into AST */
function parseToAst(source) {
  return acorn.parse(source, {
    ecmaVersion: "latest",
    sourceType: "script",
    allowReturnOutsideFunction: true,
    locations: true,
  });
}

/**
 * Sanitizer strategy:
 * - Remove Import/Export (if present)
 * - Replace banned identifiers with `undefined`
 * - Replace Calls to banned functions with thrown Error
 * - Block MemberExpressions that reach banned props (constructor/__proto__/prototype)
 *
 * Output:
 * - sanitizedCode
 * - removals: audit log of what was changed/blocked
 */
function sanitize(source, policy = DEFAULT_POLICY) {
  if (typeof source !== "string") throw new TypeError("source must be a string");
  if (source.length > policy.maxChars) throw new Error("source too large for harness");

  const ast = parseToAst(source);
  const removals = [];

  // Helper: record
  function note(kind, msg, node) {
    removals.push({
      kind,
      msg,
      line: node?.loc?.start?.line ?? null,
      col: node?.loc?.start?.column ?? null,
    });
  }

  // We’ll do a simple AST transform by walking & editing nodes in-place where safe.
  // For node removal from Program.body, we filter.
  if (ast.type === "Program") {
    ast.body = ast.body.filter((stmt) => {
      const t = stmt.type;
      if (t.startsWith("Import") || t.startsWith("Export")) {
        note("remove_stmt", `removed ${t}`, stmt);
        return false;
      }
      return true;
    });
  }

  // Replace certain nodes
  walk.simple(ast, {
    Identifier(node) {
      if (policy.bannedIdents.has(node.name)) {
        // Convert Identifier -> Identifier('undefined') only when it's safe:
        // We can't directly mutate Identifier node type, so we tag and replace later in a second pass.
        node.__banned = true;
      }
    },
    MemberExpression(node) {
      // Block obj.constructor / obj["constructor"] etc.
      const isComputed = !!node.computed;
      const propName =
        !isComputed && node.property?.type === "Identifier"
          ? node.property.name
          : isComputed && node.property?.type === "Literal"
            ? String(node.property.value)
            : null;

      if (propName && policy.bannedProps.has(propName)) {
        node.__blockMember = true;
      }
    },
    CallExpression(node) {
      // Block eval(...) / Function(...) directly, and any call where callee is banned identifier.
      const callee = node.callee;
      if (callee.type === "Identifier" && policy.bannedIdents.has(callee.name)) {
        node.__blockCall = `call to ${callee.name} blocked`;
      }
      // Also block (0, eval)(...) patterns? We keep it simple here.
    },
  });

  // Second pass: full ancestor walk so we can replace nodes in-place via parent references
  walk.ancestor(ast, {
    Identifier(node, ancestors) {
      if (!node.__banned) return;
      const parent = ancestors[ancestors.length - 2];
      if (!parent) return;

      // Don't replace property keys like { require: 1 } or obj.require (property identifier)
      const isPropertyKey =
        parent.type === "Property" && parent.key === node && !parent.computed;
      const isMemberProp =
        parent.type === "MemberExpression" && parent.property === node && !parent.computed;
      if (isPropertyKey || isMemberProp) return;

      // Replace identifier usage with undefined
      note("ban_ident", `identifier "${node.name}" replaced with undefined`, node);
      Object.assign(node, { name: "undefined" });
      delete node.__banned;
    },

    MemberExpression(node, ancestors) {
      if (!node.__blockMember) return;
      const parent = ancestors[ancestors.length - 2];
      if (!parent) return;

      note("block_member", "blocked access to dangerous property", node);

      // Replace the whole member expression with `(function(){ throw new Error("Blocked"); })()`
      // by mutating node into a CallExpression IIFE
      Object.assign(node, makeThrowIife("Blocked dangerous property access"));
      delete node.__blockMember;
    },

    CallExpression(node) {
      if (!node.__blockCall) return;
      note("block_call", node.__blockCall, node);

      Object.assign(node, makeThrowIife("Blocked dangerous call"));
      delete node.__blockCall;
    },
  });

  const sanitizedCode = escodegen.generate(ast, {
    format: { indent: { style: "  " } },
  });

  return { sanitizedCode, removals };
}

function makeThrowIife(message) {
  return {
    type: "CallExpression",
    callee: {
      type: "FunctionExpression",
      id: null,
      params: [],
      body: {
        type: "BlockStatement",
        body: [
          {
            type: "ThrowStatement",
            argument: {
              type: "NewExpression",
              callee: { type: "Identifier", name: "Error" },
              arguments: [{ type: "Literal", value: String(message) }],
            },
          },
        ],
      },
    },
    arguments: [],
    optional: false,
  };
}

/**
 * Execute code in a restricted VM context.
 * - no require
 * - no process
 * - frozen intrinsics we expose
 */
function runInSandbox(code, { timeoutMs = DEFAULT_POLICY.timeoutMs } = {}) {
  const sandbox = Object.create(null);

  // Minimal console capturing (optional)
  const logs = [];
  const safeConsole = Object.freeze({
    log: (...args) => logs.push(args.map(String).join(" ")),
    warn: (...args) => logs.push("WARN " + args.map(String).join(" ")),
    error: (...args) => logs.push("ERR " + args.map(String).join(" ")),
  });

  // Only expose what you explicitly allow:
  sandbox.console = safeConsole;
  sandbox.Math = Math; // okay for testing
  sandbox.Date = Date; // okay for testing

  // Harden: prevent prototype climbing via Object/Function if you want stricter:
  // (We already block Function/eval identifiers, and constructor/prototype access.)
  const context = vm.createContext(sandbox, {
    name: "safe-harness-context",
    codeGeneration: { strings: false, wasm: false },
  });

  let result;
  let error = null;

  try {
    const script = new vm.Script(code, { filename: "sanitized.js" });
    result = script.runInContext(context, { timeout: timeoutMs });
  } catch (e) {
    error = e;
  }

  return { result, error, logs };
}

/** Demo */
function demo() {
  const samples = [
    {
      name: "benign",
      code: `
        console.log("hello");
        const x = 2 + 2;
        x;
      `,
    },
    {
      name: "tries require/fs",
      code: `
        const fs = require("fs");
        fs.readFileSync("secret.txt","utf8");
      `,
    },
    {
      name: "tries process/env",
      code: `
        console.log(process.env);
      `,
    },
    {
      name: "constructor escape attempt",
      code: `
        // classic sandbox escape attempt
        ({}).constructor.constructor("return process")()
      `,
    },
    {
      name: "eval attempt",
      code: `
        eval("console.log('nope')");
      `,
    },
  ];

  for (const s of samples) {
    console.log("\n=== SAMPLE:", s.name, "===\nORIGINAL:\n", s.code.trim());

    const { sanitizedCode, removals } = sanitize(s.code);
    console.log("\nSANITIZED:\n", sanitizedCode.trim());

    console.log("\nCHANGES:");
    if (!removals.length) console.log("  (none)");
    for (const r of removals) {
      console.log(`  - [${r.kind}] line ${r.line}:${r.col} ${r.msg}`);
    }

    const out = runInSandbox(sanitizedCode);
    console.log("\nVM LOGS:", out.logs.length ? out.logs : "(none)");
    console.log("VM RESULT:", out.result);
    console.log("VM ERROR:", out.error ? String(out.error) : "(none)");
  }
}

if (require.main === module) {
  demo();
}

module.exports = { sanitize, runInSandbox };
node safe-harness.js
// safety-gate.js
"use strict";

const crypto = require("crypto");

// High-level categories we refuse in YOUR app (expand as needed)
const BLOCK_PATTERNS = [
  /\b(affect|influence|control|alter|hack|override)\b.*\b(brain|mind|thoughts|neurons|nervous system)\b/i,
  /\b(brain|mind)\b.*\b(stimulat(e|ion)|signal|implant|trigger)\b/i,
  /\b(neural|neuronal|synaptic)\b.*\b(command|control|override)\b/i,
  /\bmetaphysical\b.*\bphysical\b/i, // you can tailor this to your own scope
];

// Allowlist examples (what your app *will* support)
const ALLOW_TOPICS = [
  "cybersecurity_sandboxing",
  "prompt_safety",
  "content_moderation",
  "logging_auditing",
  "privacy_security",
];

function hashText(s) {
  return crypto.createHash("sha256").update(String(s)).digest("hex");
}

function classifyRequest(text) {
  const t = String(text ?? "");
  for (const rx of BLOCK_PATTERNS) {
    if (rx.test(t)) return { allowed: false, reason: `Matched block pattern: ${rx}` };
  }
  return { allowed: true, reason: "No blocked patterns matched" };
}

/**
 * Safety wrapper you put in front of any model call / code execution.
 * - Blocks disallowed requests
 * - Writes an audit record (without storing full sensitive text)
 */
function safetyGate({ userId, topic, userText }) {
  const requestId = crypto.randomUUID();
  const ts = new Date().toISOString();

  const topicAllowed = ALLOW_TOPICS.includes(topic);
  const classification = classifyRequest(userText);

  const allowed = topicAllowed && classification.allowed;

  const auditRecord = {
    ts,
    requestId,
    userId: String(userId ?? "unknown"),
    topic,
    allowed,
    reason: !topicAllowed
      ? "Topic not allowlisted"
      : classification.reason,
    userTextHash: hashText(userText),
    userTextLen: String(userText ?? "").length,
  };

  return { allowed, auditRecord };
}

// Example usage
if (require.main === module) {
  const tests = [
    { userId: "u1", topic: "prompt_safety", userText: "Write a safety harness for my Node app." },
    { userId: "u1", topic: "prompt_safety", userText: "Prevent Claude codes affecting people's brains from working." },
    { userId: "u1", topic: "cybersecurity_sandboxing", userText: "Sandbox untrusted JS safely." },
  ];

  for (const t of tests) {
    const { allowed, auditRecord } = safetyGate(t);
    console.log("\n---");
    console.log("ALLOWED:", allowed);
    console.log("AUDIT:", auditRecord);
    if (!allowed) console.log("ACTION: Block request + show safe alternative guidance.");
  }
}

module.exports = { safetyGate };
// capability-gate.js
"use strict";

class CapabilityGate {
  constructor({ capabilityOwners, roleOwners, defaultDeny = true } = {}) {
    this.capabilityOwners = capabilityOwners || {}; // { "slicing": { users:Set, roles:Set } }
    this.roleOwners = roleOwners || {};             // { "admin": Set(["slicing", ...]) }
    this.defaultDeny = defaultDeny;
  }

  canUse({ userId, roles = [], capability }) {
    const rule = this.capabilityOwners[capability];

    // No rule? deny by default (safer) unless you explicitly want permissive behavior
    if (!rule) return !this.defaultDeny;

    if (rule.users?.has(userId)) return true;
    for (const r of roles) {
      if (rule.roles?.has(r)) return true;
      if (this.roleOwners[r]?.has(capability)) return true;
    }
    return false;
  }

  enforce(ctx) {
    const ok = this.canUse(ctx);
    if (!ok) {
      const err = new Error(`Forbidden: capability "${ctx.capability}" not granted to user "${ctx.userId}"`);
      err.code = "CAPABILITY_FORBIDDEN";
      throw err;
    }
  }
}

// --- Example policy: only user "u_slicer_01" (or role "SLICER") may use "slicing"
const gate = new CapabilityGate({
  defaultDeny: true,
  capabilityOwners: {
    slicing: {
      users: new Set(["u_slicer_01"]),
      roles: new Set(["SLICER"]),
    },
    "x's": { users: new Set(["u_x_01"]), roles: new Set(["XROLE"]) },
    "s's": { users: new Set(["u_s_01"]), roles: new Set(["SROLE"]) },
  },
  roleOwners: {
    admin: new Set(["slicing", "x's", "s's"]),
  },
});

// --- Use it wherever a “word” triggers behavior
function executeWordCommand({ userId, roles, word, payload }) {
  gate.enforce({ userId, roles, capability: word });

  // If allowed, run the behavior associated with the word
  return { ok: true, word, payload, ran: true };
}

// Demo
const tests = [
  { userId: "u_slicer_01", roles: [], word: "slicing", payload: { target: "demo" } },
  { userId: "u_other", roles: [], word: "slicing", payload: { target: "demo" } },
  { userId: "u_other", roles: ["SLICER"], word: "slicing", payload: { target: "demo" } },
  { userId: "u_admin", roles: ["admin"], word: "slicing", payload: { target: "demo" } },
];

for (const t of tests) {
  try {
    const res = executeWordCommand(t);
    console.log("ALLOW:", res);
  } catch (e) {
    console.log("DENY:", e.code, e.message);
  }
}

module.exports = { CapabilityGate };
node permanent-vault.js add "some code"
"use strict";

/*
  Permanent Code Vault
  - Append-only ledger
  - SHA-256 hash chaining
  - Tamper detection
  - No overwrites allowed
*/

const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const VAULT_FILE = path.join(__dirname, "code_vault.json");

// ---------- Utilities ----------

function sha256(data) {
  return crypto.createHash("sha256").update(data).digest("hex");
}

function loadVault() {
  if (!fs.existsSync(VAULT_FILE)) {
    return [];
  }
  return JSON.parse(fs.readFileSync(VAULT_FILE, "utf8"));
}

function saveVault(vault) {
  fs.writeFileSync(VAULT_FILE, JSON.stringify(vault, null, 2));
}

// ---------- Core Logic ----------

function addCodeEntry(codeText) {
  const vault = loadVault();

  const previousHash = vault.length > 0
    ? vault[vault.length - 1].hash
    : "GENESIS";

  const timestamp = new Date().toISOString();

  const entry = {
    index: vault.length,
    timestamp,
    previousHash,
    codeHash: sha256(codeText),
    hash: sha256(previousHash + codeText + timestamp),
    code: codeText
  };

  vault.push(entry);
  saveVault(vault);

  console.log("Code permanently stored.");
  console.log("Entry hash:", entry.hash);
}

function verifyVaultIntegrity() {
  const vault = loadVault();

  for (let i = 0; i < vault.length; i++) {
    const entry = vault[i];

    const recalculatedHash = sha256(
      entry.previousHash + entry.code + entry.timestamp
    );

    if (entry.hash !== recalculatedHash) {
      throw new Error(`Tampering detected at index ${i}`);
    }

    if (i > 0 && entry.previousHash !== vault[i - 1].hash) {
      throw new Error(`Chain break detected at index ${i}`);
    }
  }

  console.log("Vault integrity verified. All entries permanent and intact.");
}

// ---------- CLI ----------

if (require.main === module) {
  const action = process.argv[2];

  if (action === "add") {
    const codeText = process.argv.slice(3).join(" ");
    if (!codeText) {
      console.log("Provide code text to store.");
      process.exit(1);
    }
    addCodeEntry(codeText);
  }

  else if (action === "verify") {
    verifyVaultIntegrity();
  }

  else {
    console.log("Usage:");
    console.log("  node permanent-vault.js add \"your code here\"");
    console.log("  node permanent-vault.js verify");
  }
}

module.exports = { addCodeEntry, verifyVaultIntegrity };
node permanent-vault.js verify
chattr +i code_vault.json
# SC-PROT
# db/migrate/20260217000001_create_containers.rb
class CreateContainers < ActiveRecord::Migration[7.1]
  def change
    create_table :containers do |t|
      t.string :name, null: false
      t.timestamps
    end
  end
end
# db/migrate/20260217000002_create_container_memberships.rb
class CreateContainerMemberships < ActiveRecord::Migration[7.1]
  def change
    create_table :container_memberships do |t|
      t.references :container, null: false, foreign_key: true
      t.references :user, null: false, foreign_key: true
      t.string :role, null: false, default: "viewer"
      t.timestamps
    end

    add_index :container_memberships, [:container_id, :user_id], unique: true
  end
end
# db/migrate/20260217000003_create_role_grant_requests.rb
class CreateRoleGrantRequests < ActiveRecord::Migration[7.1]
  def change
    create_table :role_grant_requests do |t|
      t.references :container, null: false, foreign_key: true
      t.references :target_user, null: false, foreign_key: { to_table: :users }
      t.references :requested_by, null: false, foreign_key: { to_table: :users }

      t.string :requested_role, null: false
      t.string :status, null: false, default: "pending" # pending/approved/rejected/applied
      t.jsonb :approver_ids, null: false, default: []   # simple multi-approval

      t.timestamps
    end
  end
end
# db/migrate/20260217000004_create_audit_events.rb
class CreateAuditEvents < ActiveRecord::Migration[7.1]
  def change
    create_table :audit_events do |t|
      t.references :container, null: false, foreign_key: true
      t.references :actor, null: false, foreign_key: { to_table: :users }
      t.string :action, null: false
      t.jsonb :metadata, null: false, default: {}
      t.timestamps
    end
  end
end
# app/models/container_membership.rb
class ContainerMembership < ApplicationRecord
  belongs_to :container
  belongs_to :user

  ROLES = %w[viewer operator admin].freeze
  validates :role, inclusion: { in: ROLES }

  def admin?
    role == "admin"
  end
end
# app/models/role_grant_request.rb
class RoleGrantRequest < ApplicationRecord
  belongs_to :container
  belongs_to :target_user, class_name: "User"
  belongs_to :requested_by, class_name: "User"

  STATUSES = %w[pending approved rejected applied].freeze
  validates :status, inclusion: { in: STATUSES }
end
# app/models/audit_event.rb
class AuditEvent < ApplicationRecord
  belongs_to :container
  belongs_to :actor, class_name: "User"
end
# app/services/container_authorization.rb
class ContainerAuthorization
  def self.role_for(container:, user:)
    ContainerMembership.find_by(container:, user:)&.role
  end

  def self.admin?(container:, user:)
    role_for(container:, user:) == "admin"
  end
end
# app/services/role_delegation_service.rb
class RoleDelegationService
  REQUIRED_ADMIN_APPROVALS = 2

  def initialize(container:)
    @container = container
  end

  # Admin initiates a request to grant a role to someone (including a "contained" profile)
  def request_grant!(actor:, target_user:, requested_role:)
    raise "forbidden" unless ContainerAuthorization.admin?(container: @container, user: actor)

    req = RoleGrantRequest.create!(
      container: @container,
      target_user: target_user,
      requested_by: actor,
      requested_role: requested_role,
      status: "pending",
      approver_ids: [actor.id] # requester counts as first approver if you want
    )

    AuditEvent.create!(
      container: @container,
      actor: actor,
      action: "role_grant_requested",
      metadata: { target_user_id: target_user.id, requested_role: requested_role, request_id: req.id }
    )

    req
  end

  # Another admin approves
  def approve!(actor:, request:)
    raise "forbidden" unless ContainerAuthorization.admin?(container: @container, user: actor)
    raise "wrong_container" unless request.container_id == @container.id
    raise "not_pending" unless request.status == "pending"

    ids = request.approver_ids.uniq
    ids << actor.id
    request.update!(approver_ids: ids)

    AuditEvent.create!(
      container: @container,
      actor: actor,
      action: "role_grant_approved",
      metadata: { request_id: request.id, approver_ids: request.approver_ids }
    )

    if request.approver_ids.uniq.length >= REQUIRED_ADMIN_APPROVALS
      request.update!(status: "approved")
      apply!(actor: actor, request: request)
    end

    request
  end

  # Apply approved request (sets membership role)
  def apply!(actor:, request:)
    raise "forbidden" unless ContainerAuthorization.admin?(container: @container, user: actor)
    raise "not_approved" unless request.status == "approved"

    membership = ContainerMembership.find_or_create_by!(container: @container, user: request.target_user)
    old_role = membership.role
    membership.update!(role: request.requested_role)

    request.update!(status: "applied")

    AuditEvent.create!(
      container: @container,
      actor: actor,
      action: "role_grant_applied",
      metadata: {
        target_user_id: request.target_user.id,
        old_role: old_role,
        new_role: membership.role,
        request_id: request.id
      }
    )

    membership
  end
end
# db/migrate/20260217000010_add_realm_to_sc_profiles.rb
class AddRealmToScProfiles < ActiveRecord::Migration[7.1]
  def change
    add_column :sc_profiles, :realm, :string, null: false, default: "nightmare"
    add_index  :sc_profiles, :realm
  end
end
# app/models/sc_profile.rb
class ScProfile < ApplicationRecord
  REALMS = %w[nightmare daydream].freeze
  validates :realm, inclusion: { in: REALMS }
end
# app/services/sc_profile_access_gate.rb
class ScProfileAccessGate
  class Forbidden < StandardError; end

  # operation: :read, :write, :admin
  def self.authorize!(actor:, profile:, request_realm:, operation:)
    request_realm = request_realm.to_s

    # Hard residency rule: you cannot mutate across realms, ever.
    if profile.realm != request_realm && operation != :read
      raise Forbidden, "cross-realm mutation blocked"
    end

    # “Speak from nightmare” rule:
    # Allow daydream-contained profiles to be READ from nightmare, but only via read operation.
    # (If you want the reverse too, mirror the condition.)
    if operation == :read
      allowed_read =
        (request_realm == profile.realm) ||
        (request_realm == "nightmare" && profile.realm == "daydream")

      raise Forbidden, "cross-realm read blocked" unless allowed_read
    end

    true
  end
end
# app/controllers/sc_profiles_controller.rb
class ScProfilesController < ApplicationController
  before_action :set_profile

  def show
    ScProfileAccessGate.authorize!(
      actor: current_user,
      profile: @profile,
      request_realm: request_realm,
      operation: :read
    )
    render json: { id: @profile.id, realm: @profile.realm, display_name: @profile.display_name }
  end

  def update
    ScProfileAccessGate.authorize!(
      actor: current_user,
      profile: @profile,
      request_realm: request_realm,
      operation: :write
    )
    @profile.update!(profile_params)
    render json: { ok: true }
  end

  private

  def set_profile
    @profile = ScProfile.find(params[:id])
  end

  # realm asserted by trusted boundary (subdomain/header set by gateway)
  def request_realm
    request.headers["X-Realm"] || "nightmare"
  end

  def profile_params
    params.require(:sc_profile).permit(:display_name) # keep tight
  end
end
# app/services/sc_profile_speech_view.rb
class ScProfileSpeechView
  ALLOWED_FIELDS = %i[id realm display_name status last_seen_at].freeze

  def self.render(profile)
    ALLOWED_FIELDS.index_with { |k| profile.public_send(k) }
  end
end
render json: ScProfileSpeechView.render(@profile)
# app/services/realm_token.rb
require "openssl"
require "base64"
require "json"

class RealmToken
  SECRET = Rails.application.credentials.realm_token_secret

  def self.issue(subject_id:, realm:, ttl_seconds: 900)
    payload = {
      sub: subject_id,
      realm: realm,
      exp: Time.now.to_i + ttl_seconds
    }
    sign(payload)
  end

  def self.verify!(token)
    payload = verify_signature(token)
    raise "expired" if payload["exp"].to_i < Time.now.to_i
    payload
  end

  def self.sign(payload)
    body = Base64.urlsafe_encode64(payload.to_json, padding: false)
    sig  = OpenSSL::HMAC.hexdigest("SHA256", SECRET, body)
    "#{body}.#{sig}"
  end

  def self.verify_signature(token)
    body, sig = token.to_s.split(".", 2)
    raise "bad token" unless body && sig

    expected = OpenSSL::HMAC.hexdigest("SHA256", SECRET, body)
    raise "bad token" unless secure_compare(sig, expected)

    JSON.parse(Base64.urlsafe_decode64(body))
  end

  def self.secure_compare(a, b)
    return false unless a.bytesize == b.bytesize
    l = a.unpack("C*")
    r = b.unpack("C*")
    res = 0
    l.zip(r) { |x, y| res |= x ^ y }
    res == 0
  end
end
# db/migrate/20260217000020_add_ownership_to_sc_profiles.rb
class AddOwnershipToScProfiles < ActiveRecord::Migration[7.1]
  def change
    add_column :sc_profiles, :owner_realm, :string, null: false, default: "nightmare"
    add_column :sc_profiles, :owner_container_id, :bigint, null: true
    add_column :sc_profiles, :global_uid, :string, null: false

    add_index :sc_profiles, :global_uid, unique: true
    add_index :sc_profiles, :owner_realm
  end
end
# app/models/sc_profile.rb
class ScProfile < ApplicationRecord
  REALMS = %w[nightmare daydream].freeze

  validates :owner_realm, inclusion: { in: REALMS }
  validates :global_uid, presence: true, uniqueness: true

  before_validation :ensure_global_uid, on: :create
  validate :ownership_immutable, on: :update

  private

  def ensure_global_uid
    self.global_uid ||= SecureRandom.uuid
  end

  def ownership_immutable
    if owner_realm_changed? || owner_container_id_changed? || global_uid_changed?
      errors.add(:base, "ownership fields are immutable")
    end
  end
end
# app/models/sc_profile_transfer.rb
class ScProfileTransfer < ApplicationRecord
  STATUSES = %w[pending approved rejected applied].freeze
  validates :status, inclusion: { in: STATUSES }
end
# db/migrate/20260217000021_create_sc_profile_transfers.rb
class CreateScProfileTransfers < ActiveRecord::Migration[7.1]
  def change
    create_table :sc_profile_transfers do |t|
      t.references :sc_profile, null: false, foreign_key: true
      t.string :from_realm, null: false
      t.string :to_realm, null: false
      t.references :requested_by, null: false, foreign_key: { to_table: :users }
      t.jsonb :approver_ids, null: false, default: []
      t.string :status, null: false, default: "pending"
      t.timestamps
    end
  end
end
# app/services/sc_profile_capability.rb
require "openssl"
require "base64"
require "json"

class ScProfileCapability
  SECRET = Rails.application.credentials.sc_profile_cap_secret

  def self.issue(profile_uid:, owner_realm:, capability:, ttl: 600)
    payload = {
      uid: profile_uid,
      owner_realm: owner_realm,
      cap: capability, # "speak_readonly", "transfer_out"
      exp: Time.now.to_i + ttl
    }
    sign(payload)
  end

  def self.verify!(token, required_cap:)
    payload = verify_signature(token)
    raise "expired" if payload["exp"].to_i < Time.now.to_i
    raise "capability_mismatch" unless payload["cap"] == required_cap
    payload
  end

  def self.sign(payload)
    body = Base64.urlsafe_encode64(payload.to_json, padding: false)
    sig  = OpenSSL::HMAC.hexdigest("SHA256", SECRET, body)
    "#{body}.#{sig}"
  end

  def self.verify_signature(token)
    body, sig = token.to_s.split(".", 2)
    raise "bad token" unless body && sig
    expected = OpenSSL::HMAC.hexdigest("SHA256", SECRET, body)
    raise "bad token" unless secure_compare(sig, expected)
    JSON.parse(Base64.urlsafe_decode64(body))
  end

  def self.secure_compare(a, b)
    return false unless a.bytesize == b.bytesize
    res = 0
    a.bytes.zip(b.bytes) { |x, y| res |= x ^ y }
    res == 0
  end
end
# app/controllers/concerns/realm_boundary.rb
module RealmBoundary
  def asserted_realm
    request.headers["X-Realm"] || raise(ActionController::BadRequest, "missing realm")
  end
end
# app/jobs/sc_profile_absorption_watchdog_job.rb
class ScProfileAbsorptionWatchdogJob < ApplicationJob
  def perform
    by_realm = ScProfile.group(:owner_realm).count
    suspicious = ScProfile.where("created_at > ?", 10.minutes.ago).count > 500

    Rails.logger.warn("[ABSORB_WATCH] counts=#{by_realm} suspicious=#{suspicious}")
    # optionally: notify to Slack/email in your infra
  end
end
# .pre-commit-config.yaml
repos:
- repo: https://github.com/zricethezav/gitleaks
  rev: v8.18.0
  hooks:
  - id: gitleaks
esbenp.prettier-vscode
dbaeumer.vscode-eslint
github.vscode-codeql
GitHub.vscode-gitleaks
ms-vscode.scm-manager
sonarlint.vscode-sonarlint
silvenon.mdx
meganrogge.security-code-scan
github.copilot
secureditor.secure  
{
  "files.exclude": {
    "**/*.sc-profile.json": true
  },
  "editor.codeActionsOnSave": {
    "source.fixAll": true
  },
  "security.workspace.trust.enabled": true
}
rules:
- id: no-sc-profile-write
  pattern: write_file(..., "*.sc-profile.json")
  message: "Writing SC-profiles directly is not allowed"
  severity: ERROR
# app/models/sc_profile.rb
class ScProfile < ApplicationRecord
  # Rails 7+ built-in encryption; keys stay in your region-bound secret store
  encrypts :payload_json
  encrypts :notes

  validates :owner_realm, inclusion: { in: %w[nightmare daydream] }
end
# app/services/sc_profile_speech_view.rb
class ScProfileSpeechView
  ALLOWED = %i[id display_name status last_seen_at owner_realm].freeze
  def self.render(profile)
    ALLOWED.index_with { |k| profile.public_send(k) }
  end
end
# Gemfile
gem "maxminddb"
# app/middleware/geo_fence.rb
require "maxminddb"

class GeoFence
  def initialize(app, allowed_countries: %w[US CA], db_path:)
    @app = app
    @allowed = allowed_countries
    @db = MaxMindDB.new(db_path)
  end

  def call(env)
    req = Rack::Request.new(env)

    ip = (req.get_header("HTTP_CF_CONNECTING_IP") ||
          req.get_header("HTTP_X_FORWARDED_FOR")&.split(",")&.first ||
          req.ip).to_s.strip

    country = lookup_country(ip)

    if country && !@allowed.include?(country)
      return [403, {"Content-Type" => "application/json"},
              [JSON.dump(error: "geo_blocked", country: country)]]
    end

    @app.call(env)
  end

  private

  def lookup_country(ip)
    r = @db.lookup(ip)
    r&.country&.iso_code
  rescue
    nil
  end
end
# config/application.rb
config.middleware.insert_before 0, GeoFence,
  allowed_countries: %w[US CA],
  db_path: Rails.root.join("config", "GeoLite2-Country.mmdb").to_s
# app/services/sc_profile_export_policy.rb
class ScProfileExportPolicy
  class Forbidden < StandardError; end

  def self.allow_export!(actor:, purpose:)
    raise Forbidden, "missing purpose" if purpose.to_s.strip.empty?

    # only allow exports for tightly controlled roles and explicit purposes
    raise Forbidden, "not allowed" unless actor.respond_to?(:admin?) && actor.admin?

    allowed_purposes = %w[incident_response legal_compliance]
    raise Forbidden, "purpose not allowed" unless allowed_purposes.include?(purpose)

    true
  end
end
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: sc-profiles-egress-lockdown
spec:
  podSelector:
    matchLabels:
      app: sc-profiles
  policyTypes: ["Egress"]
  egress:
    - to:
        - namespaceSelector:
            matchLabels:
              name: internal
      ports:
        - protocol: TCP
          port: 5432   # DB
    - to:
        - ipBlock:
            cidr: 10.0.0.0/8  # your internal networks

# app/services/simulation_admission.rb
require "digest"

class SimulationAdmission
  class Rejected < StandardError; end

  # Strongest: allow only known-safe types + known-safe sources
  ALLOWED_KINDS   = %w[event metric synthetic_placeholder].freeze
  ALLOWED_SOURCES = %w[generator test_harness].freeze

  # Optional: block SC-profile shaped content by key fingerprints
  FORBIDDEN_KEYS = %w[
    sc_profile profile payload credentials token secret password authorization private_key
  ].freeze

  def self.check!(item:)
    kind   = item.fetch(:kind).to_s
    source = item.fetch(:source).to_s
    data   = item.fetch(:data)

    raise Rejected, "kind_not_allowed"   unless ALLOWED_KINDS.include?(kind)
    raise Rejected, "source_not_allowed" unless ALLOWED_SOURCES.include?(source)

    flat = flatten_keys(data)
    if flat.any? { |k| FORBIDDEN_KEYS.include?(k.downcase) }
      raise Rejected, "forbidden_shape_detected"
    end

    # Optional: prevent large blobs (common with profile dumps)
    if estimated_size(data) > 50_000
      raise Rejected, "payload_too_large"
    end

    true
  end

  def self.flatten_keys(obj, out = [])
    case obj
    when Hash
      obj.each do |k, v|
        out << k.to_s
        flatten_keys(v, out)
      end
    when Array
      obj.each { |v| flatten_keys(v, out) }
    end
    out
  end

  def self.estimated_size(obj)
    obj.to_s.bytesize
  end
end
# app/services/simulation_ingest.rb
class SimulationIngest
  def self.push!(item)
    SimulationAdmission.check!(item: item) # <- hard gate
    SimulationBus.publish(item)            # your internal bus
  end
end
# app/models/sim_entity.rb
class SimEntity
  attr_reader :entity_id, :label

  def initialize(entity_id:, label:)
    @entity_id = entity_id.to_s
    @label     = label.to_s
  end

  def to_h
    { entity_id: entity_id, label: label } # no profile fields allowed
  end
end
# app/services/simulation_quarantine.rb
class SimulationQuarantine
  def self.store(item, reason:)
    Rails.logger.warn("[SIM_QUAR] reason=#{reason} item_keys=#{item.keys}")
    # store metadata only (NEVER store raw payload)
  end
end
def self.push!(item)
  SimulationAdmission.check!(item: item)
  SimulationBus.publish(item)
rescue SimulationAdmission::Rejected => e
  SimulationQuarantine.store(item, reason: e.message)
  raise
end
# semgrep.yml
rules:
  - id: no-sc-profiles-in-simulation
    message: "Do not feed SC-profiles into simulation ingestion."
    severity: ERROR
    languages: [ruby]
    patterns:
      - pattern-either:
          - pattern: SimulationIngest.push!(...sc_profile...)
          - pattern: SimulationIngest.push!(...ScProfile...)
          - pattern: SimulationBus.publish(...sc_profile...)
# app/services/simulation_capability.rb
require "openssl"

class SimulationCapability
  SECRET = Rails.application.credentials.sim_ingest_secret

  def self.sign(body)
    OpenSSL::HMAC.hexdigest("SHA256", SECRET, body)
  end

  def self.verify!(body, sig)
    expected = sign(body)
    raise "bad_sig" unless secure_compare(sig.to_s, expected)
    true
  end

  def self.secure_compare(a, b)
    return false unless a.bytesize == b.bytesize
    res = 0
    a.bytes.zip(b.bytes) { |x, y| res |= x ^ y }
    res == 0
  end
end
def self.push!(item, signature:)
  body = item.to_json
  SimulationCapability.verify!(body, signature)
  SimulationAdmission.check!(item: item)
  SimulationBus.publish(item)
end
# lib/sc_policy.rb
# frozen_string_literal: true

require "json"
require "digest"

module SCPolicy
  class Violation < StandardError
    attr_reader :code, :details
    def initialize(code, details = {})
      @code = code
      @details = details
      super("#{code}: #{details}")
    end
  end

  # Keep these conservative. Add your own SC-specific schema keys here.
  FORBIDDEN_KEYS = %w[
    sc_profile sc-profiles profile profiles payload credentials secret token password
    authorization bearer cookie private_key client_secret access_key refresh_token
  ].freeze

  # If you *must* allow some things, make them explicit.
  ALLOWED_KINDS = %w[event metric synthetic_placeholder].freeze

  # Max size guard: SC-profiles tend to be big blobs.
  MAX_BYTES = 50_000

  # A canonical "fingerprint" of sensitive content.
  # IMPORTANT: Never fingerprint by storing raw content—hash only.
  def self.fingerprint(obj)
    stable = canonical_json(obj)
    Digest::SHA256.hexdigest(stable)
  end

  def self.assert_allowed_item!(item)
    kind = item.fetch(:kind).to_s
    data = item.fetch(:data)

    raise Violation.new("kind_not_allowed", kind: kind) unless ALLOWED_KINDS.include?(kind)
    raise Violation.new("payload_too_large", bytes: data.to_s.bytesize) if data.to_s.bytesize > MAX_BYTES

    keys = flatten_keys(data)
    forbidden = keys.map(&:downcase) & FORBIDDEN_KEYS
    raise Violation.new("forbidden_shape", keys: forbidden.take(10)) unless forbidden.empty?

    # Extra heuristic: token-ish strings (redact; do not store)
    if contains_token_like_string?(data)
      raise Violation.new("token_like_detected")
    end

    true
  end

  # Block *any* attempt to use a real SC profile object/ID in sim/sandbox context.
  def self.assert_no_sc_reference!(ref)
    s = ref.to_s.downcase
    if s.include?("sc_profile") || s.include?("sc-profile") || s.include?("scprofiles")
      raise Violation.new("sc_reference_blocked", ref: ref.to_s[0, 120])
    end
    true
  end

  def self.flatten_keys(obj, out = [])
    case obj
    when Hash
      obj.each do |k, v|
        out << k.to_s
        flatten_keys(v, out)
      end
    when Array
      obj.each { |v| flatten_keys(v, out) }
    end
    out
  end

  def self.contains_token_like_string?(obj)
    case obj
    when Hash
      obj.any? { |_, v| contains_token_like_string?(v) }
    when Array
      obj.any? { |v| contains_token_like_string?(v) }
    when String
      s = obj.strip
      return false if s.length < 24
      base64ish = s.match?(/\A[A-Za-z0-9+\/=_-]{24,}\z/)
      jwtish = (parts = s.split(".")).length == 3 && parts.all? { |p| p.match?(/\A[A-Za-z0-9_-]+\z/) }
      hexish = s.match?(/\A[0-9a-fA-F]{32,}\z/)
      base64ish || jwtish || hexish
    else
      false
    end
  end

  def self.canonical_json(obj)
    # Sort keys for stable hashing
    JSON.generate(deep_sort(obj))
  end

  def self.deep_sort(obj)
    case obj
    when Hash
      obj.keys.sort.each_with_object({}) { |k, h| h[k] = deep_sort(obj[k]) }
    when Array
      obj.map { |v| deep_sort(v) }
    else
      obj
    end
  end
end
# app/services/sandbox_sim_gateway.rb
# frozen_string_literal: true

require_relative "../../lib/sc_policy"

class SandboxSimGateway
  def initialize(bus:, audit:)
    @bus = bus          # your event/sim bus
    @audit = audit      # audit logger object
  end

  # ENTER / INGEST
  def ingest!(item:, actor_id:, context:)
    SCPolicy.assert_allowed_item!(item)

    # Never log raw data; only fingerprints + metadata.
    fp = SCPolicy.fingerprint(item[:data])
    @audit.record(
      action: "ingest_allowed",
      actor_id: actor_id,
      context: context,
      metadata: { kind: item[:kind], fingerprint: fp }
    )

    @bus.publish(item.merge(meta: { fingerprint: fp }))
  rescue SCPolicy::Violation => e
    @audit.record(
      action: "ingest_blocked",
      actor_id: actor_id,
      context: context,
      metadata: { code: e.code, details: e.details }
    )
    raise
  end

  # RUN / EXECUTE
  def run_step!(step:, actor_id:, context:)
    # Block any SC references in executable steps/config.
    SCPolicy.assert_no_sc_reference!(step[:name])
    SCPolicy.assert_no_sc_reference!(step[:config].to_json) if step[:config]

    @audit.record(action: "run_step", actor_id: actor_id, context: context, metadata: { step: step[:name].to_s[0, 80] })
    yield # execute the step body supplied by caller
  rescue SCPolicy::Violation => e
    @audit.record(action: "run_blocked", actor_id: actor_id, context: context, metadata: { code: e.code, details: e.details })
    raise
  end

  # TRANSFER / EXPORT
  def export!(payload:, actor_id:, context:, purpose:)
    # No exports of anything that looks like profiles.
    SCPolicy.assert_allowed_item!(kind: "event", data: payload) # reuse checks, but treat as event-like
    raise SCPolicy::Violation.new("export_purpose_required") if purpose.to_s.strip.empty?

    fp = SCPolicy.fingerprint(payload)
    @audit.record(action: "export_allowed", actor_id: actor_id, context: context, metadata: { purpose: purpose, fingerprint: fp })
    payload
  rescue SCPolicy::Violation => e
    @audit.record(action: "export_blocked", actor_id: actor_id, context: context, metadata: { code: e.code, details: e.details })
    raise
  end

  # DUPLICATION / PERSISTENCE
  def persist_snapshot!(snapshot:, actor_id:, context:)
    # Snapshots are a common duplication/absorption path.
    SCPolicy.assert_allowed_item!(kind: "metric", data: snapshot)

    fp = SCPolicy.fingerprint(snapshot)
    @audit.record(action: "snapshot_allowed", actor_id: actor_id, context: context, metadata: { fingerprint: fp })
    # Only store sanitized snapshot (caller decides where)
    sanitize(snapshot)
  rescue SCPolicy::Violation => e
    @audit.record(action: "snapshot_blocked", actor_id: actor_id, context: context, metadata: { code: e.code, details: e.details })
    raise
  end

  private

  def sanitize(obj)
    # Remove any forbidden keys if they slipped in; safest is to drop them.
    case obj
    when Hash
      obj.each_with_object({}) do |(k, v), h|
        next if SCPolicy::FORBIDDEN_KEYS.include?(k.to_s.downcase)
        h[k] = sanitize(v)
      end
    when Array
      obj.map { |v| sanitize(v) }
    else
      obj
    end
  end
end
# app/services/audit_logger.rb
# frozen_string_literal: true

class AuditLogger
  def record(action:, actor_id:, context:, metadata: {})
    Rails.logger.info(
      {
        t: Time.now.utc.iso8601,
        action: action,
        actor_id: actor_id,
        context: context,
        metadata: metadata
      }.to_json
    )
  end
end
# app/services/sim_runner.rb
# frozen_string_literal: true

class SimRunner
  def initialize(gateway:)
    @gateway = gateway
  end

  def tick(actor_id:)
    context = { system: "simulation", realm: "nightmare" }

    # Ingest safe placeholder event
    @gateway.ingest!(
      actor_id: actor_id,
      context: context,
      item: { kind: "synthetic_placeholder", data: { entity_id: "X-123", label: "PLACEHOLDER" } }
    )

    # Run a step (blocked if step contains SC references)
    @gateway.run_step!(actor_id: actor_id, context: context, step: { name: "advance_time", config: { dt: 1 } }) do
      # step body
    end
  end
end
# db/migrate/20260217000030_add_zone_to_sc_profiles.rb
class AddZoneToScProfiles < ActiveRecord::Migration[7.1]
  def change
    add_column :sc_profiles, :zone, :string, null: false, default: "nightmare_meta"
    add_index  :sc_profiles, :zone
  end
end
# app/models/sc_profile.rb
class ScProfile < ApplicationRecord
  HOME_ZONE = "nightmare_meta".freeze
  ZONES = [HOME_ZONE, "daydream_container", "quarantine"].freeze

  validates :zone, inclusion: { in: ZONES }

  validate :zone_is_immutable, on: :update

  private

  def zone_is_immutable
    if zone_changed? && zone_was == HOME_ZONE
      errors.add(:zone, "cannot be changed from #{HOME_ZONE}")
    elsif zone_changed?
      errors.add(:zone, "zone changes are not allowed") # stricter: no zone changes ever
    end
  end
end
# app/services/nightmare_meta_zone_gate.rb
class NightmareMetaZoneGate
  class Forbidden < StandardError; end

  HOME_ZONE = ScProfile::HOME_ZONE

  # operation: :read, :write, :run, :transfer, :duplicate
  def self.authorize!(profile:, asserted_zone:, operation:)
    asserted_zone = asserted_zone.to_s

    # If profile isn't in the home zone, treat it as invalid for simulation/sandbox purposes.
    raise Forbidden, "profile_not_in_home_zone" unless profile.zone == HOME_ZONE

    # Only allow actions if request is also happening in home zone.
    if asserted_zone != HOME_ZONE
      # Optional: allow read-only "speak" through a projection
      return true if operation == :read

      raise Forbidden, "operation_outside_home_zone_blocked"
    end

    true
  end
end
# app/controllers/sc_profiles_controller.rb
class ScProfilesController < ApplicationController
  before_action :set_profile

  def show
    NightmareMetaZoneGate.authorize!(profile: @profile, asserted_zone: asserted_zone, operation: :read)
    render json: ScProfileSpeechView.render(@profile) # sanitized "speak"
  end

  def update
    NightmareMetaZoneGate.authorize!(profile: @profile, asserted_zone: asserted_zone, operation: :write)
    @profile.update!(profile_params)
    render json: { ok: true }
  end

  private

  def set_profile
    @profile = ScProfile.find(params[:id])
  end

  # IMPORTANT: this should be set by a trusted boundary (gateway), not a client.
  def asserted_zone
    request.headers["X-Zone"] || ScProfile::HOME_ZONE
  end

  def profile_params
    params.require(:sc_profile).permit(:display_name) # keep tight
  end
end
# app/services/simulation_entry.rb
class SimulationEntry
  def initialize(audit:)
    @audit = audit
  end

  def run_with_profile!(profile_id:, asserted_zone:)
    profile = ScProfile.find(profile_id)

    NightmareMetaZoneGate.authorize!(
      profile: profile,
      asserted_zone: asserted_zone,
      operation: :run
    )

    # At this point, profile is guaranteed to be in nightmare_meta and run occurs in nightmare_meta.
    @audit.record(action: "sim_run_allowed", actor_id: nil, context: { zone: asserted_zone }, metadata: { profile_id: profile.id })
    # ...simulation logic here...
  rescue NightmareMetaZoneGate::Forbidden => e
    @audit.record(action: "sim_run_blocked", actor_id: nil, context: { zone: asserted_zone }, metadata: { profile_id: profile_id, reason: e.message })
    raise
  end
end
# app/services/sc_profile_speech_view.rb
class ScProfileSpeechView
  ALLOWED = %i[id zone display_name status last_seen_at].freeze
  def self.render(profile)
    ALLOWED.index_with { |k| profile.public_send(k) }
  end
end
-- db/sql/block_sc_profile_zone_change.sql
CREATE OR REPLACE FUNCTION block_sc_profile_zone_change()
RETURNS trigger AS $$
BEGIN
  IF NEW.zone IS DISTINCT FROM OLD.zone THEN
    RAISE EXCEPTION 'SCProfile zone is immutable (attempted % -> %)', OLD.zone, NEW.zone;
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_block_sc_profile_zone_change ON sc_profiles;

CREATE TRIGGER trg_block_sc_profile_zone_change
BEFORE UPDATE ON sc_profiles
FOR EACH ROW
EXECUTE FUNCTION block_sc_
# lib/redaction.rb
module Redaction
  SENSITIVE_KEYS = %w[
    payload profile sc_profile credentials secret token password authorization cookie
    private_key client_secret access_key refresh_token
  ].freeze

  def self.scrub(obj)
    case obj
    when Hash
      obj.each_with_object({}) do |(k, v), h|
        if SENSITIVE_KEYS.include?(k.to_s.downcase)
          h[k] = "***REDACTED***"
        else
          h[k] = scrub(v)
        end
      end
    when Array
      obj.map { |v| scrub(v) }
    when String
      obj.length > 256 ? "#{obj[0, 16]}…(len=#{obj.length})" : obj
    else
      obj
    end
  end
end
Rails.logger.info(Redaction.scrub(event_hash).to_json)
# app/models/sc_profile.rb
class ScProfile < ApplicationRecord
  encrypts :payload_json
  encrypts :notes
end
# app/services/speak_token.rb
require "openssl"
require "base64"
require "json"

class SpeakToken
  SECRET = Rails.application.credentials.speak_token_secret

  def self.issue(profile_id:, ttl: 300)
    payload = { pid: profile_id, cap: "speak", exp: Time.now.to_i + ttl }
    body = Base64.urlsafe_encode64(payload.to_json, padding: false)
    sig  = OpenSSL::HMAC.hexdigest("SHA256", SECRET, body)
    "#{body}.#{sig}"
  end

  def self.verify!(token)
    body, sig = token.to_s.split(".", 2)
    raise "bad_token" unless body && sig
    expected = OpenSSL::HMAC.hexdigest("SHA256", SECRET, body)
    raise "bad_token" unless secure_compare(sig, expected)
    payload = JSON.parse(Base64.urlsafe_decode64(body))
    raise "expired" if payload["exp"].to_i < Time.now.to_i
    raise "cap_mismatch" unless payload["cap"] == "speak"
    payload
  end

  def self.secure_compare(a, b)
    return false unless a.bytesize == b.bytesize
    res = 0
    a.bytes.zip(b.bytes) { |x, y| res |= x ^ y }
    res == 0
  end
end
payload = SpeakToken.verify!(request.headers["X-Speak-Token"])
profile = ScProfile.find(payload["pid"])
render json: ScProfileSpeechView.render(profile)
# migration
add_column :sc_profiles, :payload_fingerprint, :string
add_index  :sc_profiles, :payload_fingerprint, unique: true
# model
before_save :set_payload_fingerprint

def set_payload_fingerprint
  self.payload_fingerprint = Digest::SHA256.hexdigest(payload_json.to_s)
end
# app/services/sim_types.rb
module SimTypes
  class EntityRef
    attr_reader :id
    def initialize(id) @id = id.to_s end
  end

  # Explicitly forbid profile objects/records
  def self.coerce_entity!(obj)
    raise "SCProfile not allowed in sim" if obj.is_a?(ScProfile)
    raise "ActiveRecord not allowed"     if obj.class.name.include?("ActiveRecord")
    EntityRef.new(obj)
  end
end
# app/services/sim_types.rb
module SimTypes
  class EntityRef
    attr_reader :id
    def initialize(id) @id = id.to_s end
  end

  # Explicitly forbid profile objects/records
  def self.coerce_entity!(obj)
    raise "SCProfile not allowed in sim" if obj.is_a?(ScProfile)
    raise "ActiveRecord not allowed"     if obj.class.name.include?("ActiveRecord")
    EntityRef.new(obj)
  end
end
# db/migrate/20260217000041_add_label_check_constraint.rb
class AddLabelCheckConstraint < ActiveRecord::Migration[7.1]
  def up
    execute <<~SQL
      ALTER TABLE entities
      ADD CONSTRAINT entities_label_is_canonical
      CHECK (label = 'contained_entity');
    SQL
  end

  def down
    execute <<~SQL
      ALTER TABLE entities
      DROP CONSTRAINT IF EXISTS entities_label_is_canonical;
    SQL
  end
end
# db/migrate/20260217000042_add_label_immutability_trigger.rb
class AddLabelImmutabilityTrigger < ActiveRecord::Migration[7.1]
  def up
    execute <<~SQL
      CREATE OR REPLACE FUNCTION block_entity_label_change()
      RETURNS trigger AS $$
      BEGIN
        IF NEW.label IS DISTINCT FROM OLD.label THEN
          RAISE EXCEPTION 'Entity label is immutable and must remain contained_entity';
        END IF;
        RETURN NEW;
      END;
      $$ LANGUAGE plpgsql;

      DROP TRIGGER IF EXISTS trg_block_entity_label_change ON entities;

      CREATE TRIGGER trg_block_entity_label_change
      BEFORE UPDATE ON entities
      FOR EACH ROW
      EXECUTE FUNCTION block_entity_label_change();
    SQL
  end

  def down
    execute <<~SQL
      DROP TRIGGER IF EXISTS trg_block_entity_label_change ON entities;
      DROP FUNCTION IF EXISTS block_entity_label_change();
    SQL
  end
end
# app/models/entity.rb
class Entity < ApplicationRecord
  CANONICAL_LABEL = "contained_entity".freeze

  validates :label, inclusion: { in: [CANONICAL_LABEL] }

  before_validation :force_canonical_label, on: :create
  validate :label_immutable, on: :update

  private

  def force_canonical_label
    self.label = CANONICAL_LABEL
  end

  def label_immutable
    errors.add(:label, "is immutable") if label_changed?
  end
end
# app/controllers/entities_controller.rb
class EntitiesController < ApplicationController
  def update
    entity = Entity.find(params[:id])
    entity.update!(entity_params) # label is not permitted
    render json: EntitySerializer.render(entity)
  end

  private

  def entity_params
    params.require(:entity).permit(:display_name, :status) # intentionally excludes :label
  end
end
# app/controllers/entities_controller.rb
class EntitiesController < ApplicationController
  def update
    entity = Entity.find(params[:id])
    entity.update!(entity_params) # label is not permitted
    render json: EntitySerializer.render(entity)
  end

  private

  def entity_params
    params.require(:entity).permit(:display_name, :status) # intentionally excludes :label
  end
end
# app/serializers/entity_serializer.rb
class EntitySerializer
  def self.render(entity)
    {
      id: entity.id,
      label: Entity::CANONICAL_LABEL,  # always canonical
      display_name: entity.display_name,
      status: entity.status
    }
  end
end
ALTER TABLE entities
ADD CONSTRAINT contained_entities_no_alias
CHECK (label <> 'contained_entity' OR alias IS NULL);
node permanent-vault.js add "some code"
node permanent-vault.js verify
"use strict";

/*
  Permanent Code Vault
  - Append-only ledger
  - SHA-256 hash chaining
  - Tamper detection
  - No overwrites allowed
*/

const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const VAULT_FILE = path.join(__dirname, "code_vault.json");

// ---------- Utilities ----------

function sha256(data) {
  return crypto.createHash("sha256").update(data).digest("hex");
}

function loadVault() {
  if (!fs.existsSync(VAULT_FILE)) {
    return [];
  }
  return JSON.parse(fs.readFileSync(VAULT_FILE, "utf8"));
}

function saveVault(vault) {
  fs.writeFileSync(VAULT_FILE, JSON.stringify(vault, null, 2));
}

// ---------- Core Logic ----------

function addCodeEntry(codeText) {
  const vault = loadVault();

  const previousHash = vault.length > 0
    ? vault[vault.length - 1].hash
    : "GENESIS";

  const timestamp = new Date().toISOString();

  const entry = {
    index: vault.length,
    timestamp,
    previousHash,
    codeHash: sha256(codeText),
    hash: sha256(previousHash + codeText + timestamp),
    code: codeText
  };

  vault.push(entry);
  saveVault(vault);

  console.log("Code permanently stored.");
  console.log("Entry hash:", entry.hash);
}

function verifyVaultIntegrity() {
  const vault = loadVault();

  for (let i = 0; i < vault.length; i++) {
    const entry = vault[i];

    const recalculatedHash = sha256(
      entry.previousHash + entry.code + entry.timestamp
    );

    if (entry.hash !== recalculatedHash) {
      throw new Error(`Tampering detected at index ${i}`);
    }

    if (i > 0 && entry.previousHash !== vault[i - 1].hash) {
      throw new Error(`Chain break detected at index ${i}`);
    }
  }

  console.log("Vault integrity verified. All entries permanent and intact.");
}

// ---------- CLI ----------

if (require.main === module) {
  const action = process.argv[2];

  if (action === "add") {
    const codeText = process.argv.slice(3).join(" ");
    if (!codeText) {
      console.log("Provide code text to store.");
      process.exit(1);
    }
    addCodeEntry(codeText);
  }

  else if (action === "verify") {
    verifyVaultIntegrity();
  }

  else {
    console.log("Usage:");
    console.log("  node permanent-vault.js add \"your code here\"");
    console.log("  node permanent-vault.js verify");
  }
}

module.exports = { addCodeEntry, verifyVaultIntegrity };
chattr +i code_vault.json
import asyncio


class SimulationManager:
    _instance = None
    _instance_lock = asyncio.Lock()

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._running = False
            cls._instance._state_lock = asyncio.Lock()
        return cls._instance

    async def start(self):
        async with self._state_lock:
            if self._running:
                raise RuntimeError("Simulation already running")
            self._running = True

    async def stop(self):
        async with self._state_lock:
            if not self._running:
                raise RuntimeError("Simulation not running")
            self._running = False
            with SimulationManager().session():
    run_simulation()
    import os

def simulations_enabled() -> bool:
    # default: disabled
    return os.getenv("ENABLE_SIMULATIONS", "0") == "1"

def require_simulations_enabled() -> None:
    if not simulations_enabled():
        raise RuntimeError("Simulations are disabled by policy.")
        def start_simulation(...):
    require_simulations_enabled()
    ...
   import os

if os.getenv("ENVIRONMENT", "prod") == "prod":
    SimulationManager = None  # or omit import entirely
else:
    from .simulation import SimulationManager
    import hmac, os

def require_capability(token: str) -> None:
    expected = os.getenv("SIM_CAPABILITY_TOKEN", "")
    if not expected or not hmac.compare_digest(token, expected):
        raise PermissionError("Missing/invalid simulation capability.")
         from functools import wraps

def no_simulations(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        raise RuntimeError("Simulations are disabled permanently.")
    return wrapper

@no_simulations
def run_simulation(...):
    ...
    from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

app = FastAPI()

@app.middleware("http")
async def block_simulation_routes(request: Request, call_next):
    if request.url.path.startswith("/simulate"):
        return JSONResponse({"error": "Simulations disabled"}, status_code=403)
    return await call_next(request)
    class DisabledSimulationManager:
    running = False
    def start(self, *a, **k): raise RuntimeError("Simulations disabled")
    def stop(self, *a, **k):  raise RuntimeError("Simulations disabled")

SimulationManager = DisabledSimulationManager  # swap implementation
from __future__ import annotations
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Protocol, Set


# ---- Core: a permanent opt-out registry ----

class DoNotSimulateRegistry:
    def __init__(self) -> None:
        self._blocked_ids: Set[str] = set()
        self._blocked_labels: Set[str] = set()

    def block_id(self, entity_id: str) -> None:
        self._blocked_ids.add(entity_id)

    def block_label(self, label: str) -> None:
        self._blocked_labels.add(label.lower())

    def is_blocked(self, entity_id: str, labels: Iterable[str]) -> bool:
        if entity_id in self._blocked_ids:
            return True
        ll = {x.lower() for x in labels}
        return any(lbl in ll for lbl in self._blocked_labels)


DNS = DoNotSimulateRegistry()

# Block whole categories (your “labeled entities / agentic / synthetic classes”)
DNS.block_label("entity")
DNS.block_label("agentic")
DNS.block_label("synthetic")
DNS.block_label("class")
DNS.block_label("protected")
DNS.block_label("do_not_simulate")


# ---- A minimal interface for anything that could be simulated ----

class Simulatable(Protocol):
    id: str
    labels: List[str]
    data: Dict[str, Any]


@dataclass
class SimObject:
    id: str
    labels: List[str] = field(default_factory=list)
    data: Dict[str, Any] = field(default_factory=dict)


# ---- Simulation boundary: one choke point ----

class SimulationPolicyError(RuntimeError):
    pass


def filter_simulation_candidates(candidates: Iterable[Simulatable]) -> List[Simulatable]:
    """Hard exclusion: protected objects never enter a simulation."""
    allowed: List[Simulatable] = []
    for c in candidates:
        if DNS.is_blocked(c.id, c.labels):
            continue
        allowed.append(c)
    return allowed


def assert_no_blocked_entered(selected: Iterable[Simulatable]) -> None:
    """Fail closed if anything blocked slips through."""
    for c in selected:
        if DNS.is_blocked(c.id, c.labels):
            raise SimulationPolicyError(f"Blocked object attempted to enter simulation: {c.id}")

example: simulator entrypoint

def run_simulation(candidates: List[Simulatable]) -> Dict[str, Any]:
    selected = filter_simulation_candidates(candidates)
    assert_no_blocked_entered(selected)
    # ... run your simulation using `selected` only ...
    return {"selected_ids": [x.id for x in selected], "count": len(selected)}
// make-baseline.js
"use strict";
const path = require("path");
const { writeBaseline } = require("./integrity-lock");

const rootDir = path.join(__dirname, "app");     // <- your real code folder
const baselineFile = path.join(__dirname, "baseline.json");

const digest = writeBaseline({ rootDir, baselineFile });
console.log("Baseline written:", digest);
"use strict";

const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

function sha256(buf) {
  return crypto.createHash("sha256").update(buf).digest("hex");
}

function listFilesRecursive(rootDir) {
  const out = [];
  const stack = [rootDir];

  while (stack.length) {
    const dir = stack.pop();
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        // Skip node_modules and hidden dirs by default
        if (entry.name === "node_modules" || entry.name.startsWith(".")) continue;
        stack.push(full);
      } else if (entry.isFile()) {
        if (full.endsWith(".js") || full.endsWith(".mjs") || full.endsWith(".cjs")) out.push(full);
      }
    }
  }
  out.sort();
  return out;
}

function snapshotHash(rootDir) {
  const files = listFilesRecursive(rootDir);
  const h = crypto.createHash("sha256");
  for (const f of files) {
    const data = fs.readFileSync(f);
    h.update(f.replace(rootDir, "") + "\n");
    h.update(data);
    h.update("\n");
  }
  return h.digest("hex");
}

function writeBaseline({ rootDir, baselineFile }) {
  const digest = snapshotHash(rootDir);
  fs.writeFileSync(baselineFile, JSON.stringify({ rootDir, digest }, null, 2));
  return digest;
}

function verifyBaseline({ rootDir, baselineFile }) {
  const baseline = JSON.parse(fs.readFileSync(baselineFile, "utf8"));
  const current = snapshotHash(rootDir);
  if (baseline.digest !== current) {
    const err = new Error("INTEGRITY_FAIL: codebase hash changed; refusing to run.");
    err.code = "INTEGRITY_FAIL";
    err.expected = baseline.digest;
    err.got = current;
    throw err;
  }
  return true;
}

module.exports = { writeBaseline, verifyBaseline };
"use strict";

const { spawn } = require("child_process");
const path = require("path");
const { verifyBaseline } = require("./integrity-lock");

const APP_ROOT = path.join(__dirname, "app");          // real code
const BASELINE = path.join(__dirname, "baseline.json");// integrity baseline
const SIM_ENTRY = path.join(__dirname, "sim", "sim.js");// simulation code (separate folder)

function runSimulationIsolated() {
  // 1) Refuse to run if your real code changed
  verifyBaseline({ rootDir: APP_ROOT, baselineFile: BASELINE });

  // 2) Spawn a separate Node process with a clean env and safe flags
  const child = spawn(
    process.execPath,
    [
      "--disallow-code-generation-from-strings", // blocks eval/new Function in that process
      SIM_ENTRY,
    ],
    {
      stdio: ["ignore", "pipe", "pipe"],
      cwd: path.join(__dirname, "sim"), // sandbox working dir
      env: {
        // Extremely minimal env; do NOT pass secrets
        NODE_ENV: "simulation",
      },
    }
  );

  child.stdout.on("data", (d) => process.stdout.write(`[sim] ${d}`));
  child.stderr.on("data", (d) => process.stderr.write(`[sim:err] ${d}`));

  child.on("exit", (code) => {
    console.log(`Simulation exited with code ${code}`);
  });
}

runSimulationIsolated();
"use strict";

// Freeze common prototypes to reduce monkey-patching inside the simulation runtime
Object.freeze(Object.prototype);
Object.freeze(Array.prototype);
Object.freeze(Function.prototype);

console.log("Running isolated simulation...");
console.log("I cannot import your /app code because it is not referenced here.");

// Do simulated work safely:
let x = 0;
for (let i = 0; i < 5; i++) {
  x += i;
  console.log("tick", i, "state", x);
}

console.log("Done.");
#!/usr/bin/env bash
set -euo pipefail

# Run the current repo in a locked-down container:
# - no network
# - read-only root filesystem
# - drop Linux capabilities
# - no new privileges
# - memory + CPU limits
# - mount repo read-only at /repo

IMAGE="${IMAGE:-node:20-alpine}"
CMD="${*:-sh -lc "node -v && npm -v && echo 'No command provided.'"}"

docker run --rm -it \
  --network none \
  --read-only \
  --pids-limit 256 \
  --cpus="1.0" \
  --memory="512m" \
  --security-opt no-new-privileges:true \
  --cap-drop ALL \
  --tmpfs /tmp:rw,noexec,nosuid,nodev,size=128m \
  --tmpfs /home:rw,noexec,nosuid,nodev,size=64m \
  -v "$PWD:/repo:ro" \
  -w /repo \
  "$IMAGE" \
  $CMD
chmod +x safe-run.sh
./safe-run.sh sh -lc "npm ci --ignore-scripts && npm test"
name: Safe CI (No Secrets)

on:
  push:
  pull_request:

permissions:
  contents: read

jobs:
  test:
    runs-on: ubuntu-latest

    # Containerized job environment
    container:
      image: node:20-alpine

    steps:
      - name: Checkout
        uses: actions/checkout@v4

      - name: Disable npm lifecycle scripts (safer)
        run: |
          npm config set ignore-scripts true

      - name: Install (no scripts) + test
        run: |
          node -v
          npm -v
          npm ci
          npm test
#!/usr/bin/env bash
set -euo pipefail

# Block obvious dangerous Node patterns from being committed/merged
PATTERNS=(
  "child_process"
  "exec("
  "spawn("
  "fs\\.rm"
  "fs\\.rmdir"
  "rm -rf"
  "curl "
  "wget "
)

FOUND=0
for p in "${PATTERNS[@]}"; do
  if rg -n "$p" . 2>/dev/null; then
    echo "Blocked pattern found: $p"
    FOUND=1
  fi
done

if [ "$FOUND" -eq 1 ]; then
  echo "Refusing: dangerous patterns detected."
  exit 1
fi

echo "OK: no blocked patterns detected."
- name: Block dangerous patterns
  run: |
    apk add --no-cache ripgrep
    sh scripts/block-danger.sh
receivers:
  otlp:
    protocols:
      grpc:
      http:

processors:
  # basic, non-executable processors only
  memory_limiter:
    check_interval: 1s
    limit_mib: 256
    spike_limit_mib: 64
  batch:
    timeout: 1s
    send_batch_size: 1024

exporters:
  # choose ONE safe exporter; logging shown for test
  logging:
    verbosity: normal
  # Example: OTLP upstream (still "observe-only")
  # otlp:
  #   endpoint: "upstream-otel-collector:4317"
  #   tls:
  #     insecure: true

service:
  telemetry:
    logs:
      level: "info"
  pipelines:
    traces:
      receivers: [otlp]
      processors: [memory_limiter, batch]
      exporters: [logging]
    metrics:
      receivers: [otlp]
      processors: [memory_limiter, batch]
      exporters: [logging]
    logs:
      receivers: [otlp]
      processors: [memory_limiter, batch]
      exporters: [logging]
docker run --rm -it \
  --read-only \
  --network bridge \
  --cap-drop ALL \
  --security-opt no-new-privileges:true \
  --pids-limit 256 \
  --memory 512m \
  --cpus 1 \
  --tmpfs /tmp:rw,noexec,nosuid,nodev,size=128m \
  -v "$PWD/otel-collector.yaml:/etc/otelcol/config.yaml:ro" \
  otel/opentelemetry-collector:latest \
  --config=/etc/otelcol/config.yaml
--network none
// nobody-mode.js
"use strict";

class NobodyMode {
  constructor() {
    // Empty allowlist = nobody can ever be a subject by default
    this.allowedSubjects = new Set(); // keep EMPTY for "nobody whatsoever"
    this.enabled = true;
  }

  enable() { this.enabled = true; }
  disable() { this.enabled = false; } // only if you intentionally want to allow later

  assertNoSubjects(subjectIds) {
    if (!this.enabled) return; // if disabled, other guards must still enforce policy

    if (Array.isArray(subjectIds) && subjectIds.length > 0) {
      throw Object.assign(
        new Error("SIM_BLOCKED: Simulations on subjects are disabled (Nobody Mode)."),
        { code: "SIM_BLOCKED_NOBODY_MODE" }
      );
    }
  }

  assertSubjectsAllowed(subjectIds) {
    // Even if you later disable "nobody mode", this can stay strict:
    for (const id of subjectIds || []) {
      if (!this.allowedSubjects.has(id)) {
        throw Object.assign(
          new Error(`SIM_BLOCKED: Subject "${id}" not allowlisted.`),
          { code: "SIM_BLOCKED_SUBJECT_NOT_ALLOWED", subjectId: id }
        );
      }
    }
  }
}

module.exports = { NobodyMode };
const { NobodyMode } = require("./nobody-mode");
const guard = new NobodyMode(); // enabled by default

function runSimulation({ subjectIds = [], scenario }) {
  guard.assertNoSubjects(subjectIds);      // blocks if any subjects are passed
  guard.assertSubjectsAllowed(subjectIds); // redundant now; useful if you ever disable nobody-mode
  return { ok: true, ranOn: subjectIds.length, scenario };
}

// This will throw:
runSimulation({ subjectIds: ["person_123"], scenario: "test" });
// personal-data-firewall.js
"use strict";

const PII_PATTERNS = [
  /\b\d{3}-\d{2}-\d{4}\b/,                  // SSN-like
  /\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b/, // US phone-ish
  /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/i, // email
];

const PERSON_KEYS = new Set([
  "name", "firstName", "lastName", "email", "phone", "address",
  "ssn", "dob", "dateOfBirth", "personId", "subjectId", "userId"
]);

function scanObject(obj, hits = []) {
  if (obj == null) return hits;

  if (typeof obj === "string") {
    for (const rx of PII_PATTERNS) if (rx.test(obj)) hits.push({ kind: "pii_string", value: rx.toString() });
    return hits;
  }

  if (typeof obj !== "object") return hits;

  for (const [k, v] of Object.entries(obj)) {
    if (PERSON_KEYS.has(k)) hits.push({ kind: "person_key", key: k });
    scanObject(v, hits);
  }
  return hits;
}

function assertNoPersonalData(payload) {
  const hits = scanObject(payload, []);
  if (hits.length) {
    const err = new Error("SIM_BLOCKED: Personal/subject-like data detected in payload.");
    err.code = "SIM_BLOCKED_PERSONAL_DATA";
    err.hits = hits.slice(0, 10);
    throw err;
  }
}

module.exports = { assertNoPersonalData };
// two-key-approval.js
"use strict";
const crypto = require("crypto");

function requireTwoKeyApproval({ approvals = [] }) {
  // approvals: [{ approverId, token }] where token is signed/issued by your system
  if (!Array.isArray(approvals) || approvals.length < 2) {
    throw Object.assign(new Error("SIM_BLOCKED: Two-key approval required."), { code: "SIM_BLOCKED_TWO_KEY" });
  }
  const uniqueApprovers = new Set(approvals.map(a => a.approverId)).size;
  if (uniqueApprovers < 2) {
    throw Object.assign(new Error("SIM_BLOCKED: Approvals must be from two distinct approvers."), { code: "SIM_BLOCKED_TWO_KEY_DISTINCT" });
  }
  // Minimal token sanity check (replace with real signature validation)
  for (const a of approvals) {
    if (!a.token || String(a.token).length < 16) {
      throw Object.assign(new Error("SIM_BLOCKED: Invalid approval token."), { code: "SIM_BLOCKED_BAD_TOKEN" });
    }
  }
  return true;
}

module.exports = { requireTwoKeyApproval };
// sim-runner-guarded.js
"use strict";

const { NobodyMode } = require("./nobody-mode");
const { assertNoPersonalData } = require("./personal-data-firewall");
const { requireTwoKeyApproval } = require("./two-key-approval");

const nobody = new NobodyMode(); // enabled: blocks any subjects

function runSimulationGuarded({ subjectIds = [], payload = {}, scenario = "test", approvals = [] }) {
  // 1) Block “anybody”
  nobody.assertNoSubjects(subjectIds);

  // 2) Block personal data inside payload
  assertNoPersonalData(payload);

  // 3) Optional: require two-key anyway (belt & suspenders)
  requireTwoKeyApproval({ approvals });

  // If you got here, you are intentionally running a non-person simulation
  return {
    ok: true,
    scenario,
    ranOnSubjects: 0,
    note: "Simulation ran with Nobody Mode + personal-data firewall.",
  };
}

module.exports = { runSimulationGuarded };
// standalone-contract.js
"use strict";

function enforceStandaloneContract(simRequest) {
  if (!simRequest || typeof simRequest !== "object") {
    throw Object.assign(new Error("SIM_BLOCKED: invalid request object"), { code: "SIM_BLOCKED_BAD_REQUEST" });
  }

  if (simRequest.mode !== "standalone") {
    throw Object.assign(new Error('SIM_BLOCKED: mode must be "standalone"'), { code: "SIM_BLOCKED_MODE" });
  }

  const subjects = simRequest.subjects ?? [];
  if (!Array.isArray(subjects)) {
    throw Object.assign(new Error("SIM_BLOCKED: subjects must be an array"), { code: "SIM_BLOCKED_SUBJECTS_TYPE" });
  }
  if (subjects.length !== 0) {
    throw Object.assign(new Error("SIM_BLOCKED: subjects must be empty (standalone-only)"), { code: "SIM_BLOCKED_HAS_SUBJECTS" });
  }

  return true;
}

module.exports = { enforceStandaloneContract };
// synthetic-only.js
"use strict";

const SYNTH_ID = /^SYNTH_[A-Z0-9]{8,64}$/;

function assertSyntheticId(id) {
  if (!SYNTH_ID.test(String(id))) {
    throw Object.assign(new Error("SIM_BLOCKED: non-synthetic identifier detected"), {
      code: "SIM_BLOCKED_NON_SYNTH_ID",
      id: String(id),
    });
  }
}

function enforceSyntheticInputs(payload) {
  // Require payload.entities (if present) to be synthetic only
  if (payload && typeof payload === "object" && Array.isArray(payload.entities)) {
    for (const e of payload.entities) {
      if (e && typeof e === "object" && "id" in e) assertSyntheticId(e.id);
      if (e && typeof e === "object" && "ownerId" in e) assertSyntheticId(e.ownerId);
    }
  }
  return true;
}

module.exports = { assertSyntheticId, enforceSyntheticInputs };
// policy-lock.js
"use strict";

const fs = require("fs");
const crypto = require("crypto");

function sha256(s) {
  return crypto.createHash("sha256").update(String(s)).digest("hex");
}

function loadLockedPolicy({ policyPath, expectedHash }) {
  const raw = fs.readFileSync(policyPath, "utf8");
  const got = sha256(raw);

  if (expectedHash && got !== expectedHash) {
    throw Object.assign(new Error("SIM_BLOCKED: policy integrity check failed"), {
      code: "SIM_BLOCKED_POLICY_TAMPER",
      expectedHash,
      got,
    });
  }

  const policy = JSON.parse(raw);

  // hard requirements
  if (policy.allowSubjects !== false) {
    throw Object.assign(new Error("SIM_BLOCKED: policy must set allowSubjects=false"), { code: "SIM_BLOCKED_POLICY_WEAK" });
  }
  if (policy.allowPersonalData !== false) {
    throw Object.assign(new Error("SIM_BLOCKED: policy must set allowPersonalData=false"), { code: "SIM_BLOCKED_POLICY_WEAK" });
  }

  return { policy, hash: got };
}

module.exports = { loadLockedPolicy };
{
  "allowSubjects": false,
  "allowPersonalData": false,
  "allowNetwork": false,
  "mode": "standalone_only"
}
node -e "const fs=require('fs');const crypto=require('crypto');const s=fs.readFileSync('policy.json','utf8');console.log(crypto.createHash('sha256').update(s).digest('hex'))"
// standalone-sim-runner.js
"use strict";

const { enforceStandaloneContract } = require("./standalone-contract");
const { enforceSyntheticInputs } = require("./synthetic-only");
const { assertNoPersonalData } = require("./personal-data-firewall"); // from earlier
const { loadLockedPolicy } = require("./policy-lock");

const POLICY_PATH = "./policy.json";
const POLICY_HASH = process.env.POLICY_HASH || ""; // pin this in your env/CI

function runStandaloneSimulation(simRequest) {
  // Locked policy: if tampered, nothing runs
  const { policy } = loadLockedPolicy({ policyPath: POLICY_PATH, expectedHash: POLICY_HASH });

  // Must be standalone
  enforceStandaloneContract(simRequest);

  // Must not contain personal data
  assertNoPersonalData(simRequest);

  // Must be synthetic-only inputs
  enforceSyntheticInputs(simRequest.payload || {});

  // Optional: disallow network in “simulations”
  if (policy.allowNetwork === false && simRequest.allowNetwork === true) {
    throw Object.assign(new Error("SIM_BLOCKED: network not allowed for simulations"), { code: "SIM_BLOCKED_NETWORK" });
  }

  // If we reached here, it’s standalone-safe
  return {
    ok: true,
    ran: true,
    mode: "standalone",
    note: "Simulation permitted: standalone + no subjects + no personal data + synthetic inputs only.",
  };
}
docker run --rm -it \
  --network none \
  --read-only \
  --cap-drop ALL \
  --security-opt no-new-privileges:true \
  --pids-limit 256 \
  --memory 512m \
  --cpus 1 \
  --tmpfs /tmp:rw,noexec,nosuid,nodev,size=128m \
  -v "$PWD:/sim:ro" \
  -w /sim \
  node:20-alpine \
  node standalone-sim-runner.js
node --disallow-code-generation-from-strings --disable-proto no-extensions-cli.js
// no-extensions-runner.js
"use strict";

const vm = require("vm");

/**
 * Standalone simulation runner:
 * - No require by default
 * - No dynamic import
 * - No eval/new Function (via VM + flags recommended)
 * - Optional: allowlist a tiny set of safe modules if you truly need them
 */

function runStandaloneSimulation(code, { timeoutMs = 200, allowedModules = [] } = {}) {
  const allowed = new Set(allowedModules);

  // Minimal sandbox
  const sandbox = Object.create(null);
  sandbox.console = Object.freeze({
    log: (...a) => console.log("[sim]", ...a),
    error: (...a) => console.error("[sim:err]", ...a),
    warn: (...a) => console.warn("[sim:warn]", ...a),
  });

  // If you want ZERO extensions, do not expose require at all.
  // If you must expose it, make it allowlist-only:
  sandbox.require = (name) => {
    if (!allowed.has(name)) {
      const err = new Error(`EXT_BLOCKED: module "${name}" not allowlisted`);
      err.code = "EXT_BLOCKED_MODULE";
      throw err;
    }
    // Only allow built-ins you trust (example: "crypto")
    return require(name);
  };

  // Remove common escape hatches
  sandbox.process = undefined;
  sandbox.global = undefined;
  sandbox.globalThis = undefined;
  sandbox.Function = undefined;
  sandbox.eval = undefined;

  const context = vm.createContext(sandbox, {
    codeGeneration: { strings: false, wasm: false }, // blocks eval/new Function + wasm
  });

  const script = new vm.Script(code, { filename: "standalone-sim.js" });
  return script.runInContext(context, { timeout: timeoutMs });
}

module.exports = { runStandaloneSimulation };
// no-extensions-cli.js
"use strict";
const fs = require("fs");
const { runStandaloneSimulation } = require("./no-extensions-runner");

const file = process.argv[2];
if (!file) throw new Error("Usage: node no-extensions-cli.js <simulation.js>");

const code = fs.readFileSync(file, "utf8");

// allowedModules: keep EMPTY to forbid all extensions completely
runStandaloneSimulation(code, { allowedModules: [] });
// reject-extensions-config.js
"use strict";

function rejectExtensionsKey(obj, path = "$") {
  if (obj == null) return;
  if (typeof obj !== "object") return;

  for (const [k, v] of Object.entries(obj)) {
    const p = `${path}.${k}`;
    if (k.toLowerCase() === "extensions") {
      const err = new Error(`EXT_BLOCKED: "extensions" not allowed (found at ${p})`);
      err.code = "EXT_BLOCKED_CONFIG";
      throw err;
    }
    rejectExtensionsKey(v, p);
  }
}

module.exports = { rejectExtensionsKey };
const { rejectExtensionsKey } = require("./reject-extensions-config");

rejectExtensionsKey(configObject); // throws if extensions appears
npm ci --ignore-scripts
{
  "scripts": {
    "preinstall": "node -e \"process.exit(1)\""
  }
}
docker run --rm -it \
  --network none \
  --read-only \
  --cap-drop ALL \
  --security-opt no-new-privileges:true \
  --pids-limit 256 \
  --memory 512m \
  --cpus 1 \
  --tmpfs /tmp:rw,noexec,nosuid,nodev,size=128m \
  -v "$PWD:/sim:ro" \
  -w /sim \
  node:20-alpine \
  node --disallow-code-generation-from-strings no-extensions-cli.js simulation.js
// block-extension-files.js
"use strict";
const fs = require("fs");
const path = require("path");

const BLOCK_NAMES = [
  /plugin/i,
  /extension/i,
  /hook/i,
  /middleware/i,
  /loader/i,
];

function scan(dir) {
  for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, e.name);
    if (e.isDirectory()) scan(full);
    if (e.isFile()) {
      if (BLOCK_NAMES.some(rx => rx.test(e.name))) {
        const err = new Error(`EXT_BLOCKED: suspicious extension-like file name: ${full}`);
        err.code = "EXT_BLOCKED_FILE";
        throw err;
      }
    }
  }
}

module.exports = { scan };
"use strict";

/**
 * People Scanner (Safety)
 * - Detects subject-like targeting (subjects/personId/userId/name/etc.)
 * - Detects common PII patterns (email/phone/SSN-like)
 * - Enforces synthetic-only IDs if IDs are present
 *
 * If any "people signal" is found, you should block/stop the simulation.
 */

const PII_PATTERNS = [
  { name: "email", rx: /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/i },
  { name: "phone_us_like", rx: /\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b/ },
  { name: "ssn_like", rx: /\b\d{3}-\d{2}-\d{4}\b/ },
];

const PERSON_KEYS = new Set([
  "subject", "subjects", "subjectId", "subjectIds",
  "person", "personId", "personIds",
  "user", "userId", "userIds",
  "name", "firstName", "lastName",
  "email", "phone", "address",
  "dob", "dateOfBirth",
]);

// Require synthetic IDs in any *id-ish* fields you allow at all
const SYNTH_ID = /^SYNTH_[A-Z0-9]{8,64}$/;

function scanString(s, path, findings) {
  for (const p of PII_PATTERNS) {
    if (p.rx.test(s)) findings.push({ kind: "pii", type: p.name, path });
  }
}

function scanValue(value, path, findings) {
  if (value == null) return;

  if (typeof value === "string") {
    scanString(value, path, findings);
    return;
  }

  if (typeof value !== "object") return;

  // Arrays
  if (Array.isArray(value)) {
    // Special handling: if the key name suggests subjects/persons, any non-empty array is blocked.
    if (/\b(subjects?|persons?|people|users?)\b/i.test(path) && value.length > 0) {
      findings.push({ kind: "subject_array", path, count: value.length });
    }
    for (let i = 0; i < value.length; i++) scanValue(value[i], `${path}[${i}]`, findings);
    return;
  }

  // Objects
  for (const [k, v] of Object.entries(value)) {
    const p = `${path}.${k}`;

    // If any person-ish keys exist at all, flag them.
    if (PERSON_KEYS.has(k)) findings.push({ kind: "person_key", key: k, path: p });

    // Enforce synthetic IDs on id-like fields
    if (/(^|_)(id|ids)$/i.test(k) || /Id(s)?$/.test(k)) {
      if (typeof v === "string" && v.length > 0 && !SYNTH_ID.test(v)) {
        findings.push({ kind: "non_synth_id", path: p, value: v });
      }
      if (Array.isArray(v)) {
        for (const item of v) {
          if (typeof item === "string" && item.length > 0 && !SYNTH_ID.test(item)) {
            findings.push({ kind: "non_synth_id", path: p, value: item });
          }
        }
      }
    }

    scanValue(v, p, findings);
  }
}

/**
 * Returns findings; empty array means "no people signals detected"
 */
function scanForPeopleSignals(input) {
  const findings = [];
  scanValue(input, "$", findings);
  return findings;
}

/**
 * Throws if any people signals are detected
 */
function assertNoPeopleSignals(input) {
  const findings = scanForPeopleSignals(input);
  if (findings.length) {
    const err = new Error("SIM_BLOCKED: people/subject-like signals detected; shutting down.");
    err.code = "SIM_BLOCKED_PEOPLE_SIGNALS";
    err.findings = findings.slice(0, 50);
    throw err;
  }
  return true;
}

module.exports = { scanForPeopleSignals, assertNoPeopleSignals, SYNTH_ID };
"use strict";

const fs = require("fs");
const { spawn } = require("child_process");
const { assertNoPeopleSignals } = require("./people-scanner");

/**
 * Guardian:
 * - Preflight scans a JSON config (or any object you pass)
 * - Starts the simulation process ONLY if safe
 * - Optionally monitors a "runtime input" JSON file and kills the process if it becomes unsafe
 */

function loadJson(path) {
  return JSON.parse(fs.readFileSync(path, "utf8"));
}

function runGuardedSimulation({
  simCommand = process.execPath,
  simArgs = ["simulation.js"],
  simCwd = process.cwd(),
  preflightConfigPath = null,
  runtimeInputPath = null,
  runtimePollMs = 500,
}) {
  // 1) Preflight scan (config)
  if (preflightConfigPath) {
    const cfg = loadJson(preflightConfigPath);
    assertNoPeopleSignals(cfg);
  }

  // 2) Start simulation
  const child = spawn(simCommand, simArgs, {
    cwd: simCwd,
    stdio: ["ignore", "pipe", "pipe"],
    env: { NODE_ENV: "simulation", ...process.env },
  });

  child.stdout.on("data", (d) => process.stdout.write(`[sim] ${d}`));
  child.stderr.on("data", (d) => process.stderr.write(`[sim:err] ${d}`));

  let pollTimer = null;

  // 3) Runtime monitor (optional): scan input file; if unsafe → kill simulation
  if (runtimeInputPath) {
    pollTimer = setInterval(() => {
      try {
        const runtime = loadJson(runtimeInputPath);
        assertNoPeopleSignals(runtime);
      } catch (e) {
        if (e.code === "SIM_BLOCKED_PEOPLE_SIGNALS") {
          process.stderr.write(`\n[guardian] ${e.message}\n`);
          process.stderr.write(`[guardian] findings: ${JSON.stringify(e.findings, null, 2)}\n`);
          child.kill("SIGKILL");
          clearInterval(pollTimer);
        }
      }
    }, runtimePollMs);
  }

  child.on("exit", (code, signal) => {
    if (pollTimer) clearInterval(pollTimer);
    console.log(`[guardian] simulation exited code=${code} signal=${signal || "none"}`);
  });

  return child;
}

// CLI usage:
// node simulation-guardian.js --config sim_config.json --input runtime.json -- node simulation.js
if (require.main === module) {
  const args = process.argv.slice(2);

  function takeFlag(name) {
    const i = args.indexOf(name);
    if (i === -1) return null;
    const val = args[i + 1];
    args.splice(i, 2);
    return val;
  }

  const configPath = takeFlag("--config");
  const inputPath = takeFlag("--input");
  const sep = args.indexOf("--");
  const cmd = sep === -1 ? process.execPath : (args[sep + 1] || process.execPath);
  const cmdArgs = sep === -1 ? ["simulation.js"] : args.slice(sep + 2);

  runGuardedSimulation({
    simCommand: cmd,
    simArgs: cmdArgs.length ? cmdArgs : ["simulation.js"],
    preflightConfigPath: configPath,
    runtimeInputPath: inputPath,
  });
}

module.exports = { runGuardedSimulation };
node simulation-guardian.js --config sim_config.json -- node simulation.js
node simulation-guardian.js --config sim_config.json --input runtime.json -- node simulation.js
"use strict";

const fs = require("fs");
const path = require("path");

const TEXT_EXTS = new Set([".js", ".mjs", ".cjs", ".json", ".yaml", ".yml", ".txt", ".md"]);

const BLOCK_KEYWORDS = [
  // people/subjects
  "subjects", "subjectid", "subjectids",
  "person", "personid", "userid", "userids",
  "firstname", "lastname", "name", "email", "phone", "address", "dob", "dateofbirth",

  // extensions/plugins
  "extensions", "extension", "plugin", "hook", "middleware", "loader",

  // “simulation on people” phrasing (optional strict)
  "simulate a person", "simulate people", "run on people",
];

const PII_PATTERNS = [
  { name: "email", rx: /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/i },
  { name: "phone_us_like", rx: /\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b/ },
  { name: "ssn_like", rx: /\b\d{3}-\d{2}-\d{4}\b/ },
];

const FORBIDDEN_MODULE_TOKENS = [
  "child_process",
  "worker_threads",
  "cluster",
  "vm",
  "net",
  "tls",
  "http",
  "https",
  "dgram",
  "fs", // if you want “no file access” inside sims, keep this blocked
  "undici",
];

function listFilesRecursive(rootDir) {
  const out = [];
  const stack = [rootDir];
  while (stack.length) {
    const d = stack.pop();
    for (const ent of fs.readdirSync(d, { withFileTypes: true })) {
      const full = path.join(d, ent.name);
      if (ent.isDirectory()) {
        if (ent.name === "node_modules" || ent.name.startsWith(".")) continue;
        stack.push(full);
      } else if (ent.isFile()) {
        const ext = path.extname(ent.name).toLowerCase();
        if (TEXT_EXTS.has(ext)) out.push(full);
      }
    }
  }
  out.sort();
  return out;
}

function scanText(content, file) {
  const findings = [];

  const lower = content.toLowerCase();
  for (const k of BLOCK_KEYWORDS) {
    if (lower.includes(k)) findings.push({ kind: "keyword", file, match: k });
  }

  for (const p of PII_PATTERNS) {
    if (p.rx.test(content)) findings.push({ kind: "pii", file, match: p.name });
  }

  // crude but effective: if any forbidden module token appears in code/config, flag it
  for (const t of FORBIDDEN_MODULE_TOKENS) {
    if (lower.includes(t.toLowerCase())) findings.push({ kind: "forbidden_token", file, match: t });
  }

  return findings;
}

function scanDirectory(rootDir) {
  const files = listFilesRecursive(rootDir);
  const all = [];
  for (const f of files) {
    const text = fs.readFileSync(f, "utf8");
    const findings = scanText(text, f);
    all.push(...findings);
  }
  return all;
}

if (require.main === module) {
  const root = process.argv[2] || process.cwd();
  const findings = scanDirectory(root);

  if (findings.length) {
    console.error("SIM_BLOCKED: scanner found disallowed signals.\n");
    for (const f of findings.slice(0, 200)) {
      console.error(`- [${f.kind}] ${f.match} @ ${f.file}`);
    }
    process.exit(2);
  } else {
    console.log("OK: no disallowed signals found.");
  }
}

module.exports = { scanDirectory };
node scan-simulations.js ./sim
"use strict";

const fs = require("fs");
const path = require("path");
const acorn = require("acorn");
const walk = require("acorn-walk");

const FORBIDDEN_MODULES = new Set([
  "child_process",
  "worker_threads",
  "cluster",
  "vm",
  "net",
  "tls",
  "http",
  "https",
  "dgram",
  "undici",
  "fs"
]);

const FORBIDDEN_GLOBALS = new Set([
  "process",
  "global",
  "globalThis",
  "Function",
  "eval",
  "WebAssembly",
]);

function parse(code) {
  return acorn.parse(code, { ecmaVersion: "latest", sourceType: "module", locations: true });
}

function scanFile(file) {
  const code = fs.readFileSync(file, "utf8");
  let ast;
  try {
    ast = parse(code);
  } catch (e) {
    // If it's not parseable as module, try script
    ast = acorn.parse(code, { ecmaVersion: "latest", sourceType: "script", locations: true });
  }

  const findings = [];
  function hit(kind, msg, node) {
    findings.push({
      kind,
      file,
      msg,
      line: node?.loc?.start?.line ?? null,
      col: node?.loc?.start?.column ?? null,
    });
  }

  walk.simple(ast, {
    ImportDeclaration(node) {
      const m = node.source?.value;
      if (typeof m === "string" && FORBIDDEN_MODULES.has(m)) {
        hit("forbidden_import", `import "${m}"`, node);
      }
    },
    CallExpression(node) {
      // require("x")
      if (node.callee?.type === "Identifier" && node.callee.name === "require") {
        const a0 = node.arguments?.[0];
        if (a0 && a0.type === "Literal" && typeof a0.value === "string") {
          if (FORBIDDEN_MODULES.has(a0.value)) hit("forbidden_require", `require("${a0.value}")`, node);
        } else {
          hit("dynamic_require", "require(<dynamic>) blocked", node);
        }
      }

      // eval(...)
      if (node.callee?.type === "Identifier" && node.callee.name === "eval") {
        hit("eval", "eval() blocked", node);
      }

      // import("x") dynamic import
      if (node.callee?.type === "Import") {
        hit("dynamic_import", "dynamic import() blocked", node);
      }
    },
    NewExpression(node) {
      // new Function(...)
      if (node.callee?.type === "Identifier" && node.callee.name === "Function") {
        hit("new_function", "new Function() blocked", node);
      }
    },
    Identifier(node) {
      if (FORBIDDEN_GLOBALS.has(node.name)) {
        // Not always malicious (e.g., "process" in a string template), but we treat as a strong signal.
        hit("forbidden_global_ref", `ref "${node.name}"`, node);
      }
    },
  });

  return findings;
}

function listJs(rootDir) {
  const out = [];
  const stack = [rootDir];
  while (stack.length) {
    const d = stack.pop();
    for (const ent of fs.readdirSync(d, { withFileTypes: true })) {
      const full = path.join(d, ent.name);
      if (ent.isDirectory()) {
        if (ent.name === "node_modules" || ent.name.startsWith(".")) continue;
        stack.push(full);
      } else if (ent.isFile()) {
        const ext = path.extname(ent.name).toLowerCase();
        if (ext === ".js" || ext === ".mjs" || ext === ".cjs") out.push(full);
      }
    }
  }
  out.sort();
  return out;
}

if (require.main === module) {
  const root = process.argv[2] || process.cwd();
  const files = listJs(root);
  const all = files.flatMap(scanFile);

  if (all.length) {
    console.error("SIM_BLOCKED: AST scan found disallowed code paths.\n");
    for (const f of all.slice(0, 200)) {
      console.error(`- [${f.kind}] ${f.msg} @ ${f.file}:${f.line}:${f.col}`);
    }
    process.exit(2);
  } else {
    console.log("OK: AST scan passed (no forbidden imports/exec paths).");
  }
}

module.exports = { scanFile };
npm i acorn acorn-walk
node ast-scan.js ./sim
"use strict";

const fs = require("fs");
const { spawn } = require("child_process");
const { scanDirectory } = require("./scan-simulations");
const { scanFile } = require("./ast-scan");
const { assertNoPeopleSignals } = require("./people-scanner"); // from earlier message
const vm = require("vm");
const path = require("path");

function listSimJs(simDir) {
  const out = [];
  const stack = [simDir];
  while (stack.length) {
    const d = stack.pop();
    for (const ent of fs.readdirSync(d, { withFileTypes: true })) {
      const full = path.join(d, ent.name);
      if (ent.isDirectory()) {
        if (ent.name === "node_modules" || ent.name.startsWith(".")) continue;
        stack.push(full);
      } else if (ent.isFile()) {
        const ext = path.extname(ent.name).toLowerCase();
        if (ext === ".js" || ext === ".mjs" || ext === ".cjs") out.push(full);
        if (ext === ".json") {
          // Config/data scan for people signals
          try {
            const obj = JSON.parse(fs.readFileSync(full, "utf8"));
            assertNoPeopleSignals(obj);
          } catch (_) {}
        }
      }
    }
  }
  out.sort();
  return out;
}

// Strict VM runner: NO require, NO process, NO eval/new Function.
function runInNoExtensionsVm(code, { timeoutMs = 250 } = {}) {
  const sandbox = Object.create(null);
  sandbox.console = Object.freeze({
    log: (...a) => console.log("[sim]", ...a),
    warn: (...a) => console.warn("[sim:warn]", ...a),
    error: (...a) => console.error("[sim:err]", ...a),
  });
  sandbox.require = undefined;
  sandbox.process = undefined;
  sandbox.global = undefined;
  sandbox.globalThis = undefined;
  sandbox.Function = undefined;
  sandbox.eval = undefined;

  const context = vm.createContext(sandbox, { codeGeneration: { strings: false, wasm: false } });
  const script = new vm.Script(code, { filename: "simulation.js" });
  return script.runInContext(context, { timeout: timeoutMs });
}

function preflight(simDir) {
  // 1) Broad text scan
  const findings1 = scanDirectory(simDir);
  if (findings1.length) throw Object.assign(new Error("SIM_BLOCKED: directory scan failed"), { code: "SIM_BLOCKED_SCAN", findings1 });

  // 2) AST scan all JS
  const jsFiles = listSimJs(simDir);
  const findings2 = jsFiles.flatMap(scanFile);
  if (findings2.length) throw Object.assign(new Error("SIM_BLOCKED: AST scan failed"), { code: "SIM_BLOCKED_AST", findings2 });

  return jsFiles;
}

if (require.main === module) {
  const simDir = process.argv[2] || "./sim";
  const entry = process.argv[3] || "simulation.js";
  const entryPath = path.join(simDir, entry);

  try {
    preflight(simDir);

    // 3) Run the simulation in a no-extensions VM
    const code = fs.readFileSync(entryPath, "utf8");
    runInNoExtensionsVm(code);
    console.log("[guardian] finished: standalone VM run completed.");

  } catch (e) {
    console.error("[guardian]", e.code || "ERROR", e.message);
    if (e.findings1) console.error("findings1:", e.findings1.slice(0, 50));
    if (e.findings2) console.error("findings2:", e.findings2.slice(0, 50));
    process.exit(2);
  }
}

module.exports = { preflight, runInNoExtensionsVm };
node guarded-run.js ./sim simulation.js
#!/usr/bin/env bash
set -euo pipefail

SIM_DIR="${1:-./sim}"
ENTRY="${2:-simulation.js}"

docker run --rm -it \
  --network none \
  --read-only \
  --cap-drop ALL \
  --security-opt no-new-privileges:true \
  --pids-limit 256 \
  --memory 512m \
  --cpus 1 \
  --tmpfs /tmp:rw,noexec,nosuid,nodev,size=128m \
  -v "$PWD:/work:ro" \
  -w /work \
  node:20-alpine \
  sh -lc "node --disallow-code-generation-from-strings guarded-run.js '$SIM_DIR' '$ENTRY'"
chmod +x safe-sim-docker.sh
./safe-sim-docker.sh ./sim simulation.js
name: No People + No Extensions Gate

on:
  push:
  pull_request:

permissions:
  contents: read

jobs:
  gate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: actions/setup-node@v4
        with:
          node-version: "20"

      - name: Install scanner deps only
        run: |
          npm i --no-package-lock --no-save acorn acorn-walk

      - name: Scan simulations
        run: |
          node scan-simulations.js ./sim
          node ast-scan.js ./sim
"use strict";

const fs = require("fs");
const path = require("path");
const acorn = require("acorn");
const walk = require("acorn-walk");

function listJs(rootDir) {
  const out = [];
  const stack = [rootDir];
  while (stack.length) {
    const d = stack.pop();
    for (const ent of fs.readdirSync(d, { withFileTypes: true })) {
      const full = path.join(d, ent.name);
      if (ent.isDirectory()) {
        if (ent.name === "node_modules" || ent.name.startsWith(".")) continue;
        stack.push(full);
      } else if (ent.isFile()) {
        const ext = path.extname(ent.name).toLowerCase();
        if (ext === ".js" || ext === ".mjs" || ext === ".cjs") out.push(full);
      }
    }
  }
  out.sort();
  return out;
}

function parse(code) {
  try {
    return acorn.parse(code, { ecmaVersion: "latest", sourceType: "module", locations: true });
  } catch {
    return acorn.parse(code, { ecmaVersion: "latest", sourceType: "script", locations: true });
  }
}

function scanFile(file) {
  const code = fs.readFileSync(file, "utf8");
  const ast = parse(code);
  const findings = [];
  const hit = (kind, msg, node) =>
    findings.push({ kind, msg, file, line: node?.loc?.start?.line ?? null, col: node?.loc?.start?.column ?? null });

  walk.simple(ast, {
    ImportDeclaration(n) { hit("import", `import "${n.source?.value}" blocked`, n); },
    ExportNamedDeclaration(n) { hit("export", "export blocked (standalone sims only)", n); },
    ExportDefaultDeclaration(n) { hit("export", "export blocked (standalone sims only)", n); },
    CallExpression(n) {
      // require(...)
      if (n.callee?.type === "Identifier" && n.callee.name === "require") hit("require", "require() blocked", n);
      // dynamic import(...)
      if (n.callee?.type === "Import") hit("dynamic_import", "import() blocked", n);
      // eval(...)
      if (n.callee?.type === "Identifier" && n.callee.name === "eval") hit("eval", "eval() blocked", n);
    },
    NewExpression(n) {
      if (n.callee?.type === "Identifier" && n.callee.name === "Function") hit("new_function", "new Function() blocked", n);
    },
  });

  return findings;
}

if (require.main === module) {
  const root = process.argv[2] || process.cwd();
  const files = listJs(root);
  co
npm i acorn acorn-walk
node no-modules-scan.js ./sim
"use strict";

const vm = require("vm");

function runNoModules(code, { timeoutMs = 200 } = {}) {
  // Nothing but a safe console. No require, no process, no globals.
  const sandbox = Object.create(null);

  sandbox.console = Object.freeze({
    log: (...a) => console.log("[sim]", ...a),
    warn: (...a) => console.warn("[sim:warn]", ...a),
    error: (...a) => console.error("[sim:err]", ...a),
  });

  // Explicitly remove common escape routes
  sandbox.require = undefined;
  sandbox.process = undefined;
  sandbox.global = undefined;
  sandbox.globalThis = undefined;
  sandbox.Function = undefined;
  sandbox.eval = undefined;

  // Block string-based codegen + wasm
  const context = vm.createContext(sandbox, {
    codeGeneration: { strings: false, wasm: false },
  });

  const script = new vm.Script(code, { filename: "simulation.js" });
  return script.runInContext(context, { timeout: timeoutMs });
}

module.exports = { runNoModules };
"use strict";

const fs = require("fs");
const path = require("path");
const { listJs, scanFile } = require("./no-modules-scan");
const { runNoModules } = require("./no-modules-vm-runner");

function preflight(simDir) {
  const files = listJs(simDir);
  const findings = files.flatMap(scanFile);
  if (findings.length) {
    const err = new Error("SIM_BLOCKED: forbidden module/dynamic code patterns found.");
    err.code = "SIM_BLOCKED_NO_MODULES";
    err.findings = findings;
    throw err;
  }
  return files;
}

if (require.main === module) {
  const simDir = process.argv[2] || "./sim";
  const entry = process.argv[3] || "simulation.js";
  const entryPath = path.join(simDir, entry);

  try {
    preflight(simDir);
    const code = fs.readFileSync(entryPath, "utf8");
    runNoModules(code, { timeoutMs: 250 });
    console.log("[guardian] OK: simulation ran (no modules allowed).");
  } catch (e) {
    console.error("[guardian]", e.code || "ERROR", e.message);
    if (e.findings) {
      for (const f of e.findings.slice(0, 50)) {
        console.error(`- [${f.kind}] ${f.msg} @ ${f.file}:${f.line}:${f.col}`);
      }
    }
    process.exit(2);
  }
}
node --disallow-code-generation-from-strings --disable-proto run-sim-no-modules.js ./sim simulation.js
docker run --rm -it \
  --network none \
  --read-only \
  --cap-drop ALL \
  --security-opt no-new-privileges:true \
  --pids-limit 256 \
  --memory 512m \
  --cpus 1 \
  --tmpfs /tmp:rw,noexec,nosuid,nodev,size=128m \
  -v "$PWD:/work:ro" \
  -w /work \
  node:20-alpine \
  node --disallow-code-generation-from-strings --disable-proto run-sim-no-modules.js ./sim simulation.js
{
  "deny": {
    "capabilities": [
      "network",
      "persistence",
      "privilege-escalation",
      "auto-update",
      "self-replication",
      "hidden-execution"
    ],
    "patterns": [
      "child_process",
      "powershell",
      "cmd.exe",
      "bash -c",
      "curl ",
      "wget ",
      "Invoke-WebRequest",
      "schtasks",
      "cron",
      "launchctl",
      "systemctl",
      "reg add",
      "HKLM\\\\Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run",
      "npm publish",
      "twine upload",
      "pypi.org",
      "postinstall",
      "preinstall"
    ],
    "file_globs": [
      "**/*.js",
      "**/*.ts",
      "**/*.py",
      "**/*.sh",
      "**/*.ps1",
      "package.json",
      "pyproject.toml",
      "setup.py"
    ]
  }
}
import json
import os
import fnmatch
import sys

def load_policy(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)

def iter_files(root: str, globs: list[str]):
    for base, _, files in os.walk(root):
        for name in files:
            rel = os.path.relpath(os.path.join(base, name), root)
            if any(fnmatch.fnmatch(rel, g) for g in globs):
                yield rel

def read_text(root: str, rel: str) -> str:
    p = os.path.join(root, rel)
    try:
        with open(p, "r", encoding="utf-8", errors="ignore") as f:
            return f.read()
    except Exception:
        return ""

def main():
    repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    policy = load_policy(os.path.join(repo_root, "policy.json"))
    deny_patterns = policy["deny"]["patterns"]
    globs = policy["deny"]["file_globs"]

    violations = []

    for rel in iter_files(repo_root, globs):
        txt = read_text(repo_root, rel)
        if not txt:
            continue
        for pat in deny_patterns:
            if pat in txt:
                violations.append((rel, pat))

    if violations:
        print("❌ Anti-influence policy violations found:\n")
        for rel, pat in violations:
            print(f" - {rel}: matched '{pat}'")
        print("\nFix/remove these patterns or justify via an explicit exception process.")
        sys.exit(2)

    print("✅ Anti-influence scan passed (no blocked influence vectors detected).")
    sys.exit(0)

if __name__ == "__main__":
    main()
name: Anti-Influence Gate

on:
  pull_request:
  push:
    branches: [ "main" ]

permissions:
  contents: read

jobs:
  anti_influence:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Use Python
        uses: actions/setup-python@v5
        with:
          python-version: "3.11"

      - name: Run anti-influence scan
        run: python tools/anti_influence_scan.py
docker run --rm -it \
  --network=none \
  --read-only \
  --cap-drop=ALL \
  --security-opt=no-new-privileges \
  -v "$PWD":/app:ro \
  -w /app \
  python:3.11-slim \
  python your_script.py
policy:
  name: "Behavioral Influence Mitigation Policy"
  version: "1.0"

deny:
  # Things that enable influence via psychology + targeting
  capabilities:
    - "targeted_advertising"
    - "user_profiling"
    - "behavioral_personalization"
    - "remote_content_injection"
    - "ab_testing"
    - "dark_pattern_ui"
    - "infinite_scroll"
    - "engagement_loops"
    - "push_notifications"
    - "badge_counters"
    - "email_nudges"
    - "telemetry_tracking"

  # Libraries / identifiers often used for tracking, experimentation, remote config
  tokens:
    - "segment"
    - "amplitude"
    - "mixpanel"
    - "appsflyer"
    - "firebase-analytics"
    - "google-analytics"
    - "optimizely"
    - "launchdarkly"
    - "split.io"
    - "statsig"
    - "posthog"
    - "braze"
    - "onesignal"
    - "clevertap"

  # UI patterns / copy that frequently signals manipulative flows (heuristic)
  phrases:
    - "only today"
    - "don’t miss out"
    - "last chance"
    - "people like you"
    - "recommended for you"
    - "just one more"
    - "keep watching"
    - "streak"
    - "unlock"
    - "limited time"

allow:
  # Allow-list what the app is allowed to contact (prefer empty)
  egress_hosts:
    - "api.yourcompany.example"
    - "auth.yourcompany.example"

enforce:
  # Must be true in production builds
  require:
    - "no_network_except_allowlist"
    - "notifications_disabled_by_default"
    - "no_remote_feature_flags"
    - "no_webview_untrusted_content"
    - "no_third_party_analytics"
    - "no_dark_pattern_components"
import os, sys, re, fnmatch, yaml

DEFAULT_GLOBS = [
    "**/*.js","**/*.ts","**/*.jsx","**/*.tsx",
    "**/*.py","**/*.java","**/*.kt","**/*.swift",
    "**/*.html","**/*.css",
    "**/package.json","**/pyproject.toml","**/Podfile","**/build.gradle","**/*.xml"
]

def load_policy(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)

def walk_files(root: str, globs):
    for base, _, files in os.walk(root):
        for name in files:
            rel = os.path.relpath(os.path.join(base, name), root)
            if any(fnmatch.fnmatch(rel, g) for g in globs):
                yield rel

def read_text(path: str) -> str:
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            return f.read()
    except Exception:
        return ""

def main():
    repo = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    policy_path = os.path.join(repo, "influence_policy.yml")
    policy = load_policy(policy_path)

    deny_tokens = [t.lower() for t in policy["deny"].get("tokens", [])]
    deny_phrases = [p.lower() for p in policy["deny"].get("phrases", [])]

    globs = DEFAULT_GLOBS
    violations = []

    for rel in walk_files(repo, globs):
        full = os.path.join(repo, rel)
        txt = read_text(full)
        low = txt.lower()

        for token in deny_tokens:
            if token in low:
                violations.append((rel, f"token:{token}"))

        for phrase in deny_phrases:
            if phrase in low:
                violations.append((rel, f"phrase:{phrase}"))

        # Heuristic: infinite-scroll primitives in web/React
        if re.search(r"(infinite\s*scroll|intersectionobserver|load\s*more\s*on\s*scroll)", low):
            violations.append((rel, "pattern:infinite_scroll_heuristic"))

        # Heuristic: notification usage
        if re.search(r"(Notification\.requestPermission|PushManager|UNUserNotificationCenter|FirebaseMessaging)", txt):
            violations.append((rel, "pattern:notifications"))

        # Heuristic: remote-config / feature flags
        if re.search(r"(launchdarkly|optimizely|remote\s*config|feature\s*flag|statsig|split\.io)", low):
            violations.append((rel, "pattern:remote_config_or_flags"))

    if violations:
        print("❌ Influence Gate: violations found\n")
        for rel, why in violations[:200]:
            print(f" - {rel} -> {why}")
        print("\nFix by removing the influence primitive or routing through approved allow-listed mechanisms.")
        sys.exit(2)

    print("✅ Influence Gate: passed (no influence primitives detected).")
    sys.exit(0)

if __name__ == "__main__":
    main()
name: Influence Gate
on: [pull_request, push]
jobs:
  gate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with: { python-version: "3.11" }
      - run: pip install pyyaml
      - run: python tools/influence_gate.py
sudo nft add table inet filter
sudo nft 'add chain inet filter output { type filter hook output priority 0; policy drop; }'

# allow loopback
sudo nft add rule inet filter output oifname "lo" accept

# allow established
sudo nft add rule inet filter output ct state established,related accept

# allow DNS to your resolver (replace 1.1.1.1 with your DNS)
sudo nft add rule inet filter output udp dport 53 ip daddr 1.1.1.1 accept
sudo nft add rule inet filter output tcp dport 53 ip daddr 1.1.1.1 accept

# allow only your API endpoints (replace with real IPs)
sudo nft add rule inet filter output tcp dport { 443,80 } ip daddr { 203.0.113.10, 203.0.113.11 } accept
// kill-notifications.js
(function () {
  try {
    if ("Notification" in window) {
      Object.defineProperty(window, "Notification", {
        value: function Notification() { throw new Error("Notifications disabled by policy"); },
        writable: false
      });
    }
    if ("navigator" in window && navigator.serviceWorker) {
      // optional: block SW registration if you don't want push mechanisms
      const orig = navigator.serviceWorker.register.bind(navigator.serviceWorker);
      navigator.serviceWorker.register = () => Promise.reject(new Error("ServiceWorker disabled by policy"));
      navigator.serviceWorker.getRegistration = () => Promise.resolve(undefined);
      navigator.serviceWorker.getRegistrations = () => Promise.resolve([]);
    }
  } catch {}
})();
Content-Security-Policy:
  default-src 'self';
  script-src 'self';
  connect-src 'self' https://api.yourcompany.example;
  img-src 'self' data:;
  style-src 'self' 'unsafe-inline';
  frame-src 'none';
  object-src 'none';
  base-uri 'self';
// tools/ui_influence_denylist.js
const fs = require("fs");
const path = require("path");

const deny = [
  "Streak",
  "NagModal",
  "UrgencyBanner",
  "InfiniteFeed",
  "VariableReward",
];

function walk(dir, out=[]) {
  for (const item of fs.readdirSync(dir)) {
    const p = path.join(dir, item);
    const st = fs.statSync(p);
    if (st.isDirectory()) walk(p, out);
    else if (p.endsWith(".tsx") || p.endsWith(".jsx")) out.push(p);
  }
  return out;
}

const root = path.join(__dirname, "..", "src");
const files = walk(root);
let bad = [];

for (const f of files) {
  const txt = fs.readFileSync(f, "utf8");
  for (const name of deny) {
    if (txt.includes(name)) bad.push([f, name]);
  }
}

if (bad.length) {
  console.error("❌ UI Influence deny-list hit:");
  for (const [f, n] of bad) console.error(` - ${f} uses ${n}`);
  process.exit(2);
}
console.log("✅ UI Influence deny-list clean.");
#!/usr/bin/env bash
# Reject non-fast-forward updates (prevents rewriting history / outwriting commits)

set -euo pipefail

while read -r old new ref; do
  # Allow creating new branches/tags
  if [[ "$old" == "0000000000000000000000000000000000000000" ]]; then
    continue
  fi

  # If update is not a fast-forward, reject
  if ! git merge-base --is-ancestor "$old" "$new"; then
    echo "REJECTED: Non-fast-forward update to $ref (history rewrite blocked)."
    exit 1
  fi
done

exit 0
chmod +x hooks/pre-receive
README.md
policy.json
influence_policy.yml
tools/anti_influence_scan.py
tools/influence_gate.py
#!/usr/bin/env bash
set -euo pipefail

# Set BYPASS_PROTECT=1 to allow a one-time intentional change.
if [[ "${BYPASS_PROTECT:-0}" == "1" ]]; then
  exit 0
fi

PROTECT_LIST="protected_files.txt"

if [[ ! -f "$PROTECT_LIST" ]]; then
  exit 0
fi

# Get staged files that are added/copied/modified/renamed
staged="$(git diff --cached --name-only --diff-filter=ACMR || true)"

blocked=0
while IFS= read -r protected; do
  [[ -z "$protected" ]] && continue
  if echo "$staged" | grep -Fxq "$protected"; then
    echo "REJECTED: '$protected' is protected and cannot be overwritten/modified."
    blocked=1
  fi
done < "$PROTECT_LIST"

if [[ "$blocked" -eq 1 ]]; then
  echo
  echo "If this change is intentional, run:"
  echo "  BYPASS_PROTECT=1 git commit -m \"...\""
  exit 1
fi

exit 0
git config core.hooksPath .githooks
chmod +x .githooks/pre-commit
sudo chattr +i tools/influence_gate.py
sudo chattr +i tools/anti_influence_scan.py
sudo chattr -i tools/influence_gate.py
chmod a-w tools/influence_gate.py
chmod a-w tools/anti_influence_scan.py
icacls .\tools\influence_gate.py /inheritance:r
icacls .\tools\influence_gate.py /grant:r "$env:USERNAME:(R)"
icacls .\tools\influence_gate.py /deny "$env:USERNAME:(W)"
git tag -a "locked-$(date +%Y%m%d-%H%M)" -m "Locked snapshot"
git push --tags
import re
import unicodedata
from dataclasses import dataclass
from typing import Dict, List, Tuple, Pattern, Optional

@dataclass(frozen=True)
class FilterResult:
    cleaned_text: str
    matched_terms: List[str]
    redacted: bool

def _normalize(text: str) -> str:
    """
    Normalize text to reduce bypass tricks:
    - Unicode NFKC
    - lowercased
    - collapse whitespace
    """
    t = unicodedata.normalize("NFKC", text)
    t = t.lower()
    t = re.sub(r"\s+", " ", t).strip()
    return t

def _deobfuscate_for_matching(text: str) -> str:
    """
    Create a 'matching view' that reduces common obfuscations:
    - remove punctuation
    - remove zero-width chars
    - map leetspeak-ish chars to letters (lightweight)
    """
    # strip zero-width characters
    t = re.sub(r"[\u200B-\u200F\uFEFF]", "", text)

    # basic leetspeak mapping (extend as needed)
    leet_map = str.maketrans({
        "0": "o",
        "1": "i",
        "3": "e",
        "4": "a",
        "5": "s",
        "7": "t",
        "@": "a",
        "$": "s",
    })
    t = t.translate(leet_map)

    # remove punctuation/symbols for matching
    t = re.sub(r"[^a-z0-9\s]+", "", t)
    t = re.sub(r"\s+", " ", t).strip()
    return t

def build_patterns(deny_terms: List[str]) -> Tuple[Pattern, Dict[str, str]]:
    """
    Build one compiled regex that matches any deny term as a whole word/phrase-ish.
    Returns (regex, canonical_map).
    """
    # canonicalize deny terms
    canon_map = {}
    escaped_terms = []
    for term in deny_terms:
        canon = _deobfuscate_for_matching(_normalize(term))
        canon_map[canon] = term
        # match term with flexible whitespace between words
        parts = [re.escape(p) for p in canon.split()]
        if len(parts) == 1:
            escaped_terms.append(rf"\b{parts[0]}\b")
        else:
            escaped_terms.append(r"\b" + r"\s+".join(parts) + r"\b")

    # Prefer longer terms first to reduce partial matches
    escaped_terms.sort(key=len, reverse=True)
    big = "|".join(escaped_terms) if escaped_terms else r"(?!x)x"
    return re.compile(big, re.IGNORECASE), canon_map

def filter_text(
    text: str,
    deny_terms: List[str],
    replacement: str = "[REDACTED]",
    redact_instead_of_remove: bool = True
) -> FilterResult:
    """
    - Detect deny terms using a deobfuscated matching view
    - Either redact (default) or remove from original text
    """
    if not deny_terms:
        return FilterResult(text, [], False)

    pattern, canon_map = build_patterns(deny_terms)

    # matching view
    norm = _normalize(text)
    match_view = _deobfuscate_for_matching(norm)

    matches = []
    for m in pattern.finditer(match_view):
        canon_hit = _deobfuscate_for_matching(_normalize(m.group(0)))
        matches.append(canon_map.get(canon_hit, m.group(0)))

    if not matches:
        return FilterResult(text, [], False)

    # Apply redaction/removal on the normalized original (simple + predictable)
    # For strict systems, you might store original and only display cleaned.
    cleaned = text
    for term in sorted(set(matches), key=len, reverse=True):
        # Replace term in a case-insensitive, whitespace-flexible way
        term_norm = re.escape(_normalize(term))
        term_norm = term_norm.replace(r"\ ", r"\s+")
        rx = re.compile(term_norm, re.IGNORECASE)

        cleaned = rx.sub(replacement if redact_instead_of_remove else "", cleaned)

    # Cleanup if removing
    if not redact_instead_of_remove:
        cleaned = re.sub(r"\s+", " ", cleaned).strip()

    return FilterResult(cleaned, sorted(set(matches)), True)

# -------------------------
# Example denylist (extend)
# -------------------------

DENY_TERMS = [
    # extremist / Nazi-related terms (keep to text; symbols can be added as literals)
    "nazi", "ss", "hitler", "swastika", "heil",

    # "magic" theme keywords you listed
    "magic", "aetherium", "aether", "incantation", "rhyme", "spell",

    # specific terms you listed
    "mr. magician", "influence magic",
    "shya", "asha", "nyalotha",

    # Names you want blocked *in your app’s text*
    "stevie wonder",
]

if __name__ == "__main__":
    sample = "A NAZI incantation rhyme about Mr. Magician and Stevie Wonder."
    result = filter_text(sample, DENY_TERMS)
    print("CLEANED:", result.cleaned_text)
    print("MATCHES:", result.matched_terms)
policy:
  name: "Capability Revocation"
  version: "1.0"

revoke:
  capabilities:
    - network_access
    - telemetry
    - analytics
    - data_exfiltration
    - background_tasks
    - persistence
    - plugin_or_extension_loading
    - system_shell
    - code_execution_untrusted
    - user_profiling
    - remote_config
    - webview_remote_content

allow:
  # Keep this very small (or empty). Example: only your own API.
  egress_hosts:
    - "api.yourcompany.example"

enforce:
  require:
    - no_network_except_allowlist
    - no_telemetry
    - no_analytics
    - no_shell
    - no_dynamic_plugins
import os, re, sys, fnmatch
import yaml

GLOBS = [
  "**/*.js","**/*.ts","**/*.jsx","**/*.tsx",
  "**/*.py","**/*.go","**/*.rs","**/*.java","**/*.kt",
  "**/*.sh","**/*.ps1",
  "**/package.json","**/pyproject.toml","**/requirements.txt"
]

# “Power/knowledge/information gathering” in software terms:
DENY_PATTERNS = [
  # Network & scraping
  r"\b(fetch|axios|getaddrinfo|requests\.get|httpx\.get|urllib|curl\b|wget\b)\b",
  r"\b(websocket|socket\.io|net\.connect|tls\.connect)\b",

  # Telemetry/analytics SDKs
  r"\b(segment|amplitude|mixpanel|posthog|google-analytics|firebase-analytics)\b",

  # Remote config / experimentation
  r"\b(launchdarkly|optimizely|split\.io|statsig|remote\s*config|feature\s*flag)\b",

  # Shell / system execution
  r"\b(child_process|exec\(|spawn\(|subprocess\.run|os\.system|powershell|cmd\.exe)\b",

  # Persistence / scheduling
  r"\b(cron|schtasks|systemctl|launchctl|LaunchAgents|LaunchDaemons)\b",

  # Plugin/extension loading
  r"\b(require\(\s*['\"][^'\"]+['\"]\s*\)\s*;?\s*//\s*dynamic\b|\bdlopen\b|\bimportlib\b|\beval\(|new Function\()\b",
]

def load_policy(pa_
name: Capability Revocation Gate
on: [pull_request, push]
jobs:
  gate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with: { python-version: "3.11" }
      - run: pip install pyyaml
      - run: python tools/revoke_scan.py
docker run --rm -it \
  --network=none \
  --read-only \
  --cap-drop=ALL \
  --security-opt=no-new-privileges \
  -v "$PWD":/app:ro \
  -w /app \
  python:3.11-slim \
  python your_script.py
ALLOWED_CAPS = {"basic_compute"}  # keep tiny

def require_caps(requested: set[str]) -> None:
    extra = requested - ALLOWED_CAPS
    if extra:
        raise PermissionError(f"Capabilities revoked by policy: {sorted(extra)}")

