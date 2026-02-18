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
