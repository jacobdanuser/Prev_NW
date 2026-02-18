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
