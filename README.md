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
