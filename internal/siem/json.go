package siem

import "encoding/json"

// jsonEvent is the stable, documented JSON wire schema (v1). Field names and
// semantics are a contract — see docs/schemas/siem/event.schema.json and
// docs/schemas/siem/README.md. Changing a field name or meaning is a
// breaking change for downstream SIEM pipelines and requires a schema bump.
//
// Numeric fields are always present. String fields carry the length-capped
// value; ip is omitted entirely for system-level events with no target.
type jsonEvent struct {
	SchemaVersion int    `json:"schema_version"`
	Timestamp     string `json:"timestamp"` // RFC 3339, UTC; "" when Event.Time is zero
	Vendor        string `json:"vendor"`
	Product       string `json:"product"`
	Version       string `json:"version"`
	Action        string `json:"action"`
	IP            string `json:"ip,omitempty"` // omitted when there is no target IP
	Rule          string `json:"rule"`
	Score         int    `json:"score"`
	Strike        int    `json:"strike"`
	TTLSeconds    int64  `json:"ttl_seconds"`
	Actor         string `json:"actor"`
	Node          string `json:"node"`
}

// jsonSchemaVersion is the current version of the JSON wire schema. Bump it
// whenever a field is added, removed, renamed, or changes meaning.
const jsonSchemaVersion = 1

// FormatJSON renders e as a single-line JSON object following the stable v1
// schema. Timestamps are RFC 3339 in UTC; every string field is length-capped
// (maxFieldLen bytes) BEFORE encoding, so output size is bounded regardless of
// input. encoding/json guarantees valid JSON and escapes control characters
// (a raw newline in a field becomes "\n"), so the output is always a single
// line that json.Valid accepts.
func FormatJSON(e Event) ([]byte, error) {
	je := jsonEvent{
		SchemaVersion: jsonSchemaVersion,
		Timestamp:     rfc3339UTC(e.Time),
		Vendor:        capField(e.vendor()),
		Product:       capField(e.product()),
		Version:       capField(e.version()),
		Action:        capField(e.Action),
		IP:            e.ipString(), // already canonical/bounded; no cap needed
		Rule:          capField(e.Rule),
		Score:         e.Score,
		Strike:        e.Strike,
		TTLSeconds:    int64(e.TTL.Seconds()),
		Actor:         capField(e.Actor),
		Node:          capField(e.Node),
	}
	return json.Marshal(je)
}
