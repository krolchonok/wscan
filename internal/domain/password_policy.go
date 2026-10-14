package domain

// Pointer fields distinguish an unreadable setting from a returned zero/false.
// Relative AD intervals are normalized to seconds; zero max age means unlimited.
type PasswordPolicy struct {
	DN                       string   `json:"dn"`
	Source                   string   `json:"source"`
	MinLength                *int64   `json:"min_length,omitempty"`
	HistoryLength            *int64   `json:"history_length,omitempty"`
	MinAgeSeconds            *int64   `json:"min_age_seconds,omitempty"`
	MaxAgeSeconds            *int64   `json:"max_age_seconds,omitempty"`
	Complexity               *bool    `json:"complexity,omitempty"`
	ReversibleEncryption     *bool    `json:"reversible_encryption,omitempty"`
	LockoutThreshold         *int64   `json:"lockout_threshold,omitempty"`
	LockoutDurationSeconds   *int64   `json:"lockout_duration_seconds,omitempty"`
	ObservationWindowSeconds *int64   `json:"observation_window_seconds,omitempty"`
	Precedence               *int64   `json:"precedence,omitempty"`
	AppliesTo                []string `json:"applies_to,omitempty"`
	MissingFields            []string `json:"missing_fields,omitempty"`
	Errors                   []string `json:"errors,omitempty"`
}
