package adscan

import js "wscan/internal/engine/js"

type SMBAccessObservation struct {
	Mode   string        `json:"mode"`
	State  string        `json:"state"`
	Shares []js.SMBEntry `json:"shares,omitempty"`
	Error  string        `json:"error,omitempty"`
}
