package domain

type CheckCoverage struct {
	Host     string `json:"host"`
	Port     int    `json:"port,omitempty"`
	CheckID  string `json:"check_id"`
	State    string `json:"state"`
	Evidence string `json:"evidence,omitempty"`
}
