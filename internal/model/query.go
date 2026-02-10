package model

import "time"

// EventQuery defines filters for querying connection or request events.
type EventQuery struct {
	Service     string    `json:"service"`
	Namespace   string    `json:"namespace"`
	StartTime   time.Time `json:"startTime"`
	EndTime     time.Time `json:"endTime"`
	Limit       int       `json:"limit"`
	Source      string    `json:"source"`
	Destination string    `json:"destination"`
}

// DependencyQuery defines parameters for querying dependencies.
type DependencyQuery struct {
	StartTime time.Time `json:"startTime"`
	EndTime   time.Time `json:"endTime"`
	Service   string    `json:"service"`
}

// MetricQuery defines parameters for querying metrics.
type MetricQuery struct {
	Service   string    `json:"service"`
	Namespace string    `json:"namespace"`
	StartTime time.Time `json:"startTime"`
	EndTime   time.Time `json:"endTime"`
	Step      string    `json:"step"`
}
