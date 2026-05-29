package bulkhead

import "sort"

// Subsystem names for the parts of the control plane that own a bulkhead today.
// New subsystems register their own pool as they land.
const (
	SubsystemAPI         = "api"
	SubsystemProjections = "projections"
	SubsystemOutbox      = "outbox"
	SubsystemSigning     = "signing"
)

// Set is a collection of named, isolated pools — one per subsystem. Submitting to
// one subsystem can never consume another's capacity (AN-7).
type Set struct {
	pools map[string]*Pool
}

// NewSet starts a pool for each config, keyed by config Name.
func NewSet(cfgs ...Config) *Set {
	s := &Set{pools: make(map[string]*Pool, len(cfgs))}
	for _, c := range cfgs {
		s.pools[c.Name] = New(c)
	}
	return s
}

// Default returns a Set with a conservatively sized, isolated pool for each
// subsystem that exists so far. The sizes are starting points, tunable per
// deployment.
func Default() *Set {
	return NewSet(
		Config{Name: SubsystemAPI, Workers: 8, Queue: 256},
		Config{Name: SubsystemProjections, Workers: 2, Queue: 128},
		Config{Name: SubsystemOutbox, Workers: 4, Queue: 256},
		Config{Name: SubsystemSigning, Workers: 4, Queue: 64},
	)
}

// Pool returns the named pool, or nil if no such subsystem is registered.
func (s *Set) Pool(name string) *Pool { return s.pools[name] }

// Submit runs task on the named subsystem's pool. It returns *Rejected if the
// subsystem is unknown or its pool is saturated.
func (s *Set) Submit(name string, task func()) error {
	p, ok := s.pools[name]
	if !ok {
		return &Rejected{Pool: name, Reason: ReasonUnknown}
	}
	return p.Submit(task)
}

// Close shuts down every pool, draining queued work.
func (s *Set) Close() {
	for _, p := range s.pools {
		p.Close()
	}
}

// Stats returns a snapshot of every pool's stats, ordered by subsystem name.
func (s *Set) Stats() []Stats {
	out := make([]Stats, 0, len(s.pools))
	for _, p := range s.pools {
		out = append(out, p.Stats())
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}
