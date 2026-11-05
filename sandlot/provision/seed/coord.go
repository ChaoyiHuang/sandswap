// Copyright 2026 Chaoyi Huang. All rights reserved.
//
// SPDX-License-Identifier: BUSL-1.1
//
// Use of this software is governed by the Business Source License
// included in the LICENSE file at the root of this repository.
//
// As of the Change Date specified in that file, in accordance with
// the Business Source License, use of this software will be governed
// by the Apache License, Version 2.0.

// Package seed keeps a provision instance's live seed generations in step with
// the channels that inject them, and records what it adopted.
//
// The volume-name seed is not like other secrets: it is the INDEX KEY of every
// volume's on-disk directory name, so a silent change orphans the whole tree —
// delete answers false success (ENOENT), create builds a second tree for the
// tenant. The injected channels are therefore split into two roles: an
// injector (a Vault agent, an External Secrets Operator, a systemd credential,
// any script that can write a file atomically) SUPPLIES material, and only the
// stage → run → promote window MOVES the pointer. This coordinator is the
// watchdog that keeps the two apart:
//
//   - it re-reads the configured sources at RUNTIME (fsnotify, plus a poll for
//     the filesystems where inotify never fires) instead of only at startup;
//   - it requires two agreeing reads before adopting anything, so a writer
//     caught mid-flight is never adopted;
//   - a change to the CURRENT generation is refused as tampering, never
//     adopted: the pointer may only move through stage/promote;
//   - it runs the promote completeness gate on disk BEFORE the namer drops the
//     old generation, because promotion is irreversible;
//   - it writes an adoption record, so tooling asks the RUNNING process which
//     generation it is on instead of grepping the journal.
package seed

import (
	"bytes"
	"fmt"
	"log"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	commonconfig "common/config"

	sandlotconfig "sandlot/config"
	"sandlot/provision/volname"
	"sandlot/provision/volume"
)

const (
	// guardWorkers bounds the startup guard's stamp reads; guardDeadline
	// bounds how long new directories are scheduled. The scan is a safety
	// check, not a service: whatever it cannot read in time is reported and
	// the instance keeps starting (an inconclusive scan is not a mismatch).
	guardWorkers  = 16
	guardDeadline = 30 * time.Second
)

// Options configures a Coordinator.
type Options struct {
	// Config returns the LIVE config snapshot. Every generation is resolved
	// from ONE call, so a half-applied edit can never be observed.
	Config func() sandlotconfig.SandlotConfig
	// Namer is the namer the whole process shares (provisioner, template
	// manager, this coordinator): the single place the generations move.
	Namer *volname.Map
	// VolRoot is the volumes root the guards scan.
	VolRoot string
	// StatePath is where the adoption record is written.
	StatePath string
	// Logger receives the security-relevant lines: refusals, tamper alarms and
	// the guard's verdicts. Required.
	Logger *log.Logger
	// AllowGenerationMismatch starts anyway when the volumes root carries a
	// generation no configured seed derives. Deliberate re-key / disaster
	// recovery only: it never weakens the promote gate.
	AllowGenerationMismatch bool
}

// Coordinator owns the seed generations' runtime lifecycle for one prov
// instance.
type Coordinator struct {
	opts Options

	// mu serializes every resolution and application. Two watchers (current
	// source + staged source) and the config watcher all funnel here, and the
	// namer's own state machine is only safe if the reads and the writes are
	// one critical section.
	mu       sync.Mutex
	watchers map[string]*commonconfig.ReloadWatcher
	stopped  bool

	lastErrMsg string

	stopOnce sync.Once
	stop     chan struct{}
	done     chan struct{}
}

// New builds a Coordinator. It performs no I/O: Bootstrap resolves the
// generations, StartupGuard checks them against disk, Start begins watching.
func New(opts Options) (*Coordinator, error) {
	if opts.Config == nil || opts.Namer == nil || opts.Logger == nil {
		return nil, fmt.Errorf("seed coordinator requires Config, Namer and Logger")
	}
	return &Coordinator{
		opts:     opts,
		watchers: map[string]*commonconfig.ReloadWatcher{},
		stop:     make(chan struct{}),
		done:     make(chan struct{}),
	}, nil
}

// Bootstrap resolves the configured generations and stages the next one if it
// is readable. A bad CURRENT generation is returned as an error (the caller
// refuses to start: without it no name can be derived); a bad NEXT generation
// is logged and skipped — an injector may simply not have materialized the
// staged file yet, and crash-looping there would be worse than running
// unstaged, which only means the rotation window has not opened.
func (c *Coordinator) Bootstrap() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	p := c.opts.Config().Provision
	cur, _, err := p.CurrentSeed()
	if err != nil {
		return err
	}
	if string(cur) != string(c.opts.Namer.CurrentSeed()) {
		return fmt.Errorf("the namer was built from a different seed than the config names — build it from ProvisionConfig.CurrentSeed()")
	}
	next, _, nerr := p.NextSeed()
	switch {
	case nerr != nil:
		c.opts.Logger.Printf("WARNING: the staged seed is not usable yet (%v) — starting UNSTAGED; creation keeps working and the rotation window stays closed until the source is readable", nerr)
	case next != nil:
		if bytes.Equal(next, cur) {
			// The contract above — a bad NEXT generation is logged and skipped,
			// never fatal — covers this shape too, and the shape is reachable:
			// `rotate-volume-seed.sh --stage --seed-file <the current file>`
			// writes a staged generation equal to the current one, then leaves
			// the key in the config when its adoption wait times out. Refusing
			// to start over it would crash-loop this prov instance (a
			// storage-plane outage for its fleet slice) while the tree is
			// perfectly serviceable — and the runtime path (ApplySeeds'
			// classify) refuses the same value non-fatally.
			c.opts.Logger.Printf("WARNING: the staged seed equals the current one (%s) — a rotation would rename nothing; starting UNSTAGED (creation keeps working, the rotation window stays closed)", volname.Fingerprint(next))
			break
		}
		if err := c.opts.Namer.Stage(next); err != nil {
			// Still a NEXT-generation problem, same contract, same treatment:
			// NextSeed already validated the material, so this is belt-and-
			// braces against a future resolver that slips a bad value through.
			c.opts.Logger.Printf("WARNING: the staged seed is not usable (%v) — starting UNSTAGED; creation keeps working and the rotation window stays closed until the source is fixed", err)
			break
		}
		c.opts.Logger.Printf("provision: seed rotation STAGED (creation frozen until promoted)")
	}
	c.publishStateLocked("startup", nil)
	return nil
}

// Generations reports what this instance is deriving volume names from RIGHT
// NOW — fingerprints only, never seed material. It is what the heartbeat
// publishes so the gateway's fleet view can prove that every prov instance
// converged before a rotation window closes.
func (c *Coordinator) Generations() (staged bool, currentFP, stagedFP string) {
	return c.opts.Namer.GenerationSnapshot()
}

// StartupGuard checks the volumes root against the generations this process
// loaded. The stamps are the disk-side authority: a root whose stamped volumes
// all belong to a generation NO configured seed derives means the seed source
// moved under the deployment (an injector replaced, a rolled-back source, a
// botched restore). Serving from there silently splits tenants, so the
// instance refuses to start — unless the operator explicitly allows it for a
// deliberate re-key.
//
// The check never creates an outage out of uncertainty: a missing root, an
// unreadable root, a scan that ran out of time, unreadable stamps, unverifiable
// stamps (tenant-forged, or a per-volume seed mix-up) and a legacy tree without
// stamps are all counted and reported, not fatal — an unprepared host must not
// become a crash-loop, and a single tampered stamp must not take the storage
// plane (and a rotation) down. Unverifiable volumes are quarantined by the
// operation paths (identity checks refuse them) and reported in the adoption
// record; EnsureVolume owns the actionable missing-root error. Only a FOREIGN
// generation — a tree-wide mix-up — and a deliberate abort are fatal. The
// promote gate — the irreversible step, always taken with the operator present
// — is the strict one, and it refuses an absent root, unreadable and
// unverifiable stamps outright.
//
// Error and warning strings here carry counts and generation FINGERPRINTS only:
// a volume directory name is seed-derived and must never reach a log line or
// the adoption record (the record is what rotation tooling greps instead of the
// journal).
func (c *Coordinator) StartupGuard() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	staged, curFP, stagedFP := c.opts.Namer.GenerationSnapshot()
	known := []string{curFP}
	if staged {
		known = append(known, stagedFP)
	}
	res, err := volume.ScanGenerationStamps(c.opts.VolRoot, volume.ScanOptions{
		Known: known, Seeds: namerSeeds(c.opts.Namer), Workers: guardWorkers, Deadline: guardDeadline,
	})
	if err != nil {
		c.opts.Logger.Printf("WARNING: cannot verify the volumes root %s against the configured generations (%v) — continuing; the promote gate re-checks before any irreversible step", c.opts.VolRoot, err)
		return nil
	}
	scan := &ScanState{
		Sampled: res.Sampled, Foreign: res.Foreign,
		Unstamped: res.Unstamped, PreGeneration: res.PreGeneration,
		Unverified: res.Unverified, Complete: res.Complete,
	}
	defer c.publishStateLocked("startup-guard", scan)

	if res.RootMissing {
		// Deliberately lenient, unlike the promote gate on the same reading:
		// an unprepared host must not crash-loop, and EnsureVolume owns the
		// actionable "volumes root missing" error.
		c.opts.Logger.Printf("WARNING: the volumes root %s does not exist yet — the generation check has nothing to read; creation will fail until the host is prepared, and the promote gate refuses until the root is readable", c.opts.VolRoot)
	}
	if !res.Complete {
		c.opts.Logger.Printf("WARNING: the volumes-root scan ran out of time after %d directories — the generation check is a partial reading", res.Sampled)
	}
	if res.ReadErrors > 0 {
		c.opts.Logger.Printf("WARNING: %d of %d volume(s) under %s have an unreadable generation stamp — the generation check could not classify them; the promote gate refuses until they are readable", res.ReadErrors, res.Sampled, c.opts.VolRoot)
	}
	if leg := res.LegacyCount(); leg > 0 {
		c.opts.Logger.Printf("WARNING: %d volume(s) under %s carry no usable generation stamp (legacy tree): they stay resolvable through their records, but a promotion will refuse until the one-time migration runs", leg, c.opts.VolRoot)
	}
	// A stamp that cannot be authenticated (unsigned, or signed by a seed no
	// configured generation derives) is either a tenant forgery or the seed
	// mix-up this guard exists for. It is NOT fatal at startup: the volume is
	// already quarantined by every operation path (a create/delete/swap on it
	// refuses, and the exec plane's mount identity check refuses it too), so
	// one tampered stamp must not crash-loop the storage plane (a single
	// compromised guest kernel could otherwise take the provision role down
	// and hijack a rotation). The reading is reported and recorded, and a
	// promotion still refuses it. A FOREIGN generation stays fatal: that is a
	// tree-wide seed mix-up, not one volume.
	if res.Unverified > 0 {
		msg := fmt.Sprintf("%d of %d volume(s) under %s carry a stamp that could not be authenticated against the configured seed generations (configured: %s) — those volumes are QUARANTINED (create/delete/mount refuse them) until an operator inspects them, and a promotion refuses this tree. Point the seed source back at the generation this tree was created under, or remove the volumes that are tenant forgeries (they carry no usable identity either way)",
			res.Unverified, res.Sampled, c.opts.VolRoot, strings.Join(known, ","))
		// A single tampered stamp must not crash-loop the storage plane
		// (P-01), but when EVERY sampled volume is unverifiable the cause is
		// a tree-wide seed mix-up, not one tenant forgery: serving would
		// silently split tenants. Keep that fatal, with the deliberate
		// re-key escape hatch.
		if res.Unverified == res.Sampled && res.Sampled > 0 {
			msg += " — every sampled volume is unverifiable under the configured generations; serving would silently split tenants"
			if c.opts.AllowGenerationMismatch {
				c.recordErr(msg)
				c.opts.Logger.Printf("WARNING: %s (allowed by -allow-seed-generation-mismatch)", msg)
				return nil
			}
			c.recordErr(msg)
			return fmt.Errorf("%s", msg)
		}
		c.recordErr(msg)
		c.opts.Logger.Printf("WARNING: %s", msg)
	}
	if res.Foreign > 0 {
		// Report the FOREIGN fingerprints found (one-way hashes, operator
		// substance), never volume directory names — those are seed-derived
		// and this message reaches the journal and the adoption record.
		knownSet := make(map[string]bool, len(known))
		for _, fp := range known {
			knownSet[fp] = true
		}
		var foreignFPs []string
		for fp := range res.ByGeneration {
			if !knownSet[fp] {
				foreignFPs = append(foreignFPs, fp)
			}
		}
		sort.Strings(foreignFPs)
		const maxForeignFPs = 5
		shown := foreignFPs
		if len(shown) > maxForeignFPs {
			shown = shown[:maxForeignFPs]
		}
		msg := fmt.Sprintf("%d of %d volume(s) under %s carry a naming generation that no configured seed derives (configured: %s; found: %s) — serving would silently split tenants: delete answers false success and create builds a second tree. Point the seed source back at the generation this tree was created under, or, for a deliberate re-key, start with -allow-seed-generation-mismatch and run the migration",
			res.Foreign, res.Sampled, c.opts.VolRoot, strings.Join(known, ","), strings.Join(shown, ","))
		if c.opts.AllowGenerationMismatch {
			// Recorded even though it is allowed: "this instance is running
			// against a tree no configured generation derives" is exactly what
			// an operator must be able to see in --status later.
			c.recordErr(msg)
			c.opts.Logger.Printf("WARNING: %s (allowed by -allow-seed-generation-mismatch)", msg)
			return nil
		}
		c.recordErr(msg)
		return fmt.Errorf("%s", msg)
	}
	c.opts.Logger.Printf("provision: volumes-root generations verified (sampled=%d current=%s staged=%s legacy=%d foreign=0)", res.Sampled, curFP, stagedFP, res.LegacyCount())
	return nil
}

// Start reconciles once (which also installs the watchers for the configured
// file sources) and begins the poll loop. The poll is not a fallback for a
// broken watcher: it is the only signal that exists on filesystems where
// inotify never fires (a remote NFS write), and the content compare makes a
// poll that finds nothing completely free of side effects.
func (c *Coordinator) Start() {
	c.Reconcile("start")
	go c.pollLoop()
}

// Stop shuts the watchers and the poll loop down. Safe to call more than once.
func (c *Coordinator) Stop() {
	c.stopOnce.Do(func() {
		close(c.stop)
		c.mu.Lock()
		c.stopped = true
		ws := make([]*commonconfig.ReloadWatcher, 0, len(c.watchers))
		for path, w := range c.watchers {
			ws = append(ws, w)
			delete(c.watchers, path)
		}
		c.mu.Unlock()
		// Stopped OUTSIDE the mutex: Stop waits for the watcher's callback
		// goroutine, and an in-flight callback is waiting for this mutex.
		for _, w := range ws {
			w.Stop()
		}
		<-c.done
	})
}

func (c *Coordinator) pollLoop() {
	defer close(c.done)
	for {
		interval := time.Duration(c.opts.Config().Provision.EffectiveSeedPollSec()) * time.Second
		t := time.NewTimer(interval)
		select {
		case <-c.stop:
			t.Stop()
			return
		case <-t.C:
			c.Reconcile("poll")
		}
	}
}

// Reconcile re-reads the configured generations and applies whatever the
// config now says, running the promote gate first when a promotion is what it
// says. It is the ONLY caller of the namer's transition methods: one entry
// point, one mutex, one config snapshot per attempt.
//
// The returned error is the refusal, for callers that report one (the config
// reload path); the watcher and the poll ignore it because the coordinator
// already logged the classified reason. A refusal NEVER changes the live
// generations.
func (c *Coordinator) Reconcile(trigger string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.reconcileLocked(trigger)
}

func (c *Coordinator) reconcileLocked(trigger string) error {
	p := c.opts.Config().Provision

	// Watchers FIRST, and unconditionally: they follow the CONFIGURED sources,
	// not the resolvable ones. A source that cannot be read yet (the injector
	// has not materialized it) is precisely the one whose arrival must wake us
	// — installing watchers only on the success path would leave that case to
	// the poll alone.
	c.reconcileWatchers(p)

	cur, next, curSet, nextSet, err := c.resolve(p)
	if err != nil {
		// Not adopted: the live generations stay exactly as they were, and the
		// next event (or the poll) retries. This is the normal state while an
		// injector is between "pointer names the file" and "file exists", and
		// it is also the state a mid-write read lands in — the error text says
		// which.
		c.recordErr(fmt.Sprintf("seed re-read failed: %v", err))
		c.opts.Logger.Printf("WARNING: provision seed re-read failed (trigger=%s; live generations unchanged, retrying on the next change or poll): %v", trigger, err)
		c.publishStateLocked("refused", nil)
		return err
	}

	tr, err := c.opts.Namer.Classify(cur, next, curSet, nextSet)
	if err != nil {
		// The tamper case lands here: a CURRENT generation whose value changed
		// outside the stage → run → promote window. Refusing (keeping the live
		// value, alarming) is the whole point — adopting it would orphan every
		// volume on the next restart, and the startup guard would then refuse
		// to start until an operator intervenes.
		c.recordErr(err.Error())
		c.opts.Logger.Printf("ERROR: provision seed change REFUSED (trigger=%s; live generations unchanged): %v", trigger, err)
		c.publishStateLocked("refused", nil)
		return err
	}

	if tr == volname.TransitionPromote {
		if err := c.promoteGate(next); err != nil {
			c.recordErr(err.Error())
			c.opts.Logger.Printf("ERROR: provision seed promotion REFUSED (trigger=%s; live generations unchanged): %v", trigger, err)
			c.publishStateLocked("refused", nil)
			return err
		}
	}

	if err := c.opts.Namer.ApplySeeds(cur, next, curSet, nextSet); err != nil {
		c.recordErr(err.Error())
		c.opts.Logger.Printf("ERROR: provision seed transition failed (trigger=%s; live generations unchanged): %v", trigger, err)
		c.publishStateLocked("refused", nil)
		return err
	}

	staged, curFP, stagedFP := c.opts.Namer.GenerationSnapshot()
	hadErr := c.lastErrMsg != ""
	c.clearErr()
	if tr != volname.TransitionNone {
		c.opts.Logger.Printf("volume seed generations updated: transition=%s staged=%v generation=%s staged_generation=%s trigger=%s", tr, staged, curFP, stagedFP, trigger)
		c.publishStateLocked(tr.String(), nil)
	} else if hadErr {
		// Recovered from a refusal: record the return to a consistent state.
		c.publishStateLocked("none", nil)
	}
	return nil
}

// resolve reads both generations from ONE config snapshot, twice each, and
// requires the two readings to agree. That reader-side integrity rule is what
// makes an ARBITRARY injector safe: we never have to trust that a writer
// produces complete files, only that the value is stable when we look at it
// twice (a torn or mid-write value fails here and is retried, while a
// stable-but-different current generation is refused by the namer).
func (c *Coordinator) resolve(p sandlotconfig.ProvisionConfig) (cur, next []byte, curSet, nextSet bool, err error) {
	cur, _, err = p.CurrentSeed()
	if err != nil {
		return nil, nil, false, false, err
	}
	next, _, err = p.NextSeed()
	if err != nil {
		return nil, nil, false, false, err
	}
	cur2, _, err := p.CurrentSeed()
	if err != nil {
		return nil, nil, false, false, fmt.Errorf("the current seed became unreadable between two reads: %w", err)
	}
	if !bytes.Equal(cur, cur2) {
		return nil, nil, false, false, fmt.Errorf("the current seed changed between two reads — a write is in progress")
	}
	if next != nil {
		next2, _, err := p.NextSeed()
		if err != nil {
			return nil, nil, false, false, fmt.Errorf("the staged seed became unreadable between two reads: %w", err)
		}
		if !bytes.Equal(next, next2) {
			return nil, nil, false, false, fmt.Errorf("the staged seed changed between two reads — a write is in progress")
		}
	}
	return cur, next, p.SeedConfigured("current"), p.SeedConfigured("next"), nil
}

// namerSeeds is every seed a stamp under this namer may legitimately be
// signed with (current + staged during a rotation window).
func namerSeeds(n *volname.Map) [][]byte {
	seeds := [][]byte{n.CurrentSeed()}
	if next := n.NextSeed(); len(next) > 0 {
		seeds = append(seeds, next)
	}
	return seeds
}

// promoteGate is the daemon half of the completeness check the rotation tool
// runs as a pre-flight: promotion drops the old generation, so every volume
// that still carries it (or carries no generation at all) becomes permanently
// unresolvable. Strict on purpose — this is the irreversible step, and the
// operator is present. An inconclusive scan refuses too.
func (c *Coordinator) promoteGate(next []byte) error {
	oldFP := volname.Fingerprint(c.opts.Namer.CurrentSeed())
	newFP := volname.Fingerprint(next)
	res, err := volume.ScanGenerationStamps(c.opts.VolRoot, volume.ScanOptions{
		Known: []string{oldFP, newFP}, Seeds: namerSeeds(c.opts.Namer), Workers: guardWorkers, Deadline: guardDeadline,
	})
	if err != nil {
		return fmt.Errorf("cannot verify that every volume was renamed (%v) — promotion is irreversible, refusing", err)
	}
	if res.RootMissing {
		// Nothing was scanned: this is not "a clean tree with zero volumes"
		// (an absent root is exactly what a re-pointed -volumes-dir, or shared
		// storage not mounted at promote time, looks like). A promote would
		// drop the old generation while the real tree's volumes become
		// unresolvable (delete answers false success, create builds a second
		// tree). The STARTUP guard deliberately stays lenient on this same
		// reading (an unprepared host must not crash-loop; EnsureVolume owns
		// the actionable error) — the irreversible step is the strict one.
		return fmt.Errorf("the volumes root %s does not exist — nothing was scanned, so the tree cannot be proven renamed; promotion is irreversible, refusing (fix the volumes path or mount the shared storage, then re-run)", c.opts.VolRoot)
	}
	if !res.Complete {
		return fmt.Errorf("the volumes-root scan did not finish (%d directories examined) — promotion is irreversible, refusing", res.Sampled)
	}
	if n := res.Partial; n > 0 {
		// A genuine mid-provision directory (marker AND no authenticated
		// stamp) has no generation reading, so the rename cannot be proven.
		// A tenant-planted marker on a complete volume is classified by its
		// stamp above, not counted here.
		return fmt.Errorf("%d volume(s) are mid-provision (.provisioning marker, no authenticated stamp) — their rename cannot be proven; promotion is irreversible, refusing (let the partial run self-heal or remove the stale directory)", n)
	}
	if n := res.Unverified; n > 0 {
		return fmt.Errorf("%d volume(s) carry a stamp that cannot be authenticated (unsigned, or signed by a seed no configured generation derives) — the disk-side identity proof fails; promotion is irreversible, refusing", n)
	}
	if n := res.ReadErrors; n > 0 {
		// The gate's own contract: an inconclusive reading of the disk-side
		// authority refuses. An unreadable stamp (guest-planted modes, an I/O
		// error, a substituted non-file) hides the volume's generation — and
		// since --run iterates RECORDS, not directories, a directory the tool
		// never renamed (no record, or a record without rootfs_path) is only
		// ever visible through this scan. Treating a read error as "clean"
		// would silently orphan it past the point of return.
		return fmt.Errorf("%d volume(s) carry an unreadable generation stamp — the disk-side reading is inconclusive; promotion is irreversible, refusing", n)
	}
	if n := res.GenerationCount(oldFP); n > 0 {
		// Examples come from the scan's anomaly sampling, which tracks FOREIGN
		// generations — an un-renamed volume is not anomalous, so the clause is
		// omitted rather than printed empty. The tool's --status lists them.
		return fmt.Errorf("%d volume(s) still carry the pre-promote generation %s — complete the rotation's rename step first", n, oldFP)
	}
	if n := res.LegacyCount(); n > 0 {
		return fmt.Errorf("%d volume(s) carry no usable generation stamp — run the one-time migration before promoting", n)
	}
	return nil
}

// reconcileWatchers installs a watcher per configured file source and drops the
// ones no longer configured. Watch construction failing is an ERROR, not a
// warning: an unwatched source is exactly the gap this coordinator exists to
// close — but the poll still covers it, so it is not fatal.
func (c *Coordinator) reconcileWatchers(p sandlotconfig.ProvisionConfig) {
	if c.stopped {
		return
	}
	desired := map[string]bool{}
	for _, s := range p.SeedSources() {
		if s.Kind == sandlotconfig.SeedSourceFile {
			desired[s.Path] = true
		}
	}
	for path, w := range c.watchers {
		if desired[path] {
			continue
		}
		delete(c.watchers, path)
		// Asynchronous: this reconcile may be running ON that watcher's own
		// callback goroutine (a config edit that drops the source it watches),
		// and Stop waits for that goroutine to return.
		go w.Stop()
	}
	for path := range desired {
		if _, ok := c.watchers[path]; ok {
			continue
		}
		src := path
		w, err := commonconfig.NewReloadWatcher(src, func([]byte) {
			// The content argument is deliberately ignored: the coordinator
			// re-resolves from the config snapshot (with the two-read rule)
			// rather than trusting one read of one file.
			c.Reconcile("watch:" + src)
		})
		if err != nil {
			c.opts.Logger.Printf("ERROR: provision seed source %s cannot be watched (%v) — falling back to the %ds poll", src, err, p.EffectiveSeedPollSec())
			continue
		}
		c.watchers[src] = w
	}
}

// publishStateLocked writes the adoption record. stateMu is not needed: every
// caller holds c.mu.
func (c *Coordinator) publishStateLocked(transition string, scan *ScanState) {
	staged, curFP, stagedFP := c.opts.Namer.GenerationSnapshot()
	p := c.opts.Config().Provision

	st := State{
		PID:                os.Getpid(),
		AdoptedUnix:        time.Now().Unix(),
		CurrentFingerprint: curFP,
		StagedFingerprint:  stagedFP,
		Staged:             staged,
		LastTransition:     transition,
		Sources:            sourceStates(p),
		StartupScan:        scan,
		LastError:          c.lastErrMsg,
	}
	if err := WriteState(c.opts.StatePath, st); err != nil {
		c.opts.Logger.Printf("WARNING: cannot write the seed adoption record %s: %v", c.opts.StatePath, err)
	}
}

// sourceStates describes every configured channel, marking whether it reads
// right now. A configured-but-unresolved source is the "injector has not
// materialized it yet" state, which --status exists to show.
func sourceStates(p sandlotconfig.ProvisionConfig) []SourceState {
	srcs := p.SeedSources()
	out := make([]SourceState, 0, len(srcs))
	for _, s := range srcs {
		resolved := false
		switch s.Generation {
		case "next":
			_, _, err := p.NextSeed()
			resolved = err == nil
		default:
			_, _, err := p.CurrentSeed()
			resolved = err == nil
		}
		out = append(out, SourceState{Generation: s.Generation, Kind: s.Kind, Path: s.Path, Resolved: resolved})
	}
	return out
}

func (c *Coordinator) recordErr(msg string) { c.lastErrMsg = msg }

// clearErr drops the recorded refusal once a consistent state is applied
// again, so LastError in the state file never outlives the condition.
func (c *Coordinator) clearErr() { c.lastErrMsg = "" }
