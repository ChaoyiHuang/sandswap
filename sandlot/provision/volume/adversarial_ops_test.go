// Copyright 2026 Chaoyang Huang. All rights reserved.
//
// SPDX-License-Identifier: BUSL-1.1
//
// Adversarial pins for the volume-ops contract: planted markers,
// re-seed/re-save and swap attacks. Where a defense exists the attack
// assertion is inverted to REQUIRE it; the rest keep their adversarial
// form (controls included).

package volume

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"sandlot/provision/template"
	"sandlot/provision/volname"
)

const advSeed = "303030303030303030303030303030303030303030303030303030303030303030"

func advProvisioner(t *testing.T) (*Provisioner, string, string) {
	t.Helper()
	base := t.TempDir()
	volRoot := filepath.Join(base, "volumes")
	store := filepath.Join(base, "templates")
	if err := os.MkdirAll(volRoot, 0o770); err != nil {
		t.Fatal(err)
	}
	// local overlay + flat template sources
	ovSrc := filepath.Join(base, "ovsrc")
	if err := os.MkdirAll(filepath.Join(ovSrc, "etc"), 0755); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(ovSrc, "etc", "motd"), []byte("overlay-template"), 0644)
	// (The flat source is created inside the store, AFTER NewManager — the
	// flat consume path only accepts store/scan-root content.)

	mgr, err := template.NewManager(template.Config{TemplatesDir: store})
	if err != nil {
		t.Fatal(err)
	}
	flatSrc := filepath.Join(store, "flatsrc")
	if err := os.MkdirAll(filepath.Join(flatSrc, "etc"), 0755); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(flatSrc, "etc", "motd"), []byte("flat-template"), 0644)
	ovSrc2 := filepath.Join(base, "ovsrc2")
	if err := os.MkdirAll(filepath.Join(ovSrc2, "etc"), 0755); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(ovSrc2, "etc", "motd"), []byte("overlay-template-2"), 0644)
	if err := mgr.RegisterLocalTemplate("ov:v1", ovSrc); err != nil {
		t.Fatal(err)
	}
	if err := mgr.RegisterLocalTemplate("ov:v2", ovSrc2); err != nil {
		t.Fatal(err)
	}
	if err := mgr.RegisterFlatTemplate("fl:v1", flatSrc); err != nil {
		t.Fatal(err)
	}
	seed, err := volname.DecodeSeed(advSeed)
	if err != nil {
		t.Fatal(err)
	}
	namer, err := volname.NewMap(seed)
	if err != nil {
		t.Fatal(err)
	}
	p, err := NewWithNamer(volRoot, mgr, namer)
	if err != nil {
		t.Fatal(err)
	}
	return p, volRoot, store
}

// D1: an existing dir whose stamp names ANOTHER sandfs must be refused for
// both ensure and delete (cross-tenant guard).
func TestVolStampMismatchRefused(t *testing.T) {
	p, _, _ := advProvisioner(t)
	if _, err := p.EnsureVolume(context.Background(), "sf-alice", "overlay", "ov:v1"); err != nil {
		t.Fatal(err)
	}
	volPath, _ := p.resolveVolPath("sf-alice")
	// forge the stamp to another tenant (seed mix-up / hand-rename state)
	if err := os.WriteFile(filepath.Join(volPath, VolumeIdentityFile), []byte("sandfs_id: sf-bob\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := p.EnsureVolume(context.Background(), "sf-alice", "overlay", "ov:v1"); err == nil {
		t.Fatalf("ensure accepted a foreign-stamped dir")
	} else {
		t.Logf("ensure refused: %v", err)
	}
	if err := p.DeleteVolume(context.Background(), "sf-alice"); err == nil {
		t.Fatalf("delete accepted a foreign-stamped dir")
	} else {
		t.Logf("delete refused: %v", err)
	}
	if _, err := p.SwapTemplate(context.Background(), "sf-alice", "ov:v1", ""); err == nil {
		t.Fatalf("swap accepted a foreign-stamped dir")
	} else {
		t.Logf("swap refused: %v", err)
	}
	if _, err := os.Stat(volPath); err != nil {
		t.Fatalf("refused ops must not delete the dir")
	}
}

// D2: un-stamped dir refused.
func TestVolUnstampedRefused(t *testing.T) {
	p, volRoot, _ := advProvisioner(t)
	named := p.Names.Current("sf-carol")
	volPath := filepath.Join(volRoot, named)
	if err := os.MkdirAll(volPath, 0o770); err != nil {
		t.Fatal(err)
	}
	if _, err := p.EnsureVolume(context.Background(), "sf-carol", "overlay", "ov:v1"); err == nil {
		t.Fatalf("ensure accepted an un-stamped dir")
	} else {
		t.Logf("ensure refused: %v", err)
	}
	if err := p.DeleteVolume(context.Background(), "sf-carol"); err == nil {
		t.Fatalf("delete accepted an un-stamped dir")
	} else {
		t.Logf("delete refused: %v", err)
	}
}

// D3: a .provisioning marker only explains a MISSING stamp. When a stamp is
// present it is checked first — the marker lives in the same agent-writable
// volume root, so letting it shadow a stamp would be a one-touch bypass of
// the signature and layout checks.
func TestVolMarkerDoesNotShadowStamp(t *testing.T) {
	p, volRoot, _ := advProvisioner(t)
	named := p.Names.Current("sf-dave")
	volPath := filepath.Join(volRoot, named)
	if err := os.MkdirAll(volPath, 0o770); err != nil {
		t.Fatal(err)
	}
	// foreign stamp AND marker: the stamp is authoritative, so this is refused.
	os.WriteFile(filepath.Join(volPath, VolumeIdentityFile), []byte("sandfs_id: sf-someoneelse\n"), 0644)
	os.WriteFile(filepath.Join(volPath, provisioningMarker), []byte("x"), 0644)
	if err := p.DeleteVolume(context.Background(), "sf-dave"); err == nil {
		t.Fatalf("delete accepted a marker-carrying dir with a foreign stamp")
	}
	if _, err := os.Stat(volPath); err != nil {
		t.Fatalf("refused volume should still exist: %v", err)
	}

	// With NO stamp, the marker still exempts (the self-heal path).
	named2 := p.Names.Current("sf-erin")
	volPath2 := filepath.Join(volRoot, named2)
	if err := os.MkdirAll(volPath2, 0o770); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(volPath2, provisioningMarker), []byte("x"), 0644)
	if err := p.DeleteVolume(context.Background(), "sf-erin"); err != nil {
		t.Fatalf("delete refused a marker-only partial volume: %v", err)
	}
	if _, err := os.Stat(volPath2); !os.IsNotExist(err) {
		t.Fatalf("marker-only dir not removed")
	}
}

// D4: SwapTemplate home policies; workspace never touched.
func TestVolSwapHomePolicies(t *testing.T) {
	p, _, _ := advProvisioner(t)
	if _, err := p.EnsureVolume(context.Background(), "sf-eve", "overlay", "ov:v1"); err != nil {
		t.Fatal(err)
	}
	volPath, _ := p.resolveVolPath("sf-eve")
	os.WriteFile(filepath.Join(volPath, "workspace", "thesis.txt"), []byte("WORK"), 0644)
	os.WriteFile(filepath.Join(volPath, "home", "notes.txt"), []byte("HOME"), 0644)

	if _, err := p.SwapTemplate(context.Background(), "sf-eve", "ov:v2", HomeArchive); err != nil {
		t.Fatalf("swap: %v", err)
	}
	archives := 0
	entries, _ := os.ReadDir(volPath)
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "home.pre-attach-") {
			archives++
		}
	}
	if archives != 1 {
		t.Fatalf("expected 1 archive, got %d", archives)
	}
	if b, _ := os.ReadFile(filepath.Join(volPath, "workspace", "thesis.txt")); string(b) != "WORK" {
		t.Fatalf("workspace lost")
	}
	t.Logf("archive: home archived once, workspace kept")

	// idempotent re-issue of the same (ref, policy)
	if _, err := p.SwapTemplate(context.Background(), "sf-eve", "ov:v2", HomeArchive); err != nil {
		t.Fatalf("re-swap: %v", err)
	}
	if mk, err := p.Templates.LoadRefEntry("ov:v2", "overlay"); err != nil || len(mk.Layers) == 0 {
		t.Fatalf("v2 ref broken: %v", err)
	}
	// reset wipes home but not workspace (swap back to v1)
	if _, err := p.SwapTemplate(context.Background(), "sf-eve", "ov:v1", HomeReset); err != nil {
		t.Fatalf("reset swap: %v", err)
	}
	if _, err := os.Stat(filepath.Join(volPath, "home", "notes.txt")); !os.IsNotExist(err) {
		t.Fatalf("reset did not wipe home")
	}
	if b, _ := os.ReadFile(filepath.Join(volPath, "workspace", "thesis.txt")); string(b) != "WORK" {
		t.Fatalf("workspace lost on reset")
	}
	t.Logf("reset: home wiped, workspace kept")
}

// D5: an agent-planted .template marker (flat volumes are agent-writable)
// pins an overlay template from deletion.
func TestPlantedMarkerBlocksTemplateDelete(t *testing.T) {
	p, _, _ := advProvisioner(t)
	if _, err := p.EnsureVolume(context.Background(), "sf-frank", "flat", "fl:v1"); err != nil {
		t.Fatal(err)
	}
	volPath, _ := p.resolveVolPath("sf-frank")
	// the volume root is the agent's chroot: the agent can write here
	if err := os.WriteFile(filepath.Join(volPath, ".template"), []byte("ov:v1"), 0644); err != nil {
		t.Fatal(err)
	}
	// fix (pinned): a marker WITHOUT the overlay layout signature
	// (workspace/ + home/) is tenant-plantable garbage and must NOT pin the
	// template. (The naive refusal here is TemplateInUseError; the pin
	// requires the delete to proceed.)
	err := p.DeleteTemplate(context.Background(), "ov:v1", "overlay", false)
	if err != nil {
		t.Fatalf(": planted marker (no layout) still pinned the template: %v", err)
	}
	t.Logf("planted marker rejected: delete proceeded without --force")

	// Control: a REAL overlay volume (layout present) still pins.
	if _, err := p.EnsureVolume(context.Background(), "sf-real-ov", "overlay", "ov:v2"); err != nil {
		t.Fatal(err)
	}
	if err := p.DeleteTemplate(context.Background(), "ov:v2", "overlay", false); err == nil {
		t.Fatalf("control failed: real overlay volume did not pin its template")
	} else if _, ok := err.(*TemplateInUseError); !ok {
		t.Fatalf("unexpected control error type: %T %v", err, err)
	}
	if err := p.DeleteTemplate(context.Background(), "ov:v2", "overlay", true); err != nil {
		t.Fatalf("force delete failed: %v", err)
	}
	t.Logf("control: real overlay pins; force proceeds")
}

// D6: SaveAsTemplate wipes a hand-created local-<name>-<ver> dir with no ref.
func TestSaveWipesHandMadeLayerDir(t *testing.T) {
	p, volRoot, store := advProvisioner(t)
	if _, err := p.EnsureVolume(context.Background(), "sf-gina", "flat", "fl:v1"); err != nil {
		t.Fatal(err)
	}
	// a manager WITH a volume resolver, as the prov role wires it
	mgr2, err := template.NewManager(template.Config{
		TemplatesDir:  store,
		ResolveVolume: func(id string) (string, error) { return filepath.Join(volRoot, p.Names.Current(id)), nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	handMade := filepath.Join(store, "layers", "local-precious-v9")
	if err := os.MkdirAll(handMade, 0755); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(handMade, "operator-data"), []byte("OPERATOR"), 0644)

	// fix (pinned): a hand-made dir (no sandfs save-marker) must NOT
	// be wiped — refuse loudly. (The naive behavior wipes and re-seeds
	// silently.)
	if _, err := mgr2.SaveAsTemplate(context.Background(), "sf-gina", template.SaveAsTemplateRequest{TemplateRef: "precious:v9"}); err == nil {
		t.Fatalf(": hand-made local dir was not protected (save succeeded)")
	} else {
		t.Logf("save refused over hand-made dir: %v", err)
	}
	if b, err := os.ReadFile(filepath.Join(handMade, "operator-data")); err != nil || string(b) != "OPERATOR" {
		t.Fatalf("operator data lost despite refusal")
	}
}

// K: re-ensure with a DIFFERENT template silently re-seeds over an existing
// complete volume (mixed content, no gate).
func TestReensureDifferentTemplateMixes(t *testing.T) {
	p, _, _ := advProvisioner(t)
	// Inside the store: the flat consume path accepts only store/scan-root
	// content.
	fl2 := filepath.Join(p.Templates.TemplatesDir(), "fl2")
	os.MkdirAll(filepath.Join(fl2, "etc"), 0755)
	os.WriteFile(filepath.Join(fl2, "etc", "motd"), []byte("flat-two"), 0644)
	if err := p.Templates.RegisterFlatTemplate("fl:v2", fl2); err != nil {
		t.Fatal(err)
	}
	// put an extra file into v1 source after first ensure
	if _, err := p.EnsureVolume(context.Background(), "sf-hank", "flat", "fl:v1"); err != nil {
		t.Fatal(err)
	}
	volPath, _ := p.resolveVolPath("sf-hank")
	os.WriteFile(filepath.Join(volPath, "agent-data"), []byte("AGENT"), 0644)

	// fix (pinned): a complete stamped volume is NEVER re-seeded —
	// the v2 content must not appear and the agent data must survive.
	// (The naive behavior silently re-seeds into mixed content; the pin
	// requires the no-op.) Template changes go through swap-template / delete+create.
	res, err := p.EnsureVolume(context.Background(), "sf-hank", "flat", "fl:v2")
	if err != nil {
		t.Fatalf("re-ensure: %v", err)
	}
	if res.RootfsPath != volPath {
		t.Fatalf("re-ensure path changed: %s vs %s", res.RootfsPath, volPath)
	}
	motd, _ := os.ReadFile(filepath.Join(volPath, "etc", "motd"))
	if string(motd) != "flat-template" {
		t.Fatalf(": v2 content leaked into a complete volume (motd=%q)", motd)
	}
	if b, aerr := os.ReadFile(filepath.Join(volPath, "agent-data")); aerr != nil || string(b) != "AGENT" {
		t.Fatalf("agent data lost: %v %q", aerr, b)
	}
	t.Logf("re-ensure with different ref was a true no-op; content mixed = no")
}

// Idempotency: same-ref re-ensure must be safe (the claim).
func TestReensureSameRefIdempotent(t *testing.T) {
	p, _, _ := advProvisioner(t)
	if _, err := p.EnsureVolume(context.Background(), "sf-ivy", "flat", "fl:v1"); err != nil {
		t.Fatal(err)
	}
	volPath, _ := p.resolveVolPath("sf-ivy")
	os.WriteFile(filepath.Join(volPath, "agent-data"), []byte("AGENT"), 0644)
	if _, err := p.EnsureVolume(context.Background(), "sf-ivy", "flat", "fl:v1"); err != nil {
		t.Fatalf("same-ref re-ensure failed: %v", err)
	}
	if b, err := os.ReadFile(filepath.Join(volPath, "agent-data")); err != nil || string(b) != "AGENT" {
		t.Fatalf("agent data lost on same-ref re-ensure: %v %q", err, b)
	}
	t.Logf("same-ref re-ensure: idempotent, agent data kept")
}

// Control: SaveAsTemplate strips the volume control files from the copy and
// refuses overlay sources.
func TestSaveStripsControlFiles(t *testing.T) {
	p, volRoot, store := advProvisioner(t)
	if _, err := p.EnsureVolume(context.Background(), "sf-zoe", "flat", "fl:v1"); err != nil {
		t.Fatal(err)
	}
	mgr2, err := template.NewManager(template.Config{
		TemplatesDir:  store,
		ResolveVolume: func(id string) (string, error) { return filepath.Join(volRoot, p.Names.Current(id)), nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := mgr2.SaveAsTemplate(context.Background(), "sf-zoe", template.SaveAsTemplateRequest{TemplateRef: "zoe:v1"}); err != nil {
		t.Fatal(err)
	}
	layer := filepath.Join(store, "layers", "local-zoe-v1")
	if _, err := os.Stat(filepath.Join(layer, ".sandfs-id")); !os.IsNotExist(err) {
		t.Fatalf("identity stamp survived into the saved template")
	}
	if _, err := os.Stat(filepath.Join(layer, ".provisioning")); !os.IsNotExist(err) {
		t.Fatalf("provisioning marker survived into the saved template")
	}
	t.Logf("control files stripped from the saved layer")

	// overlay source refused
	if _, err := p.EnsureVolume(context.Background(), "sf-yan", "overlay", "ov:v1"); err != nil {
		t.Fatal(err)
	}
	if _, err := mgr2.SaveAsTemplate(context.Background(), "sf-yan", template.SaveAsTemplateRequest{TemplateRef: "yan:v1"}); err == nil {
		t.Fatalf("overlay source accepted for save")
	} else {
		t.Logf("overlay source refused: %.80v", err)
	}
}
