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

package volume

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"common/util"
	"sandlot/provision/volname"
)

// VolumeIdentityFile is the stamp every volume carries: WHICH sandfs this
// directory belongs to. Since the directory NAME is derived from the seed
// (volname), the name alone cannot be verified against a record — the stamp is
// what turns a name/identity mismatch into a loud refusal instead of a silent
// mis-attach.
//
// What it protects against, in order of likelihood:
//
//   - a SEED MIX-UP (a half-applied rotation, a restored backup, a hand-renamed
//     directory): the same sandfs id now maps to a different directory name, so
//     an idempotent "the directory exists, carry on" would materialize a second
//     tree and split the tenant's data silently. The stamp makes EnsureVolume
//     refuse with ErrVolumeIdentityMismatch instead.
//   - a seed/id collision — 2^-128 per pair, i.e. not a real risk, but the same
//     check covers it for free.
//   - a TENANT-PLANTED stamp. In flat mode the volume root IS the agent's
//     chroot, so the tenant can replace this file (unlink + recreate). The
//     stamp therefore carries an HMAC over its own contents, keyed with the
//     volume-name seed the daemon never has: a forged/replayed stamp cannot be
//     made to verify, and the volume's directory NAME is bound into the MAC so
//     a valid stamp copied to another volume does not verify either.
//
// It deliberately contains NO seed material: only the logical id (which is
// public — DNS names and the agent API both carry it), the generation
// FINGERPRINT (a one-way 8-hex hash of the seed, for asserting which naming
// generation a directory's name belongs to), a creation timestamp (forensic
// only) and the one-way MAC.
const VolumeIdentityFile = ".sandfs-id"

// stampSigPrefix is the line carrying the hex HMAC.
const stampSigPrefix = "sig:"

// validVolumeEpoch is the accepted volume_epoch format: lowercase hex, at most
// 64 characters (empty = a pre-epoch stamp). The epoch is parsed from a
// line-oriented stamp and compared against gateway-supplied records, so a value
// carrying a newline (or any other separator) would corrupt the field layout:
// it is refused at WRITE time (before it can be signed into a stamp that later
// parses differently) and at READ time (a planted field is then a tampering
// signal, not a value).
var validVolumeEpoch = regexp.MustCompile(`^[0-9a-f]{0,64}$`)

// ErrVolumeStampUnreadable marks a stamp that EXISTS but is not a usable
// marker: a symlink/FIFO/oversized file planted in an agent-writable volume
// root, or a malformed field. It is a class of its own so a destructive
// cleanup can converge (quarantine) where a mount must simply refuse.
var ErrVolumeStampUnreadable = fmt.Errorf("volume identity stamp unreadable")

// validateVolumeEpoch enforces validVolumeEpoch.
func validateVolumeEpoch(epoch string) error {
	if !validVolumeEpoch.MatchString(epoch) {
		return fmt.Errorf("volume_epoch %q is not lowercase hex of at most 64 characters", epoch)
	}
	return nil
}

// volumeStamp is the parsed stamp.
type volumeStamp struct {
	SandfsID   string
	Generation string // volname fingerprint; "" = pre-generation stamp
	Mode       string // "flat" | "overlay"; "" = stamped before the mode field
	// VolumeEpoch is the random per-create identity from the sandfs record.
	// Empty = a pre-epoch stamp (legacy/dev); a mount with an expected epoch
	// refuses it.
	VolumeEpoch string
	CreatedUnix int64
	// Signature is the hex HMAC-SHA256 over the canonical payload, keyed with
	// the generation's seed. "" = an unsigned stamp (written by a pre-signature
	// build, or planted by the tenant): it never authenticates. The rotation
	// `--migrate` re-signs such volumes.
	Signature string
}

// stampPayload is the canonical MAC input. The volume's DIRECTORY NAME is
// bound in, so a stamp copied from another volume (or a directory renamed by
// hand) does not verify.
func stampPayload(volPath, id, generation, mode, volumeEpoch string, createdUnix int64) []byte {
	return stampPayloadForName(filepath.Base(volPath), id, generation, mode, volumeEpoch, createdUnix)
}

// stampPayloadForName is stampPayload with an explicit directory name (the
// rotation tool verifies a pre-rename stamp under the name it was written for).
func stampPayloadForName(name, id, generation, mode, volumeEpoch string, createdUnix int64) []byte {
	return []byte(fmt.Sprintf(
		"sandswap-volume-stamp-v1\nsandfs_id:%s\nvolume:%s\ngeneration:%s\nmode:%s\nvolume_epoch:%s\ncreated_unix:%d\n",
		id, name, generation, mode, volumeEpoch, createdUnix,
	))
}

func signStamp(seed, payload []byte) string {
	mac := hmac.New(sha256.New, seed)
	mac.Write(payload)
	return hex.EncodeToString(mac.Sum(nil))
}

// verifyVolumeStamp reports whether a stamp's signature matches one of the
// live generation seeds. An UNSIGNED stamp does NOT verify: in flat mode the
// volume root is the tenant's chroot, so an unsigned file proves nothing.
// (sandswap has no released deployments carrying pre-signature stamps; the
// one-time rotation `--migrate` re-signs any volume created by an unsigned
// build.)
func verifyVolumeStamp(volPath string, st volumeStamp, seeds [][]byte) bool {
	return verifyVolumeStampAtName(volPath, "", st, seeds)
}

// verifyVolumeStampAtName verifies a stamp whose signature was written for a
// DIFFERENT directory name (the seed-rotation rename: the stamp moves with the
// directory, but its MAC binds the old basename). An empty name means the
// current basename. The caller must only pass a name it observed before the
// rename; the name is bound into the MAC, so this is not a trust widening.
func verifyVolumeStampAtName(volPath, name string, st volumeStamp, seeds [][]byte) bool {
	if st.Signature == "" {
		return false
	}
	if name == "" {
		name = filepath.Base(volPath)
	}
	payload := stampPayloadForName(name, st.SandfsID, st.Generation, st.Mode, st.VolumeEpoch, st.CreatedUnix)
	for _, seed := range seeds {
		if len(seed) == 0 {
			continue
		}
		want := signStamp(seed, payload)
		if hmac.Equal([]byte(want), []byte(st.Signature)) {
			return true
		}
	}
	return false
}

// writeVolumeStamp writes the stamp for id under the given seed. Called from
// the one place that materializes a volume, and by the rotation tooling after
// a rename.
//
// mode is recorded because it is the only NODE-SIDE evidence of how a volume
// was created: a flat volume's directory IS the agent's chroot (fully
// guest-writable), so the overlay layout signature (marker + workspace/ +
// home/) is plantable there — but the mode is not something the guest decides,
// it is what the CREATE asked for (and it is covered by the MAC).
//
// The write is symlink-proof: a CreateTemp file (O_CREATE|O_EXCL, random
// name) in the volume directory, then rename over the final name. The tenant
// can plant `.sandfs-id` or any temp name as a symlink; O_EXCL refuses an
// existing entry, and rename(2) replaces the link itself rather than following
// it. The old fixed `.sandfs-id.tmp` name made the shell/root rotation path
// follow a tenant-planted link and truncate an arbitrary host file.
func writeVolumeStamp(volPath, id, mode string, seed []byte, createdUnix int64, epochs ...string) error {
	volumeEpoch := ""
	if len(epochs) > 0 {
		volumeEpoch = epochs[0]
	}
	if err := validateVolumeEpoch(volumeEpoch); err != nil {
		return fmt.Errorf("write volume stamp: %w", err)
	}
	generation := volname.Fingerprint(seed)
	sig := signStamp(seed, stampPayload(volPath, id, generation, mode, volumeEpoch, createdUnix))
	content := fmt.Sprintf(
		"sandfs_id: %s\ngeneration: %s\nmode: %s\nvolume_epoch: %s\ncreated_unix: %d\n%s %s\n",
		id, generation, mode, volumeEpoch, createdUnix, stampSigPrefix, sig,
	)
	tmp, err := os.CreateTemp(volPath, VolumeIdentityFile+".tmp-*")
	if err != nil {
		return fmt.Errorf("write volume stamp: %w", err)
	}
	tmpName := tmp.Name()
	installed := false
	defer func() {
		if !installed {
			_ = os.Remove(tmpName)
		}
	}()
	if _, err := tmp.WriteString(content); err != nil {
		tmp.Close()
		return fmt.Errorf("write volume stamp: %w", err)
	}
	// 0644: group-readable like the rest of the tree, owner-writable only.
	// CreateTemp starts at 0600.
	if err := tmp.Chmod(0o644); err != nil {
		tmp.Close()
		return fmt.Errorf("write volume stamp: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("write volume stamp: sync: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("write volume stamp: %w", err)
	}
	if err := os.Rename(tmpName, filepath.Join(volPath, VolumeIdentityFile)); err != nil {
		return fmt.Errorf("install volume stamp: %w", err)
	}
	installed = true
	return nil
}

// readVolumeStamp parses the stamp. ok=false means the file is absent.
//
// The read is hardened with util.ReadMarkerFile (O_NOFOLLOW + O_NONBLOCK +
// regular-file + 4 KiB cap). In flat mode the volume root is the tenant's
// chroot: a planted `.sandfs-id -> /dev/zero` used to make this host-side read
// loop until the prov process OOMed (the startup guard runs it for every
// volume), and a FIFO could park it forever. An entry that exists but is not a
// usable marker is reported as an ERROR (tampering), never as "no stamp".
func readVolumeStamp(volPath string) (volumeStamp, bool, error) {
	path := filepath.Join(volPath, VolumeIdentityFile)
	data, usable, err := util.ReadMarkerFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return volumeStamp{}, false, nil
		}
		return volumeStamp{}, false, err
	}
	if !usable {
		return volumeStamp{}, false, fmt.Errorf(
			"%w: %s exists but is not a regular file of at most %d bytes (planted symlink/FIFO/oversize?) — treating the stamp as unreadable",
			ErrVolumeStampUnreadable, path, util.MaxMarkerBytes,
		)
	}
	var st volumeStamp
	for _, line := range strings.Split(string(data), "\n") {
		key, val, found := strings.Cut(strings.TrimSpace(line), ":")
		if !found {
			continue
		}
		switch strings.TrimSpace(key) {
		case "sandfs_id":
			st.SandfsID = strings.TrimSpace(val)
		case "generation":
			st.Generation = strings.TrimSpace(val)
		case "mode":
			st.Mode = strings.TrimSpace(val)
		case "volume_epoch":
			st.VolumeEpoch = strings.TrimSpace(val)
		case "created_unix":
			st.CreatedUnix, _ = strconv.ParseInt(strings.TrimSpace(val), 10, 64)
		case "sig":
			st.Signature = strings.TrimSpace(val)
		}
	}
	if err := validateVolumeEpoch(st.VolumeEpoch); err != nil {
		return volumeStamp{}, false, fmt.Errorf("%w: %s: %v", ErrVolumeStampUnreadable, path, err)
	}
	return st, true, nil
}

// CheckVolumeID is the SEEDLESS identity gate the exec node runs at
// cold-mount time: the volume directory must carry a readable identity stamp
// whose sandfs_id field equals sandfsID, binding the gateway-supplied
// (sandfs_id, volume_path) pair to the on-disk identity. The exec role
// deliberately holds no seed (the volume-name seed is prov-only), so the
// stamp's HMAC cannot be checked here — the signature remains
// Provisioner.VerifyVolumeIdentity's job on the prov instance. Equality is
// the right check for this threat: a compromised gateway (which mounts no
// storage and has no write grant) chooses the path, but cannot rewrite the
// victim volume's stamp. A mounted-storage writer is a higher trust root and
// is out of this gate's scope.
//
// Errors are detailed for the caller's LOCAL log; callers must not forward
// them to an agent because the volume path is a host-side secret.
func CheckVolumeID(volPath, sandfsID string, epochs ...string) error {
	if err := ValidateSandfsID(sandfsID); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidArgument, err)
	}
	st, ok, err := readVolumeStamp(volPath)
	if err != nil {
		return fmt.Errorf("%w: cannot read the identity stamp (%v)", ErrVolumeIdentityMismatch, err)
	}
	if !ok {
		return fmt.Errorf("%w: the directory carries no %s stamp", ErrVolumeIdentityMismatch, VolumeIdentityFile)
	}
	if st.SandfsID != sandfsID {
		return fmt.Errorf("%w: the stamp names a different sandfs", ErrVolumeIdentityMismatch)
	}
	if len(epochs) > 0 {
		// A mount carrying no epoch cannot be bound to the volume generation:
		// pre-epoch volumes are refused rather than compared as "empty ==
		// empty", which would let a stale record for a reused id mount the
		// new owner's volume.
		if epochs[0] == "" {
			return fmt.Errorf("%w: the mount carries no volume epoch", ErrVolumeIdentityMismatch)
		}
		if st.VolumeEpoch != epochs[0] {
			return fmt.Errorf("%w: the stamp names a different volume generation", ErrVolumeIdentityMismatch)
		}
	}
	return nil
}

// StampInfo is the exported view of a volume's identity stamp, for the
// rotation tool. The tool must never read the stamp with shell redirection or
// grep: in flat mode the file sits in the tenant's chroot, where a planted
// symlink turns a root-run read/write into an arbitrary host-file operation.
type StampInfo struct {
	SandfsID    string
	Generation  string
	Mode        string
	VolumeEpoch string
	CreatedUnix int64
	Signed      bool
}

// stampInfoOf projects a parsed stamp onto the tool-facing view.
func stampInfoOf(st volumeStamp) StampInfo {
	return StampInfo{
		SandfsID:    st.SandfsID,
		Generation:  st.Generation,
		Mode:        st.Mode,
		VolumeEpoch: st.VolumeEpoch,
		CreatedUnix: st.CreatedUnix,
		Signed:      st.Signature != "",
	}
}

// ReadVolumeStampForTool is the safe stamp read for `template-tool
// volume-stamp-read` (O_NOFOLLOW, regular file, 4 KiB cap; symlinks/FIFOs/
// oversize are an ERROR, not "absent").
func ReadVolumeStampForTool(volPath string) (StampInfo, bool, error) {
	st, ok, err := readVolumeStamp(volPath)
	if err != nil || !ok {
		return StampInfo{}, ok, err
	}
	return stampInfoOf(st), true, nil
}

// ReadVerifiedVolumeStampForTool reads a stamp ONCE and reports whether it
// verifies against the given seeds. One read, one parse: the returned fields
// and the verdict describe the same file bytes, so a caller may trust the
// fields (sandfs_id, mode) exactly when verified is true — re-reading the file
// after a separate verification would leave a swap window in which a tenant
// replaces the stamp between the two reads.
func ReadVerifiedVolumeStampForTool(volPath string, seeds [][]byte) (info StampInfo, present, verified bool, err error) {
	st, ok, err := readVolumeStamp(volPath)
	if err != nil || !ok {
		return StampInfo{}, ok, false, err
	}
	return stampInfoOf(st), true, verifyVolumeStamp(volPath, st, seeds), nil
}

// VerifyVolumeStampForTool reads a stamp safely and reports whether its
// signature verifies against a provided seed. Used by the rotation tool before
// it preserves fields (mode/created) from an existing stamp: a tenant-chosen
// value must not be re-signed into authority.
func VerifyVolumeStampForTool(volPath string, seeds [][]byte) (present, verified bool, err error) {
	return VerifyVolumeStampForToolAtName(volPath, "", seeds)
}

// VerifyVolumeStampForToolAtName is VerifyVolumeStampForTool with the
// pre-rename directory name. The rotation tool renames a volume (and its
// stamp) before re-signing; the old signature binds the OLD basename, so
// verifying it against the new path alone would silently drop the preserved
// volume_epoch. The name is bound into the MAC, so a caller cannot widen trust
// by naming an arbitrary directory.
func VerifyVolumeStampForToolAtName(volPath, name string, seeds [][]byte) (present, verified bool, err error) {
	st, ok, err := readVolumeStamp(volPath)
	if err != nil || !ok {
		return ok, false, err
	}
	if name != "" && verifyVolumeStampAtName(volPath, name, st, seeds) {
		return true, true, nil
	}
	return true, verifyVolumeStamp(volPath, st, seeds), nil
}

// WriteVolumeStampForTool is the safe stamp write for `template-tool
// volume-stamp-write`: CreateTemp (O_EXCL) + rename, never a followed
// path, signed with the generation's seed.
func WriteVolumeStampForTool(volPath, id, mode string, seed []byte, createdUnix int64, epochs ...string) error {
	return writeVolumeStamp(volPath, id, mode, seed, createdUnix, epochs...)
}

// ErrVolumeIdentityMismatch is the refusal EnsureVolume raises when an
// existing directory's stamp does not name the sandfs being created. It is a
// named class (not a bare error) because the operator action differs from
// every other failure: inspect the seed generations (a mix-up is the likely
// cause) and, if the directory is genuinely the wrong tenant's, do NOT
// continue.
var ErrVolumeIdentityMismatch = fmt.Errorf("volume identity mismatch")
