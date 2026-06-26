package store

import (
	"context"
	"fmt"
	"net/netip"
)

// ScanRecord is a row from scan_baseline — a persisted snapshot of one
// listening socket. It is deliberately independent from internal/scan.Listener
// so the store package has no dependency on the scan package.
type ScanRecord struct {
	Proto          string
	LocalAddr      string // netip.AddrPort.String() form: "ip:port" or "[ip]:port"
	PID            int
	ExePath        string
	UID            uint32
	UserName       string
	IsPublic       bool
	OwnerType      string
	UnitName       string
	ContainerID    string
	ContainerName  string
	ContainerImage string
	LogSource      string
}

// UpsertScanRecord upserts a scan result into scan_baseline.
// On first insert first_seen is set; subsequent upserts refresh last_seen and
// all metadata columns so the baseline always reflects the latest observation.
// All values are parameterized — log-derived data never reaches SQL as literals.
func (s *DB) UpsertScanRecord(ctx context.Context, r ScanRecord) error {
	now := nowRFC3339()
	isPublic := 0
	if r.IsPublic {
		isPublic = 1
	}
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO scan_baseline
		    (proto, local_addr, first_seen, last_seen, pid, exe_path, uid, user_name,
		     is_public, owner_type, unit_name, container_id, container_name, container_image,
		     log_source)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(proto, local_addr) DO UPDATE SET
		    last_seen       = excluded.last_seen,
		    pid             = excluded.pid,
		    exe_path        = excluded.exe_path,
		    uid             = excluded.uid,
		    user_name       = excluded.user_name,
		    is_public       = excluded.is_public,
		    owner_type      = excluded.owner_type,
		    unit_name       = excluded.unit_name,
		    container_id    = excluded.container_id,
		    container_name  = excluded.container_name,
		    container_image = excluded.container_image,
		    log_source      = excluded.log_source
	`,
		r.Proto, r.LocalAddr, now, now,
		r.PID, r.ExePath, r.UID, r.UserName,
		isPublic, r.OwnerType, r.UnitName,
		r.ContainerID, r.ContainerName, r.ContainerImage,
		r.LogSource,
	)
	if err != nil {
		return fmt.Errorf("store: UpsertScanRecord %s %s: %w", r.Proto, r.LocalAddr, err)
	}
	return nil
}

// ScanBaseline returns all rows in scan_baseline as ScanRecord values.
// Callers compare the result against a fresh Scan to detect new listeners.
func (s *DB) ScanBaseline(ctx context.Context) ([]ScanRecord, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT proto, local_addr, pid, exe_path, uid, user_name,
		       is_public, owner_type, unit_name,
		       container_id, container_name, container_image, log_source
		FROM scan_baseline
	`)
	if err != nil {
		return nil, fmt.Errorf("store: ScanBaseline: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var out []ScanRecord
	for rows.Next() {
		var (
			r           ScanRecord
			isPublicInt int
		)
		if err := rows.Scan(
			&r.Proto, &r.LocalAddr,
			&r.PID, &r.ExePath, &r.UID, &r.UserName,
			&isPublicInt, &r.OwnerType, &r.UnitName,
			&r.ContainerID, &r.ContainerName, &r.ContainerImage,
			&r.LogSource,
		); err != nil {
			return nil, fmt.Errorf("store: ScanBaseline scan: %w", err)
		}
		r.IsPublic = isPublicInt != 0
		// Validate the stored addr:port to guard against corrupt DB rows.
		if _, err := netip.ParseAddrPort(r.LocalAddr); err != nil {
			return nil, fmt.Errorf("store: ScanBaseline bad addr %q: %w", r.LocalAddr, err)
		}
		out = append(out, r)
	}
	return out, rows.Err()
}
