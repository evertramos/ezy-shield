// SPDX-License-Identifier: AGPL-3.0-only

package config

// Validation tests for the enforce.aws_waf section (issue #201): scope and
// region rules, IPSet designation, strict rejection of credential-shaped
// keys and of pasted key material (credentials must never live in
// EzyShield config — ADR-0012).

import (
	"strings"
	"testing"
)

func loadAWSWAF(t *testing.T, section string) error {
	t.Helper()
	yaml := "data_dir: /tmp\nenforce:\n  aws_waf:\n" + section
	_, err := LoadConfigReader(strings.NewReader(yaml), "test")
	return err
}

func TestAWSWAF_ValidConfigs(t *testing.T) {
	t.Parallel()
	for name, section := range map[string]string{
		"regional both sets": `    scope: regional
    region: eu-west-1
    ipset_v4: {name: ez4, id: id4}
    ipset_v6: {name: ez6, id: id6}
`,
		"cloudfront v4 only": `    scope: cloudfront
    ipset_v4: {name: ez4, id: id4}
`,
		"named": `    name: edge
    scope: regional
    region: us-west-2
    ipset_v6: {name: ez6, id: id6}
`,
	} {
		if err := loadAWSWAF(t, section); err != nil {
			t.Errorf("%s: unexpected error: %v", name, err)
		}
	}
}

func TestAWSWAF_InvalidConfigs(t *testing.T) {
	t.Parallel()
	for name, tc := range map[string]struct {
		section string
		wantErr string
	}{
		"missing scope": {
			section: "    ipset_v4: {name: ez4, id: id4}\n",
			wantErr: "'scope' is required",
		},
		"bad scope": {
			section: "    scope: global\n    ipset_v4: {name: ez4, id: id4}\n",
			wantErr: "must be regional or cloudfront",
		},
		"regional without region": {
			section: "    scope: regional\n    ipset_v4: {name: ez4, id: id4}\n",
			wantErr: "requires 'region'",
		},
		"cloudfront with foreign region": {
			section: "    scope: cloudfront\n    region: eu-west-1\n    ipset_v4: {name: ez4, id: id4}\n",
			wantErr: "pins region us-east-1",
		},
		"no ipset": {
			section: "    scope: regional\n    region: eu-west-1\n",
			wantErr: "at least one of 'ipset_v4'/'ipset_v6'",
		},
		"ipset missing id": {
			section: "    scope: regional\n    region: eu-west-1\n    ipset_v4: {name: ez4}\n",
			wantErr: "both 'name' and 'id' are required",
		},
		// Credentials must never appear in config: a credential-shaped key
		// is rejected by the strict decoder as unknown…
		// (the AKIA string is AWS's PUBLIC documentation example, not a
		// real key)
		"inline credential field": {
			section: "    scope: regional\n    region: eu-west-1\n    access_key_id: AKIA" + "IOSFODNN7EXAMPLE\n    ipset_v4: {name: ez4, id: id4}\n", //nolint:gosec // AWS's public docs example key id
			wantErr: "field access_key_id not found",
		},
		// …and pasted key material inside a value field is caught by the
		// loader's generic credential scan.
		"key pasted into ipset name": {
			section: "    scope: regional\n    region: eu-west-1\n    ipset_v4: {name: AKIA" + "IOSFODNN7EXAMPLE, id: id4}\n", //nolint:gosec // AWS's public docs example key id
			wantErr: "appears to contain a credential",
		},
	} {
		err := loadAWSWAF(t, tc.section)
		if err == nil {
			t.Errorf("%s: expected an error", name)
			continue
		}
		if !strings.Contains(err.Error(), tc.wantErr) {
			t.Errorf("%s: error %q does not contain %q", name, err, tc.wantErr)
		}
	}
}
