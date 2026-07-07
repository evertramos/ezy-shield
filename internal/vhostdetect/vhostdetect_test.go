package vhostdetect

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
)

// fakeCLI is a table-driven DockerCLI used by every test here. It returns
// canned Ps output and per-container Inspect output; either can be forced
// to error to simulate Docker being down / a container disappearing between
// enumeration and inspection.
type fakeCLI struct {
	psOut      string
	psErr      error
	inspect    map[string]string // container name → env output
	inspectErr map[string]error  // container name → err

	psCalls      int
	inspectCalls int
}

func (f *fakeCLI) Ps(_ context.Context, _ string) (string, error) {
	f.psCalls++
	return f.psOut, f.psErr
}

func (f *fakeCLI) Inspect(_ context.Context, container, _ string) (string, error) {
	f.inspectCalls++
	if err := f.inspectErr[container]; err != nil {
		return "", err
	}
	return f.inspect[container], nil
}

func TestDetect_MultiDomainVirtualHost(t *testing.T) {
	t.Parallel()
	cli := &fakeCLI{
		psOut: strings.Join([]string{
			"web1\tnginxproxy/nginx-proxy",
			"api\tcompany/api:1.0",
			"db\tpostgres:16",
		}, "\n"),
		inspect: map[string]string{
			"web1": "PATH=/usr/bin\nDEBIAN_FRONTEND=noninteractive\n",
			"api":  "VIRTUAL_HOST=api.example.com, admin.example.com ,   ,dashboard.example.com\nAPP_ENV=prod\n",
			"db":   "POSTGRES_PASSWORD=secret\n",
		},
	}
	got, err := Detect(context.Background(), cli)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("want 1 vhost container, got %d: %+v", len(got), got)
	}
	v := got[0]
	if v.Container != "api" {
		t.Errorf("Container = %q, want api", v.Container)
	}
	wantDomains := []string{"api.example.com", "admin.example.com", "dashboard.example.com"}
	if !reflect.DeepEqual(v.Domains, wantDomains) {
		t.Errorf("Domains = %v, want %v (empty and whitespace-only entries must be dropped)", v.Domains, wantDomains)
	}
}

func TestDetect_MissingVirtualHostEnv(t *testing.T) {
	t.Parallel()
	cli := &fakeCLI{
		psOut: "solo\tnginx:1.27\n",
		inspect: map[string]string{
			"solo": "PATH=/usr/bin\n",
		},
	}
	got, err := Detect(context.Background(), cli)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("expected no vhosts, got %+v", got)
	}
}

func TestDetect_DockerDown_ReturnsEmpty(t *testing.T) {
	t.Parallel()
	cli := &fakeCLI{
		psErr: errors.New("connect: no such file or directory"),
	}
	got, err := Detect(context.Background(), cli)
	if err != nil {
		t.Fatalf("want nil err on docker-down, got %v", err)
	}
	if got != nil {
		t.Errorf("want nil slice, got %+v", got)
	}
	// And we must NOT have called inspect at all — the ps failure is
	// terminal.
	if cli.inspectCalls != 0 {
		t.Errorf("inspect called %d times after ps failure — should be 0", cli.inspectCalls)
	}
}

func TestDetect_PerContainerInspectError_IsSkipped(t *testing.T) {
	t.Parallel()
	cli := &fakeCLI{
		psOut: strings.Join([]string{
			"gone\tnginx:1",
			"good\tnginx:1",
		}, "\n"),
		inspect: map[string]string{
			"good": "VIRTUAL_HOST=example.com\n",
		},
		inspectErr: map[string]error{
			"gone": errors.New("no such container"),
		},
	}
	got, err := Detect(context.Background(), cli)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if len(got) != 1 || got[0].Container != "good" {
		t.Errorf("want just [good], got %+v", got)
	}
}

func TestSplitDomains(t *testing.T) {
	t.Parallel()
	cases := []struct {
		in   string
		want []string
	}{
		{"", nil},
		{"a.com", []string{"a.com"}},
		{"a.com,b.com", []string{"a.com", "b.com"}},
		{"  a.com  ,  b.com  ", []string{"a.com", "b.com"}},
		{"a.com,,b.com", []string{"a.com", "b.com"}},
		{"*.example.com,ok.example.com", []string{"ok.example.com"}}, // wildcard dropped
		{".broken.com", nil},                                         // leading dot dropped
	}
	for _, tc := range cases {
		got := splitDomains(tc.in)
		if !reflect.DeepEqual(got, tc.want) {
			t.Errorf("splitDomains(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

func TestAllDomains_Deduplicates(t *testing.T) {
	t.Parallel()
	in := []VHost{
		{Container: "a", Domains: []string{"x.com", "y.com"}},
		{Container: "b", Domains: []string{"y.com", "z.com"}},
	}
	got := AllDomains(in)
	want := []string{"x.com", "y.com", "z.com"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("AllDomains = %v, want %v", got, want)
	}
}
