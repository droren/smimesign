package main

import (
	"strings"
	"testing"
)

func TestExtractCommitSignaturePEM(t *testing.T) {
	commit := strings.Join([]string{
		"tree deadbeef",
		"author Test User <test@example.com> 0 +0000",
		"committer Test User <test@example.com> 0 +0000",
		"gpgsig -----BEGIN SIGNED MESSAGE-----",
		" MIIB",
		" AAAA",
		" -----END SIGNED MESSAGE-----",
		"",
		"message",
	}, "\n")

	got, err := extractCommitSignaturePEM([]byte(commit))
	if err != nil {
		t.Fatalf("extractCommitSignaturePEM returned error: %v", err)
	}

	want := strings.Join([]string{
		"-----BEGIN SIGNED MESSAGE-----",
		"MIIB",
		"AAAA",
		"-----END SIGNED MESSAGE-----",
		"",
	}, "\n")

	if string(got) != want {
		t.Fatalf("unexpected signature contents:\nwant:\n%s\ngot:\n%s", want, string(got))
	}
}

func TestExtractCommitSignaturePEMUnsignedCommit(t *testing.T) {
	_, err := extractCommitSignaturePEM([]byte("tree deadbeef\n\nmessage\n"))
	if err == nil {
		t.Fatal("expected error for unsigned commit")
	}
}
