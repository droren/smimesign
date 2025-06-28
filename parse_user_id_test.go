package main

import "testing"

// These test-vectors are taken from examples commonly found in git-config
// documentation and various mail headers.

func TestParseUserID(t *testing.T) {
    cases := []struct {
        in                 string
        wantName           string
        wantComment        string
        wantEmail          string
    }{
        {"Alice <alice@example.com>", "Alice", "", "alice@example.com"},
        {"Bob (Work) <bob@work.example>", "Bob", "Work", "bob@work.example"},
        {"Carol", "Carol", "", ""},
        {"<root@localhost>", "", "", "root@localhost"},
        {"Dave (comment only)", "Dave", "comment only", ""},
    }

    for _, c := range cases {
        gotName, gotComment, gotEmail := parseUserID(c.in)
        if gotName != c.wantName || gotComment != c.wantComment || gotEmail != c.wantEmail {
            t.Fatalf("parseUserID(%q) = (%q,%q,%q), want (%q,%q,%q)",
                c.in, gotName, gotComment, gotEmail, c.wantName, c.wantComment, c.wantEmail)
        }
    }
}

