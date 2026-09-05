package main

import (
	"strings"
	"testing"
)

func TestClientSetupPageMarkup(t *testing.T) {
	if got := clientSetupHTML(nil); got != "" {
		t.Fatal("admin downloads must not include client profile setup")
	}
	profile := &downloadProfile{
		Server:   `https://porta.test/"<server>`,
		Token:    `" autofocus onfocus="alert('token')`,
		QRCode:   "data:image/png;base64,aW1hZ2U=",
		Notice:   `<script>alert("notice")</script>`,
		SetupURI: `porta://profile?v=1&token="<setup>`,
	}
	page := clientSetupHTML(profile)
	for _, want := range []string{
		`2. Set up your profile`,
		`id="setup-qr"`,
		`src="data:image/png;base64,aW1hZ2U="`,
		`type="password"`,
		`https://porta.test/&#34;&lt;server&gt;`,
		`&#34; autofocus onfocus=&#34;alert(&#39;token&#39;)`,
		`&lt;script&gt;alert(&#34;notice&#34;)&lt;/script&gt;`,
		`src="/assets/portal-client.js"`,
		`Scan QR code`,
		`Windows / Linux`,
		`Copy setup`,
		`Add profile &gt; Paste setup`,
		`id="setup-uri" type="hidden" value="porta://profile?v=1&amp;token=&#34;&lt;setup&gt;"`,
	} {
		if !strings.Contains(page, want) {
			t.Errorf("missing %q", want)
		}
	}
	if strings.Contains(page, profile.Notice) || strings.Contains(page, profile.Token) || strings.Contains(page, profile.SetupURI) ||
		strings.Contains(page, `href="porta:`) {
		t.Fatal("unescaped profile data")
	}
	for _, qr := range []string{"", "https://external.test/secret.png", "data:image/png;base64,invalid!"} {
		profile.QRCode = qr
		page = clientSetupHTML(profile)
		if strings.Contains(page, `id="setup-qr"`) || !strings.Contains(page, "Profile QR unavailable") ||
			!strings.Contains(page, `id="setup-token"`) {
			t.Fatalf("invalid QR %q must retain manual setup without an image", qr)
		}
		profile.SetupURI = ""
		page = clientSetupHTML(profile)
		if strings.Contains(page, `id="setup-copy-uri"`) || strings.Contains(page, `id="setup-uri"`) {
			t.Fatal("missing setup URI must not offer a broken clipboard action")
		}
	}
}

func TestJoinPageMarkup(t *testing.T) {
	page := joinPageHTML("")
	for _, want := range []string{
		`data-join-state="auto"`,
		`src="/assets/portal-join.js"`,
		`href="/access"`,
		`<noscript>`,
	} {
		if !strings.Contains(page, want) {
			t.Errorf("missing %q", want)
		}
	}
	if strings.Contains(page, "<input") {
		t.Fatal("invitation landing page must not prompt for an access token")
	}
	message := `<script>alert("secret")</script>`
	page = joinPageHTML(message)
	if !strings.Contains(page, `data-join-state="error"`) ||
		strings.Contains(page, message) ||
		!strings.Contains(page, "&lt;script&gt;") {
		t.Fatal("server error must be escaped and must disable automatic redemption")
	}
}
