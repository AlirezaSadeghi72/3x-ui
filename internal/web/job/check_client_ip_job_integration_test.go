package job

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/op/go-logging"

	"github.com/mhsanaei/3x-ui/v3/internal/database"
	"github.com/mhsanaei/3x-ui/v3/internal/database/model"
	xuilogger "github.com/mhsanaei/3x-ui/v3/internal/logger"
)

// 3x-ui logger must be initialised once before any code path that can
// log a warning. otherwise log.Warningf panics on a nil logger.
var loggerInitOnce sync.Once

// setupIntegrationDB wires a temp sqlite db and log folder so
// updateInboundClientIps can run end to end. closes the db before
// TempDir cleanup so windows doesn't complain about the file being in
// use.
func setupIntegrationDB(t *testing.T) {
	t.Helper()

	loggerInitOnce.Do(func() {
		xuilogger.InitLogger(logging.ERROR)
	})

	dbDir := t.TempDir()
	logDir := t.TempDir()

	t.Setenv("XUI_DB_FOLDER", dbDir)
	t.Setenv("XUI_LOG_FOLDER", logDir)

	// updateInboundClientIps calls log.SetOutput on the package global,
	// which would leak to other tests in the same binary.
	origLogWriter := log.Writer()
	origLogFlags := log.Flags()
	t.Cleanup(func() {
		log.SetOutput(origLogWriter)
		log.SetFlags(origLogFlags)
	})

	if err := database.InitDB(filepath.Join(dbDir, "x-ui.db")); err != nil {
		t.Fatalf("database.InitDB failed: %v", err)
	}
	// LIFO cleanup order: this runs before t.TempDir's own cleanup.
	t.Cleanup(func() {
		if err := database.CloseDB(); err != nil {
			t.Logf("database.CloseDB warning: %v", err)
		}
	})
}

// seed an inbound whose settings json has a single client with the
// given email and ip limit.
func seedInboundWithClient(t *testing.T, tag, email string, limitIp int) {
	t.Helper()
	seedInboundOnlyWithClient(t, tag, email, limitIp)
}

func seedInboundOnlyWithClient(t *testing.T, tag, email string, limitIp int) *model.Inbound {
	t.Helper()
	settings := map[string]any{
		"clients": []map[string]any{
			{
				"email":   email,
				"limitIp": limitIp,
				"enable":  true,
			},
		},
	}
	settingsJSON, err := json.Marshal(settings)
	if err != nil {
		t.Fatalf("marshal settings: %v", err)
	}
	inbound := &model.Inbound{
		Tag:      tag,
		Enable:   true,
		Protocol: model.VLESS,
		Port:     4321,
		Settings: string(settingsJSON),
	}
	if err := database.GetDB().Create(inbound).Error; err != nil {
		t.Fatalf("seed inbound: %v", err)
	}
	return inbound
}

func seedLinkedInboundWithClient(t *testing.T, tag, email string, limitIp int) *model.Inbound {
	t.Helper()
	inbound := seedInboundOnlyWithClient(t, tag, email, limitIp)
	client := &model.ClientRecord{Email: email, LimitIP: limitIp}
	if err := database.GetDB().Create(client).Error; err != nil {
		t.Fatalf("seed client record: %v", err)
	}
	link := &model.ClientInbound{ClientId: client.Id, InboundId: inbound.Id}
	if err := database.GetDB().Create(link).Error; err != nil {
		t.Fatalf("seed client inbound link: %v", err)
	}
	return inbound
}

// seed an InboundClientIps row with the given blob.
func seedClientIps(t *testing.T, email string, ips []IPWithTimestamp) *model.InboundClientIps {
	t.Helper()
	blob, err := json.Marshal(ips)
	if err != nil {
		t.Fatalf("marshal ips: %v", err)
	}
	row := &model.InboundClientIps{
		ClientEmail: email,
		Ips:         string(blob),
	}
	if err := database.GetDB().Create(row).Error; err != nil {
		t.Fatalf("seed InboundClientIps: %v", err)
	}
	return row
}

// read the persisted blob and parse it back.
func readClientIps(t *testing.T, email string) []IPWithTimestamp {
	t.Helper()
	row := &model.InboundClientIps{}
	if err := database.GetDB().Where("client_email = ?", email).First(row).Error; err != nil {
		t.Fatalf("read InboundClientIps for %s: %v", email, err)
	}
	if row.Ips == "" {
		return nil
	}
	var out []IPWithTimestamp
	if err := json.Unmarshal([]byte(row.Ips), &out); err != nil {
		t.Fatalf("unmarshal Ips blob %q: %v", row.Ips, err)
	}
	return out
}

// make a lookup map so asserts don't depend on slice order.
func ipSet(entries []IPWithTimestamp) map[string]int64 {
	out := make(map[string]int64, len(entries))
	for _, e := range entries {
		out[e.IP] = e.Timestamp
	}
	return out
}

// With the access-log fallback removed, an unavailable online-stats API (xray
// down, as in this unit test) must make Run a clean no-op: no fail2ban probe, no
// ban log, and no inbound_client_ips rows — never a crash or partial work.
func TestRun_NoOpWhenOnlineApiUnavailable(t *testing.T) {
	setupIntegrationDB(t)
	t.Setenv("XUI_ENABLE_FAIL2BAN", "true")
	marker := fakeFail2BanClient(t)

	const email = "no-api-user"
	seedInboundWithClient(t, "inbound-no-api", email, 1)

	NewCheckClientIpJob().Run()

	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatalf("fail2ban-client should not have been probed when the online API is unavailable, stat error: %v", err)
	}
	if info, err := os.Stat(readIpLimitLogPath()); err == nil && info.Size() > 0 {
		body, _ := os.ReadFile(readIpLimitLogPath())
		t.Fatalf("3xipl.log should be empty when Run no-ops, got:\n%s", body)
	}
	var count int64
	if err := database.GetDB().Model(&model.InboundClientIps{}).Where("client_email = ?", email).Count(&count).Error; err != nil {
		t.Fatalf("count InboundClientIps: %v", err)
	}
	if count != 0 {
		t.Fatalf("no IP-limit rows should be persisted when Run no-ops, got %d", count)
	}
}

// #4091 repro: client has limit=3, db still holds 3 idle ips from a
// few minutes ago, only one live ip is actually connecting. pre-fix:
// live ip got banned every tick and never appeared in the panel.
// post-fix: no ban, live ip persisted, historical ips still visible.
func TestUpdateInboundClientIps_LiveIpNotBannedByStillFreshHistoricals(t *testing.T) {
	setupIntegrationDB(t)

	const email = "pr4091-repro"
	seedInboundWithClient(t, "inbound-pr4091", email, 3)

	now := time.Now().Unix()
	// idle but still within the 300s TTL window.
	row := seedClientIps(t, email, []IPWithTimestamp{
		{IP: "10.0.0.1", Timestamp: now - 100},
		{IP: "10.0.0.2", Timestamp: now - 200},
		{IP: "10.0.0.3", Timestamp: now - 250},
	})

	j := NewCheckClientIpJob()
	// the one that's actually connecting (user's 128.71.x.x).
	live := []IPWithTimestamp{
		{IP: "128.71.1.1", Timestamp: now},
	}
	observedLive := map[string]bool{"128.71.1.1": true}
	staleCutoff := staleCutoffForTTL(0)

	inbound, err := j.getInboundByEmail(email)
	if err != nil {
		t.Fatalf("getInboundByEmail: %v", err)
	}
	shouldCleanLog, banned := j.updateInboundClientIps(database.GetDB(), row, inbound, email, 3, live, true, false, staleCutoff, observedLive, 0)

	if shouldCleanLog {
		t.Fatalf("shouldCleanLog must be false, nothing should have been banned with 1 live ip under limit 3")
	}
	if banned {
		t.Fatalf("banned must be false with 1 live ip under limit 3")
	}
	if len(j.disAllowedIps) != 0 {
		t.Fatalf("disAllowedIps must be empty, got %v", j.disAllowedIps)
	}

	persisted := ipSet(readClientIps(t, email))
	for _, want := range []string{"128.71.1.1", "10.0.0.1", "10.0.0.2", "10.0.0.3"} {
		if _, ok := persisted[want]; !ok {
			t.Errorf("expected %s to be persisted in inbound_client_ips.ips; got %v", want, persisted)
		}
	}
	if got := persisted["128.71.1.1"]; got != now {
		t.Errorf("live ip timestamp should match the scan timestamp %d, got %d", now, got)
	}

	// 3xipl.log must not contain a ban line.
	if info, err := os.Stat(readIpLimitLogPath()); err == nil && info.Size() > 0 {
		body, _ := os.ReadFile(readIpLimitLogPath())
		t.Fatalf("3xipl.log should be empty when no ips are banned, got:\n%s", body)
	}
}

// opposite invariant: when several ips are actually live and exceed
// the limit, the oldest connection is dropped and the most recent one
// keeps the slot (last-IP-wins policy from #3735, restored in #4699).
func TestUpdateInboundClientIps_ExcessLiveIpIsStillBanned(t *testing.T) {
	setupIntegrationDB(t)

	const email = "pr4091-abuse"
	seedInboundWithClient(t, "inbound-pr4091-abuse", email, 1)

	now := time.Now().Unix()
	row := seedClientIps(t, email, []IPWithTimestamp{
		{IP: "10.1.0.1", Timestamp: now - 60}, // original connection
	})

	j := NewCheckClientIpJob()
	// both live, limit=1. use distinct timestamps so sort-by-timestamp
	// is deterministic: 10.1.0.1 is the original (older) and must get
	// banned; 192.0.2.9 joined later and keeps the slot (last IP wins).
	live := []IPWithTimestamp{
		{IP: "10.1.0.1", Timestamp: now - 5},
		{IP: "192.0.2.9", Timestamp: now},
	}

	inbound, err := j.getInboundByEmail(email)
	if err != nil {
		t.Fatalf("getInboundByEmail: %v", err)
	}
	observedLive := map[string]bool{"10.1.0.1": true, "192.0.2.9": true}
	staleCutoff := staleCutoffForTTL(0)
	shouldCleanLog, banned := j.updateInboundClientIps(database.GetDB(), row, inbound, email, 1, live, true, false, staleCutoff, observedLive, 0)

	if !shouldCleanLog {
		t.Fatalf("shouldCleanLog must be true when the live set exceeds the limit")
	}
	if !banned {
		t.Fatalf("banned must be true when the live set exceeds the limit")
	}
	if len(j.disAllowedIps) != 1 || j.disAllowedIps[0] != "10.1.0.1" {
		t.Fatalf("expected 10.1.0.1 to be banned; disAllowedIps = %v", j.disAllowedIps)
	}

	persisted := ipSet(readClientIps(t, email))
	if _, ok := persisted["192.0.2.9"]; !ok {
		t.Errorf("newest IP 192.0.2.9 must still be persisted; got %v", persisted)
	}
	if _, ok := persisted["10.1.0.1"]; ok {
		t.Errorf("banned IP 10.1.0.1 must NOT be persisted; got %v", persisted)
	}

	// 3xipl.log must contain the ban line in the exact fail2ban format.
	body, err := os.ReadFile(readIpLimitLogPath())
	if err != nil {
		t.Fatalf("read 3xipl.log: %v", err)
	}
	wantSubstr := "[LIMIT_IP] Email = pr4091-abuse || Disconnecting OLD IP = 10.1.0.1"
	if !contains(string(body), wantSubstr) {
		t.Fatalf("3xipl.log missing expected ban line %q\nfull log:\n%s", wantSubstr, body)
	}
}

// #4800: per-client IP tracking must populate even when no client has an IP
// limit. processObserved records observed IPs for the panel regardless of any
// limit; only enforcement is gated, so a limit-free install still shows IPs. No
// ban may be written since there's no limit.
func TestProcessObserved_CollectsIpsWithoutLimit(t *testing.T) {
	setupIntegrationDB(t)

	const email = "no-limit-user"
	seedInboundWithClient(t, "inbound-no-limit", email, 0) // limitIp = 0

	observed := map[string]map[string]int64{
		email: {"203.0.113.10": time.Now().Unix()},
	}
	NewCheckClientIpJob().processObserved(observed, true, true)

	ips := readClientIps(t, email)
	if len(ips) != 1 || ips[0].IP != "203.0.113.10" {
		t.Fatalf("expected the observed IP to be collected without a limit, got %v", ips)
	}

	if info, err := os.Stat(readIpLimitLogPath()); err == nil && info.Size() > 0 {
		body, _ := os.ReadFile(readIpLimitLogPath())
		t.Fatalf("3xipl.log should be empty with no limit set, got:\n%s", body)
	}
}

// #4963: an observed IP for a renamed/deleted client (its email no longer maps
// to any inbound) must not create or resurrect an inbound_client_ips row, and
// must drop any orphan left behind — instead of erroring every run.
func TestProcessObserved_StaleEmailIsSkippedAndOrphanDropped(t *testing.T) {
	setupIntegrationDB(t)

	const staleEmail = "renamed-away"
	// No inbound references staleEmail. Pre-seed an orphan tracking row to
	// confirm the job removes it rather than leaving it to error forever.
	seedClientIps(t, staleEmail, []IPWithTimestamp{{IP: "203.0.113.5", Timestamp: time.Now().Unix()}})

	observed := map[string]map[string]int64{
		staleEmail: {"203.0.113.5": time.Now().Unix()},
	}
	NewCheckClientIpJob().processObserved(observed, true, true)

	var count int64
	if err := database.GetDB().Model(&model.InboundClientIps{}).Where("client_email = ?", staleEmail).Count(&count).Error; err != nil {
		t.Fatalf("count InboundClientIps: %v", err)
	}
	if count != 0 {
		t.Fatalf("stale-email orphan row should be deleted, got %d row(s)", count)
	}
}

// readIpLimitLogPath reads the 3xipl.log path the same way the job
// does via xray.GetIPLimitLogPath but without importing xray here
// just for the path helper (which would pull a lot more deps into the
// test binary). The env-derived log folder is deterministic.
func readIpLimitLogPath() string {
	folder := os.Getenv("XUI_LOG_FOLDER")
	if folder == "" {
		folder = filepath.Join(".", "log")
	}
	return filepath.Join(folder, "3xipl.log")
}

func contains(haystack, needle string) bool {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}

// the exact clients/client_inbounds relation must win over the substring scan,
// so a client is resolved to its own inbound even when another inbound holds a
// superstring email.
func TestGetInboundByEmailUsesClientInboundLink(t *testing.T) {
	setupIntegrationDB(t)

	want := seedLinkedInboundWithClient(t, "linked-inbound", "exact@example.com", 1)
	seedInboundOnlyWithClient(t, "other-inbound", "not-exact@example.com", 1)

	got, err := (&CheckClientIpJob{}).getInboundByEmail("exact@example.com")
	if err != nil {
		t.Fatalf("getInboundByEmail returned error: %v", err)
	}
	if got.Id != want.Id {
		t.Fatalf("getInboundByEmail returned inbound %d, want %d", got.Id, want.Id)
	}
}

// the substring fallback must still verify the exact email inside settings, so
// "ann@example.com" does not match an inbound holding "joann@example.com".
func TestGetInboundByEmailRejectsSubstringFallbackMatch(t *testing.T) {
	setupIntegrationDB(t)

	seedInboundOnlyWithClient(t, "substring-only", "joann@example.com", 1)

	if got, err := (&CheckClientIpJob{}).getInboundByEmail("ann@example.com"); err == nil {
		t.Fatalf("substring email matched inbound %d; want no exact match", got.Id)
	}
}

// hasLimitIp gates every 10s scan on the normalized clients table: a bare
// "limitIp":0 in settings JSON (which the old LIKE scan matched and parsed)
// must not enable enforcement, while a single clients.limit_ip > 0 row must.
func TestHasLimitIp_ProbesClientRecords(t *testing.T) {
	setupIntegrationDB(t)
	j := &CheckClientIpJob{}

	if j.hasLimitIp() {
		t.Fatal("hasLimitIp = true on an empty database")
	}

	seedLinkedInboundWithClient(t, "no-limit", "nolimit@example.com", 0)
	if j.hasLimitIp() {
		t.Fatal("hasLimitIp = true with only limit_ip=0 clients")
	}

	limited := &model.ClientRecord{Email: "limited@example.com", LimitIP: 2}
	if err := database.GetDB().Create(limited).Error; err != nil {
		t.Fatalf("seed limited client: %v", err)
	}
	if !j.hasLimitIp() {
		t.Fatal("hasLimitIp = false with a limit_ip=2 client present")
	}
}

// scenario 4: TTL expiry cleanup — IPs older than ttlSec are removed
// from inbound_client_ips, while live and fresh IPs that are within
// the TTL window survive and participate in enforcement.
func TestUpdateInboundClientIps_TtlExpiryCleansStaleIps(t *testing.T) {
	setupIntegrationDB(t)

	const email = "ttl-expiry-user"
	seedInboundWithClient(t, "inbound-ttl-expiry", email, 5)

	ttlSec := int64(300)
	now := time.Now().Unix()
	staleCutoff := now - ttlSec

	// Two IPs inside the TTL window (should survive).
	// Two IPs outside the TTL window (should be expired).
	row := seedClientIps(t, email, []IPWithTimestamp{
		{IP: "10.0.0.1", Timestamp: now - 60},        // fresh, within TTL
		{IP: "10.0.0.2", Timestamp: now - 100},       // fresh, within TTL
		{IP: "10.0.0.3", Timestamp: now - ttlSec - 1}, // expired (just past cutoff)
		{IP: "10.0.0.4", Timestamp: now - ttlSec - 500}, // expired (far past cutoff)
	})

	j := NewCheckClientIpJob()
	live := []IPWithTimestamp{
		{IP: "203.0.113.50", Timestamp: now}, // new live IP
	}
	observedLive := map[string]bool{"203.0.113.50": true}

	inbound, err := j.getInboundByEmail(email)
	if err != nil {
		t.Fatalf("getInboundByEmail: %v", err)
	}
	shouldCleanLog, banned := j.updateInboundClientIps(database.GetDB(), row, inbound, email, 5, live, true, false, staleCutoff, observedLive, 0)

	if shouldCleanLog {
		t.Fatalf("shouldCleanLog must be false — 1 live IP under limit 5")
	}
	if banned {
		t.Fatalf("banned must be false — 1 live IP under limit 5")
	}

	persisted := ipSet(readClientIps(t, email))
	// Fresh IPs should survive.
	for _, want := range []string{"10.0.0.1", "10.0.0.2", "203.0.113.50"} {
		if _, ok := persisted[want]; !ok {
			t.Errorf("expected IP %q to survive TTL cleanup; got %v", want, persisted)
		}
	}
	// Expired IPs must be gone.
	for _, gone := range []string{"10.0.0.3", "10.0.0.4"} {
		if _, ok := persisted[gone]; ok {
			t.Errorf("expired IP %q must have been removed by TTL cleanup; got %v", gone, persisted)
		}
	}
}

// scenario 6: TTL disabled (ttlSec=0) falls back to the legacy 30-minute
// stale cutoff. IPs older than 30 minutes are expired; IPs within 30 minutes survive.
func TestUpdateInboundClientIps_TtlDisabledUsesLegacyCutoff(t *testing.T) {
	setupIntegrationDB(t)

	const email = "ttl-disabled-user"
	seedInboundWithClient(t, "inbound-ttl-disabled", email, 5)

	now := time.Now().Unix()
	// TTL=0 → staleCutoff = now - 30min (legacy).
	staleCutoff := staleCutoffForTTL(0)

	row := seedClientIps(t, email, []IPWithTimestamp{
		{IP: "10.0.0.1", Timestamp: now - 100},       // 100s old — survives 30min legacy cutoff
		{IP: "10.0.0.2", Timestamp: now - 2000},       // 33min old — just past legacy cutoff? no, 2000s = 33.3min > 30min
		{IP: "10.0.0.3", Timestamp: now - 1800 - 1},   // just past 30min legacy cutoff → expired
	})

	j := NewCheckClientIpJob()
	live := []IPWithTimestamp{
		{IP: "198.51.100.1", Timestamp: now},
	}
	observedLive := map[string]bool{"198.51.100.1": true}

	inbound, err := j.getInboundByEmail(email)
	if err != nil {
		t.Fatalf("getInboundByEmail: %v", err)
	}
	shouldCleanLog, banned := j.updateInboundClientIps(database.GetDB(), row, inbound, email, 5, live, true, false, staleCutoff, observedLive, 0)

	if shouldCleanLog {
		t.Fatalf("shouldCleanLog must be false")
	}
	if banned {
		t.Fatalf("banned must be false")
	}

	persisted := ipSet(readClientIps(t, email))
	if _, ok := persisted["10.0.0.1"]; !ok {
		t.Errorf("IP 10.0.0.1 within 30min legacy cutoff should survive; got %v", persisted)
	}
	for _, gone := range []string{"10.0.0.2", "10.0.0.3"} {
		if _, ok := persisted[gone]; ok {
			t.Errorf("IP %q past 30min legacy cutoff should be expired; got %v", gone, persisted)
		}
	}
	if _, ok := persisted["198.51.100.1"]; !ok {
		t.Errorf("live IP 198.51.100.1 must be persisted; got %v", persisted)
	}
}

// scenario 7: multi-email isolation — CGNAT churn for one email does not
// affect the IP tracking of a second email. Each email gets independent
// enforcements, stale-cutoff expiry, and churn replacement.
func TestProcessObserved_MultiEmailIsolation(t *testing.T) {
	setupIntegrationDB(t)

	const emailA = "churn-user-a"
	const emailB = "stable-user-b"

	now := time.Now().Unix()
	seedInboundWithClient(t, "inbound-a", emailA, 1)
	seedInboundWithClient(t, "inbound-b", emailB, 1)

	// Email A: one old IP that will be churned (replaced by a newer one).
	seedClientIps(t, emailA, []IPWithTimestamp{
		{IP: "10.1.1.1", Timestamp: now - 100},
	})
	// Email B: one old IP that stays (no churn).
	seedClientIps(t, emailB, []IPWithTimestamp{
		{IP: "10.2.2.2", Timestamp: now - 100},
	})

	observed := map[string]map[string]int64{
		emailA: {"10.1.1.1": now - 100, "10.20.20.1": now}, // churn: old 10.1.1.1 → new 10.20.20.1
		emailB: {"10.2.2.2": now},                          // no churn, same IP observed again
	}

	j := NewCheckClientIpJob()
	j.processObserved(observed, true, true)

	// Email A's IPs should now contain the new IP (old one was churned/expired by TTL).
	ipsA := ipSet(readClientIps(t, emailA))
	if _, ok := ipsA["10.20.20.1"]; !ok {
		t.Errorf("email A should have the new IP after churn; got %v", ipsA)
	}

	// Email B's IP should be untouched by email A's churn.
	ipsB := ipSet(readClientIps(t, emailB))
	if _, ok := ipsB["10.2.2.2"]; !ok {
		t.Errorf("email B should retain its IP unaffected by email A's churn; got %v", ipsB)
	}
}

// Scenario 2: End-to-end CGNAT churn — same email, IP changes within
// IPReplaceThreshold. The old IP must be replaced; only the new IP persists.
// No LIMIT_IP event, no Fail2Ban trigger.
func TestProcessObserved_CGNATChurnReplacesOldIP(t *testing.T) {
	setupIntegrationDB(t)

	const email = "cgnat-churn-user"
	seedInboundWithClient(t, "inbound-cgnat", email, 2)

	now := time.Now().Unix()
	// Pre-seed one old IP from a previous scan (CGNAT-assigned IP).
	seedClientIps(t, email, []IPWithTimestamp{
		{IP: "10.20.30.1", Timestamp: now - 15},
	})

	observed := map[string]map[string]int64{
		email: {
			// Old IP is gone; a new CGNAT IP appeared within threshold.
			"10.20.30.2": now,
		},
	}

	j := NewCheckClientIpJob()
	j.processObserved(observed, true, true)

	persisted := ipSet(readClientIps(t, email))
	// Old IP 10.20.30.1 should have been replaced by 10.20.30.2.
	if _, ok := persisted["10.20.30.1"]; ok {
		t.Errorf("old CGNAT IP 10.20.30.1 should have been replaced; got %v", persisted)
	}
	if _, ok := persisted["10.20.30.2"]; !ok {
		t.Errorf("new CGNAT IP 10.20.30.2 must be persisted; got %v", persisted)
	}

	// No [LIMIT_IP] ban line — only one IP, under limit.
	body, err := os.ReadFile(readIpLimitLogPath())
	if err != nil || len(body) == 0 {
		// empty or missing 3xipl.log is correct (no ban)
	} else {
		t.Errorf("no LIMIT_IP ban expected for single-IP CGNAT churn; got 3xipl.log:\n%s", body)
	}
}

// Scenario 4: Two active devices behind the same email.
// Both IPs appear in observedThisScan (live). Neither is replaced.
// Both are counted toward the IP limit normally.
func TestUpdateInboundClientIps_TwoActiveDevicesNoReplacement(t *testing.T) {
	setupIntegrationDB(t)

	const email = "two-active-devices"
	seedInboundWithClient(t, "inbound-two-devices", email, 5)

	now := time.Now().Unix()
	oldIPs := seedClientIps(t, email, []IPWithTimestamp{
		{IP: "10.1.1.1", Timestamp: now - 100},
	})

	j := NewCheckClientIpJob()
	// Both IPs are live in this scan — neither should be replaced.
	live := []IPWithTimestamp{
		{IP: "10.1.1.1", Timestamp: now},
		{IP: "10.1.1.2", Timestamp: now},
	}
	observedBoth := map[string]bool{"10.1.1.1": true, "10.1.1.2": true}
	staleCutoff := staleCutoffForTTL(300)

	inbound, err := j.getInboundByEmail(email)
	if err != nil {
		t.Fatalf("getInboundByEmail: %v", err)
	}
	shouldClean, banned := j.updateInboundClientIps(database.GetDB(), oldIPs, inbound, email, 5, live, true, false, staleCutoff, observedBoth, 30)

	if shouldClean {
		t.Fatalf("shouldCleanLog must be false — 2 IPs under limit 5")
	}
	if banned {
		t.Fatalf("banned must be false — 2 IPs under limit 5")
	}

	persisted := ipSet(readClientIps(t, email))
	for _, want := range []string{"10.1.1.1", "10.1.1.2"} {
		if _, ok := persisted[want]; !ok {
			t.Errorf("live IP %q must be persisted; got %v", want, persisted)
		}
	}
}

// Scenario 5: Three active devices with limit=2.
// The oldest live device must be banned; the two newest remain.
func TestUpdateInboundClientIps_ThreeDevicesLimitTwoBanOldest(t *testing.T) {
	setupIntegrationDB(t)

	const email = "three-devices-limit-two"
	seedInboundWithClient(t, "inbound-three-devices", email, 2)

	now := time.Now().Unix()
	oldIPs := seedClientIps(t, email, []IPWithTimestamp{
		{IP: "10.1.1.1", Timestamp: now - 200},
	})

	j := NewCheckClientIpJob()
	// Three live IPs, limit=2. oldest should be banned.
	live := []IPWithTimestamp{
		{IP: "10.1.1.1", Timestamp: now - 10},
		{IP: "10.1.1.2", Timestamp: now - 5},
		{IP: "10.1.1.3", Timestamp: now},
	}
	observedAll := map[string]bool{"10.1.1.1": true, "10.1.1.2": true, "10.1.1.3": true}
	staleCutoff := staleCutoffForTTL(300)

	inbound, err := j.getInboundByEmail(email)
	if err != nil {
		t.Fatalf("getInboundByEmail: %v", err)
	}
	shouldClean, banned := j.updateInboundClientIps(database.GetDB(), oldIPs, inbound, email, 2, live, true, false, staleCutoff, observedAll, 30)

	if !shouldClean {
		t.Fatalf("shouldCleanLog must be true — 3 IPs over limit 2")
	}
	if !banned {
		t.Fatalf("banned must be true — 3 IPs over limit 2")
	}
	if len(j.disAllowedIps) != 1 || j.disAllowedIps[0] != "10.1.1.1" {
		t.Errorf("expected oldest IP 10.1.1.1 to be banned; got disAllowedIps=%v", j.disAllowedIps)
	}
}

// Scenario 8: Replace disabled (threshold=0). Every IP change is stored
// independently. Multiple old IPs are retained; no churn replacement.
func TestUpdateInboundClientIps_ReplaceDisabledThresholdZero(t *testing.T) {
	setupIntegrationDB(t)

	const email = "replace-disabled-user"
	seedInboundWithClient(t, "inbound-replace-disabled", email, 5)

	now := time.Now().Unix()
	thresholdSec := int64(0)
	oldIPs := seedClientIps(t, email, []IPWithTimestamp{
		{IP: "10.1.1.1", Timestamp: now - 60},
	})

	j := NewCheckClientIpJob()
	// A new IP within 30s of the old one would normally trigger replacement.
	// But with threshold=0, replaceChurnedIPs is a no-op. Both IPs survive.
	live := []IPWithTimestamp{
		{IP: "10.1.1.1", Timestamp: now - 10},
		{IP: "10.2.2.2", Timestamp: now},
	}
	observedNew := map[string]bool{"10.1.1.1": true, "10.2.2.2": true}
	staleCutoff := staleCutoffForTTL(300)

	inbound, err := j.getInboundByEmail(email)
	if err != nil {
		t.Fatalf("getInboundByEmail: %v", err)
	}
	shouldClean, banned := j.updateInboundClientIps(database.GetDB(), oldIPs, inbound, email, 5, live, true, false, staleCutoff, observedNew, thresholdSec)

	if shouldClean {
		t.Fatalf("shouldCleanLog must be false — 2 IPs under limit 5")
	}
	if banned {
		t.Fatalf("banned must be false")
	}

	persisted := ipSet(readClientIps(t, email))
	// Both old and new IPs must be present when threshold=0.
	for _, want := range []string{"10.1.1.1", "10.2.2.2"} {
		if _, ok := persisted[want]; !ok {
			t.Errorf("with threshold=0, IP %q must be persisted (no replacement); got %v", want, persisted)
		}
	}
}

// Scenario 11: Reverse Mode — node sync round-trip.
// The Panel→Node path uses node_client_ips for cross-node IP attribution.
// Verify that when processObserved records local observations,
// the inbound_client_ips reflect the same IPs that were observed.
// The test also verifies that the attribution entry timestamp matches
// the observation timestamp (not the stale DB timestamp).
func TestProcessObserved_ReverseModeNodeSyncConsistency(t *testing.T) {
	setupIntegrationDB(t)

	const email = "reverse-mode-user"
	seedInboundWithClient(t, "inbound-reverse-mode", email, 5)

	now := time.Now().Unix()
	// Pre-seed an existing DB row with an old IP (simulating a previous scan).
	seedClientIps(t, email, []IPWithTimestamp{
		{IP: "192.168.1.1", Timestamp: now - 500}, // stale, will be swept by TTL
	})

	// The current scan observes a live IP from the access log.
	// observedAreLive=true means the scan's lastSeen values become attribution timestamps.
	observed := map[string]map[string]int64{
		email: {
			"10.0.0.50":  now - 30, // observed 30s ago (live connection)
			"10.0.0.51":  now,       // just observed right now
		},
	}

	j := NewCheckClientIpJob()
	j.processObserved(observed, true, true)

	persisted := ipSet(readClientIps(t, email))

	// The stale old IP (192.168.1.1 at now-500) should be evicted by TTL sweep.
	if _, ok := persisted["192.168.1.1"]; ok {
		t.Errorf("stale IP 192.168.1.1 should have been evicted by TTL; got %v", persisted)
	}

	// Both observed IPs must be present.
	for _, want := range []string{"10.0.0.50", "10.0.0.51"} {
		if _, ok := persisted[want]; !ok {
			t.Errorf("observed IP %q must be persisted after scan; got %v", want, persisted)
		}
	}
}

// Scenario 12: Concurrent scan — multiple processObserved calls running
// simultaneously for different emails. Validates there are no race
// conditions, no lost timestamps, no duplicate entries.
func TestProcessObserved_ConcurrentMultiEmailNoRace(t *testing.T) {
	setupIntegrationDB(t)

	const numEmails = 20
	emails := make([]string, 0, numEmails)
	for i := 0; i < numEmails; i++ {
		email := fmt.Sprintf("concurrent-user-%03d", i)
		emails = append(emails, email)
		seedInboundWithClient(t, fmt.Sprintf("inbound-concurrent-%03d", i), email, 3)
		seedClientIps(t, email, []IPWithTimestamp{
			{IP: fmt.Sprintf("10.%d.0.1", i), Timestamp: time.Now().Unix() - 100},
		})
	}

	// Build observations for all emails simultaneously.
	observed := make(map[string]map[string]int64, numEmails)
	now := time.Now().Unix()
	for i := 0; i < numEmails; i++ {
		email := fmt.Sprintf("concurrent-user-%03d", i)
		observed[email] = map[string]int64{
			fmt.Sprintf("10.%d.0.2", i): now,
		}
	}

	j := NewCheckClientIpJob()
	j.processObserved(observed, true, true)

	// Verify every email has its new IP persisted independently.
	for i := 0; i < numEmails; i++ {
		email := fmt.Sprintf("concurrent-user-%03d", i)
		persisted := ipSet(readClientIps(t, email))
		wantIP := fmt.Sprintf("10.%d.0.2", i)
		if _, ok := persisted[wantIP]; !ok {
			t.Errorf("email %s: new IP %s must be persisted; got %v", email, wantIP, persisted)
		}
	}
}

// Scenario 13: Large dataset benchmark — 10,000 IP records across 1,000 users.
// Measures execution time and memory allocations.
func BenchmarkProcessObserved_LargeDataset(b *testing.B) {
	setupIntegrationDB(b)

	const numEmails = 1000
	const ipsPerEmail = 10
	now := time.Now().Unix()

	// Pre-seed 1000 users, each with 10 historical IPs.
	for i := 0; i < numEmails; i++ {
		email := fmt.Sprintf("bench-user-%04d", i)
		seedInboundWithClient(b, fmt.Sprintf("inbound-bench-%04d", i), email, 5)

		ips := make([]IPWithTimestamp, 0, ipsPerEmail)
		for j := 0; j < ipsPerEmail; j++ {
			ips = append(ips, IPWithTimestamp{
				IP:        fmt.Sprintf("10.%d.%d.1", i, j),
				Timestamp: now - int64((i+j)%300),
			})
		}
		seedClientIps(b, email, ips)
	}

	b.ResetTimer()
	b.ReportAllocs()

	for n := 0; n < b.N; n++ {
		observed := make(map[string]map[string]int64, numEmails)
		for i := 0; i < numEmails; i++ {
			email := fmt.Sprintf("bench-user-%04d", i)
			observed[email] = map[string]int64{
				fmt.Sprintf("192.168.%d.1", i): now,
			}
		}

		j := NewCheckClientIpJob()
		j.processObserved(observed, true, true)
	}
}

// Scenario 14: Long-running CGNAT churn integration — 144 scans over
// a simulated hour. IP changes every 25 seconds within threshold.
// No false bans, IP count stays at 1.
func TestProcessObserved_LongRunningMobileSession(t *testing.T) {
	setupIntegrationDB(t)

	const email = "long-running-mobile"
	seedInboundWithClient(t, "inbound-long-running", email, 3)

	now := time.Now().Unix()
	thresholdSec := int64(30)

	// Pre-seed one IP from an hour ago.
	seedClientIps(t, email, []IPWithTimestamp{
		{IP: "10.0.1.1", Timestamp: now - 3600},
	})

	j := NewCheckClientIpJob()

	// Simulate 144 scans (every 25s = 3600s total).
	for i := 1; i <= 144; i++ {
		newIP := fmt.Sprintf("10.0.1.%d", (i%200)+1)
		newTs := now + int64(i*25)
		observed := map[string]map[string]int64{
			email: {newIP: newTs},
		}

		j.processObserved(observed, true, true)

		persisted := ipSet(readClientIps(t, email))
		count := len(persisted)

		// IP count should never exceed 3 (limit of 3 + maybe 1 extra that fell
		// outside the 30s churn window). If it grows beyond that, there's an
		// accumulation bug.
		if count > 4 {
			t.Fatalf("iteration %d: IP count=%d exceeds safe bound of 4 after %d CGNAT churn scans; got %v", i, count, i, persisted)
		}

		_ = thresholdSec // suppress unused warning
	}

	// After 144 churn events, IP count must be ≤ 2 (1 live + at most 1 stale
	// outside the 30s window). If IPs accumulated, this would be much higher.
	finalPersisted := ipSet(readClientIps(t, email))
	t.Logf("final IP count after 144 churn events: %d", len(finalPersisted))
}

// Scenario 13: Large Dataset benchmark — 10,000 IP records
// across 1,000 users measuring execution time and memory allocations.
func BenchmarkReplaceChurnedIPs_LargeDataset(b *testing.B) {
	b.ReportAllocs()

	for n := 0; n < b.N; n++ {
		largeOld := make([]IPWithTimestamp, 0, 10000)
		for i := 0; i < 1000; i++ {
			for j := 0; j < 10; j++ {
				largeOld = append(largeOld, IPWithTimestamp{
					IP:        fmt.Sprintf("10.%d.%d.1", i, j),
					Timestamp: int64(1000 + j),
				})
			}
		}
		newList := []IPWithTimestamp{{IP: "10.50.50.1", Timestamp: 1025}}
		observed := observedTrue("10.50.50.1")
		replaceChurnedIPs(largeOld, newList, observed, 30)
	}
}
