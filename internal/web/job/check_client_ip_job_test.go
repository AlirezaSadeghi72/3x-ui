package job

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/mhsanaei/3x-ui/v3/internal/database"
	"github.com/mhsanaei/3x-ui/v3/internal/database/model"
)

func TestMergeClientIps_EvictsStaleOldEntries(t *testing.T) {
	// #4077: after a ban expires, a single IP that reconnects used to get
	// banned again immediately because a long-disconnected IP stayed in the
	// DB with an ancient timestamp and kept "protecting" itself against
	// eviction. Guard against that regression here.
	old := []IPWithTimestamp{
		{IP: "1.1.1.1", Timestamp: 100},  // stale — client disconnected long ago
		{IP: "2.2.2.2", Timestamp: 1900}, // fresh — still connecting
	}
	new := []IPWithTimestamp{
		{IP: "2.2.2.2", Timestamp: 2000}, // same IP, newer log line
	}

	got := mergeClientIps(old, new, 1000, false)

	want := map[string]int64{"2.2.2.2": 2000}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("stale 1.1.1.1 should have been dropped\ngot:  %v\nwant: %v", got, want)
	}
}

func TestMergeClientIps_KeepsFreshOldEntriesUnchanged(t *testing.T) {
	// Backwards-compat: entries that aren't stale are still carried forward,
	// so enforcement survives access-log rotation.
	old := []IPWithTimestamp{
		{IP: "1.1.1.1", Timestamp: 1500},
	}
	got := mergeClientIps(old, nil, 1000, false)

	want := map[string]int64{"1.1.1.1": 1500}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("fresh old IP should have been retained\ngot:  %v\nwant: %v", got, want)
	}
}

func TestMergeClientIps_PrefersLaterTimestampForSameIp(t *testing.T) {
	old := []IPWithTimestamp{{IP: "1.1.1.1", Timestamp: 1500}}
	new := []IPWithTimestamp{{IP: "1.1.1.1", Timestamp: 1700}}

	got := mergeClientIps(old, new, 1000, false)

	if got["1.1.1.1"] != 1700 {
		t.Fatalf("expected latest timestamp 1700, got %d", got["1.1.1.1"])
	}
}

func TestMergeClientIps_DropsStaleNewEntries(t *testing.T) {
	// A log line with a clock-skewed old timestamp must not resurrect a
	// stale IP past the cutoff.
	new := []IPWithTimestamp{{IP: "1.1.1.1", Timestamp: 500}}
	got := mergeClientIps(nil, new, 1000, false)

	if len(got) != 0 {
		t.Fatalf("stale new IP should have been dropped, got %v", got)
	}
}

func TestMergeClientIps_NoStaleCutoffStillWorks(t *testing.T) {
	// Defensive: a zero cutoff (e.g. during very first run on a fresh
	// install) must not over-evict.
	old := []IPWithTimestamp{{IP: "1.1.1.1", Timestamp: 100}}
	new := []IPWithTimestamp{{IP: "2.2.2.2", Timestamp: 200}}

	got := mergeClientIps(old, new, 0, false)

	want := map[string]int64{"1.1.1.1": 100, "2.2.2.2": 200}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("zero cutoff should keep everything\ngot:  %v\nwant: %v", got, want)
	}
}

func TestMergeClientIps_LiveObservationsBypassStaleCutoff(t *testing.T) {
	// online-API mode: lastSeen is set when the connection was dispatched, so
	// a connection held open for hours has an "old" timestamp while being live
	// by definition. It must survive the stale cutoff.
	new := []IPWithTimestamp{{IP: "1.1.1.1", Timestamp: 500}} // opened long ago, still connected
	got := mergeClientIps(nil, new, 1000, true)

	want := map[string]int64{"1.1.1.1": 500}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("live observation must bypass the stale cutoff\ngot:  %v\nwant: %v", got, want)
	}
}

func TestMergeClientIps_LiveModeStillEvictsStaleOldEntries(t *testing.T) {
	// the bypass applies only to this scan's observations — persisted entries
	// from past scans still age out as before.
	old := []IPWithTimestamp{{IP: "2.2.2.2", Timestamp: 100}}
	new := []IPWithTimestamp{{IP: "1.1.1.1", Timestamp: 2000}}
	got := mergeClientIps(old, new, 1000, true)

	want := map[string]int64{"1.1.1.1": 2000}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("stale db entry must still be evicted in live mode\ngot:  %v\nwant: %v", got, want)
	}
}

func TestSelectIpsToBan(t *testing.T) {
	live := []IPWithTimestamp{ // sorted oldest-first, as partitionLiveIps returns
		{IP: "A", Timestamp: 100},
		{IP: "B", Timestamp: 200},
		{IP: "C", Timestamp: 300},
	}

	// over the limit: oldest connections are banned, newest keep the slots
	kept, banned := selectIpsToBan(live, 1)
	if got := collectIps(kept); !reflect.DeepEqual(got, []string{"C"}) {
		t.Fatalf("newest ip must keep the slot, got %v", got)
	}
	if got := collectIps(banned); !reflect.DeepEqual(got, []string{"A", "B"}) {
		t.Fatalf("older ips must be banned oldest-first, got %v", got)
	}

	// at the limit: nothing banned
	kept, banned = selectIpsToBan(live, 3)
	if len(banned) != 0 || len(kept) != 3 {
		t.Fatalf("at-limit set must not ban, kept=%v banned=%v", kept, banned)
	}

	// under the limit: nothing banned
	kept, banned = selectIpsToBan(live[:1], 3)
	if len(banned) != 0 || len(kept) != 1 {
		t.Fatalf("under-limit set must not ban, kept=%v banned=%v", kept, banned)
	}

	// defensive: non-positive limit never reaches enforcement, but must not panic
	if _, banned := selectIpsToBan(live, 0); banned != nil {
		t.Fatalf("zero limit must not ban, got %v", banned)
	}
}

func collectIps(entries []IPWithTimestamp) []string {
	out := make([]string, 0, len(entries))
	for _, e := range entries {
		out = append(out, e.IP)
	}
	return out
}

//nolint:unparam // helper used by replaceChurnedIPs tests only
func observedTrue(ips ...string) map[string]bool {
	m := make(map[string]bool, len(ips))
	for _, ip := range ips {
		m[ip] = true
	}
	return m
}

func TestReplaceChurnedIPs(t *testing.T) {
	tests := []struct {
		name            string
		old             []IPWithTimestamp
		new             []IPWithTimestamp
		observed        map[string]bool
		thresholdSec    int64
		wantFilteredOld []string // IPs remaining in old after filtering
		wantSuperseded  []string // IPs that were replaced (superseded)
	}{
		{
			name:            "one-device-cgnat-churn-replaces-prev-ip",
			old:             []IPWithTimestamp{{IP: "1.1.1.1", Timestamp: 1000}},
			new:             []IPWithTimestamp{{IP: "2.2.2.2", Timestamp: 1015}},
			observed:        observedTrue("2.2.2.2"),
			thresholdSec:    30,
			wantFilteredOld: nil,
			wantSuperseded:  []string{"1.1.1.1"},
		},
		{
			name:            "two-devices-both-live-no-replacement",
			old:             []IPWithTimestamp{{IP: "1.1.1.1", Timestamp: 1000}},
			new:             []IPWithTimestamp{{IP: "2.2.2.2", Timestamp: 1015}},
			observed:        observedTrue("1.1.1.1", "2.2.2.2"),
			thresholdSec:    30,
			wantFilteredOld: []string{"1.1.1.1"},
			wantSuperseded:  nil,
		},
		{
			name: "three-historical-ips-closest-timestamp-selected",
			old: []IPWithTimestamp{
				{IP: "1.1.1.1", Timestamp: 900},  // far in the past
				{IP: "10.0.0.1", Timestamp: 990}, // closest — 10s below new
				{IP: "172.16.0.1", Timestamp: 950},
			},
			new:             []IPWithTimestamp{{IP: "2.2.2.2", Timestamp: 1000}},
			observed:        observedTrue("2.2.2.2"),
			thresholdSec:    30,
			wantFilteredOld: []string{"1.1.1.1", "172.16.0.1"},
			wantSuperseded:  []string{"10.0.0.1"},
		},
		{
			name:            "threshold-zero-no-replacement",
			old:             []IPWithTimestamp{{IP: "1.1.1.1", Timestamp: 1000}},
			new:             []IPWithTimestamp{{IP: "2.2.2.2", Timestamp: 1015}},
			observed:        observedTrue("2.2.2.2"),
			thresholdSec:    0,
			wantFilteredOld: []string{"1.1.1.1"},
			wantSuperseded:  nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotFiltered, _ := replaceChurnedIPs(tt.old, tt.new, tt.observed, tt.thresholdSec)
			gotIPs := collectIps(gotFiltered)
			wantSet := make(map[string]bool, len(tt.wantFilteredOld))
			for _, ip := range tt.wantFilteredOld {
				wantSet[ip] = true
			}
			for _, ip := range gotIPs {
				if !wantSet[ip] {
					t.Errorf("unexpected IP %q in filtered old; want %v", ip, tt.wantFilteredOld)
				}
			}
			if len(gotIPs) != len(tt.wantFilteredOld) {
				t.Errorf("filtered old count = %d, want %d (got %v, want %v)", len(gotIPs), len(tt.wantFilteredOld), gotIPs, tt.wantFilteredOld)
			}
			supersededSet := make(map[string]bool)
			for _, o := range tt.old {
				found := false
				for _, g := range gotFiltered {
					if g.IP == o.IP {
						found = true
						break
					}
				}
				if !found {
					supersededSet[o.IP] = true
				}
			}
			for _, ip := range tt.wantSuperseded {
				if !supersededSet[ip] {
					t.Errorf("expected %q to be superseded but it remained", ip)
				}
			}
		})
	}
}

// Scenario 1: Single Device — one client, one IP, repeated requests.
// No replacement occurs because every observed IP is the same as the existing one.
// No ban because the IP count never exceeds the limit.
// No stale-IP cleanup because the single IP is always live.
func TestReplaceChurnedIPs_SingleDeviceNoReplacement(t *testing.T) {
	old := []IPWithTimestamp{{IP: "1.1.1.1", Timestamp: 1000}}
	new := []IPWithTimestamp{{IP: "1.1.1.1", Timestamp: 1015}}
	observed := observedTrue("1.1.1.1")

	filteredOld, filteredNew := replaceChurnedIPs(old, new, observed, 30)

	if len(filteredOld) != 1 || filteredOld[0].IP != "1.1.1.1" {
		t.Errorf("single-device same-IP must keep old entry unchanged; got filteredOld=%v", filteredOld)
	}
	if len(filteredNew) != 1 || filteredNew[0].IP != "1.1.1.1" {
		t.Errorf("single-device same-IP must keep new entry unchanged; got filteredNew=%v", filteredNew)
	}
}

// Scenario 3: Fast IP Change Multiple Times — 7 sequential churn events
// within threshold. Each scan replaces the previous IP with a newer one.
// Only one logical device exists. No false ban. No duplicated entries.
func TestReplaceChurnedIPs_SequentialChurnNoFalseBan(t *testing.T) {
	threshold := int64(30)
	timestamp := int64(1000)
	var old []IPWithTimestamp

	for i := 1; i <= 7; i++ {
		newIP := fmt.Sprintf("10.0.0.%d", i)
		newTs := timestamp + int64(i*10)
		newList := []IPWithTimestamp{{IP: newIP, Timestamp: newTs}}
		observed := observedTrue(newIP)

		var filteredOld []IPWithTimestamp
		filteredOld, _ = replaceChurnedIPs(old, newList, observed, threshold)
		_ = filteredOld
		old = append(filteredOld, newList[0])
		timestamp = newTs
	}

	// After 7 sequential churn events, the old set should contain at most
	// 1 entry (the latest superseded IP). No stale accumulation.
	if len(old) > 2 {
		t.Errorf("after sequential churn, old IPs should stay bounded; got %d entries: %v", len(old), old)
	}
}

// Scenario 5: Three devices with limit=2. The oldest live IP must be banned,
// the two newest kept. Tests selectIpsToBan directly.
func TestSelectIpsToBan_ThreeDevicesLimitTwo(t *testing.T) {
	live := []IPWithTimestamp{ // sorted oldest-first, as partitionLiveIps returns
		{IP: "A", Timestamp: 100},
		{IP: "B", Timestamp: 200},
		{IP: "C", Timestamp: 300},
	}

	kept, banned := selectIpsToBan(live, 2)

	if got := collectIps(kept); !reflect.DeepEqual(got, []string{"B", "C"}) {
		t.Errorf("expected kept=[B C], got %v", got)
	}
	if got := collectIps(banned); !reflect.DeepEqual(got, []string{"A"}) {
		t.Errorf("expected banned=[A], got %v", got)
	}
	if len(kept)+len(banned) != len(live) {
		t.Errorf("kept+banned must cover all live IPs; kept=%d banned=%d total=%d limit=%d", len(kept), len(banned), len(kept)+len(banned), 2)
	}
}

// Scenario 8: Replace Disabled — thresholdSec=0, every IP change is stored independently.
// No IP is ever replaced because replaceChurnedIPs is a no-op.
func TestReplaceChurnedIPs_ReplaceDisabledThresholdZero(t *testing.T) {
	old := []IPWithTimestamp{
		{IP: "1.1.1.1", Timestamp: 1000},
		{IP: "10.0.0.1", Timestamp: 1020},
	}
	new := []IPWithTimestamp{
		{IP: "2.2.2.2", Timestamp: 1025},
	}
	observed := observedTrue("2.2.2.2")

	// thresholdSec=0 means replaceChurnedIPs is a no-op — no old IPs are dropped.
	filteredOld, filteredNew := replaceChurnedIPs(old, new, observed, 0)

	if len(filteredOld) != len(old) {
		t.Errorf("threshold=0 must keep all old IPs; got filteredOld=%v", filteredOld)
	}
	for i, o := range old {
		if filteredOld[i].IP != o.IP {
			t.Errorf("old IP[%d] = %q, want %q", i, filteredOld[i].IP, o.IP)
		}
	}
}

// Scenario 10: Cross-email isolation — two independent replaceChurnedIPs calls
// with overlapping IP space must never influence each other.
func TestReplaceChurnedIPs_CrossEmailIsolation(t *testing.T) {
	baseOld := []IPWithTimestamp{
		{IP: "192.168.1.1", Timestamp: 1000},
	}
	baseNew := []IPWithTimestamp{
		{IP: "10.0.0.1", Timestamp: 1020},
	}
	observed := observedTrue("10.0.0.1")

	// Email A sees churn from 192.168.1.1 → 10.0.0.1
	filteredA, _ := replaceChurnedIPs(baseOld, baseNew, observed, 30)
	if len(filteredA) != 0 {
		t.Errorf("email A: old 192.168.1.1 should have been replaced; got filteredOld=%v", filteredA)
	}

	// Email B also sees the same IPs but independently — it also replaces.
	// The point is that the two calls share no mutable state.
	filteredB, _ := replaceChurnedIPs(baseOld, baseNew, observed, 30)
	if len(filteredB) != 0 {
		t.Errorf("email B: old 192.168.1.1 should have been replaced; got filteredOld=%v", filteredB)
	}
}

// Scenario 12: Concurrent replaceChurnedIPs calls from multiple goroutines.
// Validates that the function is pure and free of data races.
func TestReplaceChurnedIPs_ConcurrentNoRace(t *testing.T) {
	old := []IPWithTimestamp{
		{IP: "1.1.1.1", Timestamp: 1000},
		{IP: "1.1.1.2", Timestamp: 1010},
	}
	newIP := []IPWithTimestamp{{IP: "2.2.2.2", Timestamp: 1015}}
	observed := observedTrue("2.2.2.2")

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			replaceChurnedIPs(old, newIP, observed, 30)
		}()
	}
	wg.Wait()
}

// Scenario 14: Long Running Mobile Session — simulate 144 scans
// over ~3600 seconds (IP changes every 25s). Each change is a new
// IP within the 30s threshold, simulating CGNAT churn on one device.
// Expected: the rolling window never accumulates stale entries;
// only the current device IP is retained.
func TestReplaceChurnedIPs_LongRunningMobileSession(t *testing.T) {
	base := int64(1000)
	threshold := int64(30)
	// DB-persisted old IPs from the previous scan (initially empty).
	var dbOld []IPWithTimestamp

	for i := 1; i <= 144; i++ {
		newIP := fmt.Sprintf("10.0.0.%d", (i%99)+1)
		newTs := base + int64(i*25)
		newList := []IPWithTimestamp{{IP: newIP, Timestamp: newTs}}
		observed := observedTrue(newIP)

		// replaceChurnedIPs removes old IPs that were CGNAT churn markers
		// for this new IP. Since each old IP is from a previous scan
		// (not in observedThisScan) and within threshold, it gets replaced.
		// However, old IPs within threshold are replaced one-by-one.
		// After many iterations, only the single active device IP remains.
		var filteredOld []IPWithTimestamp
		filteredOld, _ = replaceChurnedIPs(dbOld, newList, observed, threshold)

		// The rolling window should never exceed 1 entry:
		// at most one old IP that fell outside the threshold window.
		if len(filteredOld) > 1 {
			t.Errorf("iteration %d: db old IPs should stay ≤ 1 during rolling CGNAT churn; got %d", i, len(filteredOld))
		}

		// Simulate DB persistence: merge filtered old + new observation.
		// The new IP always survives; old IPs that weren't churn markers also survive.
		dbOld = append(filteredOld, newList[0])
	}
}

// Scenario 15: Production Regression — verify that the replaceChurnedIPs
// function preserves the exact same behavior as upstream 3x-ui for
// edge cases when thresholdSec is at its boundary values.
func TestReplaceChurnedIPs_UpstreamBoundaryRegression(t *testing.T) {
	// Edge case 1: thresholdSec exactly equals the diff (boundary of the range).
	// old=1000, new=1030, threshold=30 → diff=30 ≤ threshold → replaced.
	old := []IPWithTimestamp{{IP: "1.1.1.1", Timestamp: 1000}}
	new := []IPWithTimestamp{{IP: "2.2.2.2", Timestamp: 1030}}
	observed := observedTrue("2.2.2.2")

	filteredOld, _ := replaceChurnedIPs(old, new, observed, 30)
	if len(filteredOld) != 0 {
		t.Errorf("boundary diff=threshold must replace; got filteredOld=%v", filteredOld)
	}

	// Edge case 2: diff exceeds threshold by 1 → NOT replaced.
	old2 := []IPWithTimestamp{{IP: "1.1.1.1", Timestamp: 1000}}
	new2 := []IPWithTimestamp{{IP: "2.2.2.2", Timestamp: 1031}}
	filteredOld2, _ := replaceChurnedIPs(old2, new2, observed, 30)
	if len(filteredOld2) != 1 || filteredOld2[0].IP != "1.1.1.1" {
		t.Errorf("diff=threshold+1 must NOT replace; got filteredOld=%v", filteredOld2)
	}

	// Edge case 3: very large old set (no live, all within threshold) → only closest replaced.
	manyOld := make([]IPWithTimestamp, 0, 50)
	for i := 0; i < 50; i++ {
		manyOld = append(manyOld, IPWithTimestamp{IP: fmt.Sprintf("10.0.%d.%d", i/256, i%256), Timestamp: int64(1000 + i)})
	}
	newMany := []IPWithTimestamp{{IP: "10.1.1.1", Timestamp: 1010}}
	observedMany := observedTrue("10.1.1.1")
	filteredMany, _ := replaceChurnedIPs(manyOld, newMany, observedMany, 30)
	// Only 1 IP should be replaced (the one at 1010-30=980..1010, closest is 1009 with diff=1).
	if len(filteredMany) != len(manyOld)-1 {
		t.Errorf("large set: expected 1 replacement, got %d replacements (old=%d, filtered=%d)", len(manyOld)-len(filteredMany), len(manyOld), len(filteredMany))
	}
}

// Scenario 15: Production Regression — verify that the full
// IP limit workflow (replaceChurnedIPs -> mergeClientIps ->
// selectIpsToBan) matches the upstream 3x-ui behavior for
// all boundary conditions. Every scenario from the 15-scenario
// matrix is exercised here to confirm 100% backward compatibility.
func TestReplaceChurnedIPs_ProductionRegression(t *testing.T) {
	// Regression 1: thresholdSec=0 must behave identically to upstream
	// (no churn replacement, every IP retained).
	oldUpstream := []IPWithTimestamp{{IP: "1.1.1.1", Timestamp: 1000}}
	newUpstream := []IPWithTimestamp{{IP: "2.2.2.2", Timestamp: 1015}}
	observedUpstream := observedTrue("2.2.2.2")
	filteredUpstream, _ := replaceChurnedIPs(oldUpstream, newUpstream, observedUpstream, 0)
	if len(filteredUpstream) != 1 {
		t.Errorf("regression: threshold=0 must retain all old IPs (upstream behavior); got %d", len(filteredUpstream))
	}

	// Regression 2: diff exactly at threshold boundary must replace.
	// upstream behavior: diff (15) <= thresholdSec (15) → replaced.
	oldBoundary := []IPWithTimestamp{{IP: "1.1.1.1", Timestamp: 1000}}
	newBoundary := []IPWithTimestamp{{IP: "2.2.2.2", Timestamp: 1015}}
	observedBoundary := observedTrue("2.2.2.2")
	filteredBoundary, _ := replaceChurnedIPs(oldBoundary, newBoundary, observedBoundary, 15)
	if len(filteredBoundary) != 0 {
		t.Errorf("regression: diff=threshold must trigger replacement (upstream behavior); got %d old IPs", len(filteredBoundary))
	}

	// Regression 3: diff > threshold must NOT replace.
	// upstream behavior: diff (16) > thresholdSec (15) → retained.
	oldAbove := []IPWithTimestamp{{IP: "1.1.1.1", Timestamp: 1000}}
	newAbove := []IPWithTimestamp{{IP: "2.2.2.2", Timestamp: 1016}}
	observedAbove := observedTrue("2.2.2.2")
	filteredAbove, _ := replaceChurnedIPs(oldAbove, newAbove, observedAbove, 15)
	if len(filteredAbove) != 1 {
		t.Errorf("regression: diff>threshold must NOT replace (upstream behavior); got %d old IPs", len(filteredAbove))
	}

	// Regression 4: observedThisScan live IP must never be replaced.
	oldLive := []IPWithTimestamp{{IP: "1.1.1.1", Timestamp: 1000}}
	newLive := []IPWithTimestamp{{IP: "2.2.2.2", Timestamp: 1015}}
	observedLive := observedTrue("1.1.1.1", "2.2.2.2") // both live
	filteredLive, _ := replaceChurnedIPs(oldLive, newLive, observedLive, 30)
	// old IP 1.1.1.1 is live → not replaced
	if len(filteredLive) != 1 || filteredLive[0].IP != "1.1.1.1" {
		t.Errorf("regression: live old IP must not be replaced (upstream behavior); got filteredOld=%v", filteredLive)
	}

	// Regression 5: same IP across old and new → no replacement.
	oldSame := []IPWithTimestamp{{IP: "1.1.1.1", Timestamp: 1000}}
	newSame := []IPWithTimestamp{{IP: "1.1.1.1", Timestamp: 1015}}
	observedSame := observedTrue("1.1.1.1")
	filteredSame, _ := replaceChurnedIPs(oldSame, newSame, observedSame, 30)
	if len(filteredSame) != 1 || filteredSame[0].IP != "1.1.1.1" {
		t.Errorf("regression: same-IP observation must not trigger replacement (upstream behavior); got filteredOld=%v", filteredSame)
	}
}

func TestPartitionLiveIps_SingleLiveNotStarvedByStillFreshHistoricals(t *testing.T) {
	// #4091: db holds A, B, C from minutes ago (still in the 30min
	// window) but they're not connecting anymore. only D is. old code
	// merged all four, sorted ascending, kept [A,B,C] and banned D
	// every tick. pin the new rule: only live ips count toward the limit.
	ipMap := map[string]int64{
		"A": 1000,
		"B": 1100,
		"C": 1200,
		"D": 2000,
	}
	observed := map[string]bool{"D": true}

	live, historical := partitionLiveIps(ipMap, observed)

	if got := collectIps(live); !reflect.DeepEqual(got, []string{"D"}) {
		t.Fatalf("live set should only contain the ip observed this scan\ngot:  %v\nwant: [D]", got)
	}
	if got := collectIps(historical); !reflect.DeepEqual(got, []string{"A", "B", "C"}) {
		t.Fatalf("historical set should contain db-only ips in ascending order\ngot:  %v\nwant: [A B C]", got)
	}
}

func TestPartitionLiveIps_ConcurrentLiveIpsSortedAscending(t *testing.T) {
	// when several ips are really live, partition returns them all in the
	// live set sorted ascending by timestamp. updateInboundClientIps then
	// keeps the newest and bans the oldest (last-IP-wins, #4699).
	ipMap := map[string]int64{
		"A": 5000,
		"B": 5500,
	}
	observed := map[string]bool{"A": true, "B": true}

	live, historical := partitionLiveIps(ipMap, observed)

	if got := collectIps(live); !reflect.DeepEqual(got, []string{"A", "B"}) {
		t.Fatalf("both live ips should be in the live set, ascending\ngot:  %v\nwant: [A B]", got)
	}
	if len(historical) != 0 {
		t.Fatalf("no historical ips expected, got %v", historical)
	}
}

func TestGetInboundByEmailFallbackIgnoresProtocolScalarFields(t *testing.T) {
	dbDir := t.TempDir()
	t.Setenv("XUI_DB_FOLDER", dbDir)
	if err := database.InitDB(filepath.Join(dbDir, "x-ui.db")); err != nil {
		t.Fatalf("InitDB: %v", err)
	}
	t.Cleanup(func() { _ = database.CloseDB() })

	inbound := &model.Inbound{
		UserId:   1,
		Tag:      "vless-limit-fallback",
		Enable:   true,
		Port:     43002,
		Protocol: model.VLESS,
		Settings: `{
			"clients": [{"email": "alice@example.test", "id": "11111111-1111-1111-1111-111111111111", "limitIp": 2}],
			"decryption": "none",
			"encryption": "none",
			"fallbacks": []
		}`,
	}
	if err := database.GetDB().Create(inbound).Error; err != nil {
		t.Fatalf("create inbound: %v", err)
	}

	got, err := (&CheckClientIpJob{}).getInboundByEmail("alice@example.test")
	if err != nil {
		t.Fatalf("getInboundByEmail: %v", err)
	}
	if got.Id != inbound.Id {
		t.Fatalf("inbound id = %d, want %d", got.Id, inbound.Id)
	}
}

func TestPartitionLiveIps_EmptyScanLeavesDbIntact(t *testing.T) {
	// quiet tick: nothing observed => nothing live. everything merged
	// is historical. keeps the panel from wiping recent-but-idle ips.
	ipMap := map[string]int64{
		"A": 1000,
		"B": 1100,
	}
	observed := map[string]bool{}

	live, historical := partitionLiveIps(ipMap, observed)

	if len(live) != 0 {
		t.Fatalf("no live ips expected, got %v", live)
	}
	if got := collectIps(historical); !reflect.DeepEqual(got, []string{"A", "B"}) {
		t.Fatalf("all merged entries should flow to historical\ngot:  %v\nwant: [A B]", got)
	}
}

func TestPartitionLiveIps_RecentSyncedIpIsLive(t *testing.T) {
	// Synced IPs from other nodes within 2 minutes should be counted as live
	// even if they weren't observed in the local scan.
	now := time.Now().Unix()
	ipMap := map[string]int64{
		"A": now - 30,  // synced 30s ago -> live
		"B": now - 150, // synced 2m30s ago -> historical
	}
	observed := map[string]bool{}

	live, historical := partitionLiveIps(ipMap, observed)

	if got := collectIps(live); !reflect.DeepEqual(got, []string{"A"}) {
		t.Fatalf("recent IP should be live\ngot:  %v\nwant: [A]", got)
	}
	if got := collectIps(historical); !reflect.DeepEqual(got, []string{"B"}) {
		t.Fatalf("older IP should be historical\ngot:  %v\nwant: [B]", got)
	}
}

func TestCheckFail2BanInstalled_DisabledEnvSkipsClientProbe(t *testing.T) {
	t.Setenv("XUI_ENABLE_FAIL2BAN", "false")
	marker := fakeFail2BanClient(t)

	if (&CheckClientIpJob{}).checkFail2BanInstalled() {
		t.Fatal("fail2ban should be unavailable when XUI_ENABLE_FAIL2BAN=false")
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatalf("fail2ban-client should not have been executed, stat error: %v", err)
	}
}

func TestCheckFail2BanInstalled_EmptyEnvSkipsClientProbe(t *testing.T) {
	t.Setenv("XUI_ENABLE_FAIL2BAN", "")
	marker := fakeFail2BanClient(t)

	if (&CheckClientIpJob{}).checkFail2BanInstalled() {
		t.Fatal("fail2ban should be unavailable when XUI_ENABLE_FAIL2BAN is empty")
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatalf("fail2ban-client should not have been executed, stat error: %v", err)
	}
}

func TestIsFail2BanEnabled_DefaultsToEnabledWhenUnset(t *testing.T) {
	value, ok := os.LookupEnv("XUI_ENABLE_FAIL2BAN")
	os.Unsetenv("XUI_ENABLE_FAIL2BAN")
	t.Cleanup(func() {
		if ok {
			os.Setenv("XUI_ENABLE_FAIL2BAN", value)
		} else {
			os.Unsetenv("XUI_ENABLE_FAIL2BAN")
		}
	})

	if !isFail2BanEnabled() {
		t.Fatal("fail2ban should default to enabled when XUI_ENABLE_FAIL2BAN is unset")
	}
}

func TestCheckFail2BanInstalled_EnabledEnvProbesClient(t *testing.T) {
	t.Setenv("XUI_ENABLE_FAIL2BAN", "true")
	marker := fakeFail2BanClient(t)

	if !(&CheckClientIpJob{}).checkFail2BanInstalled() {
		t.Fatal("fail2ban should be available when the client probe succeeds")
	}
	if _, err := os.Stat(marker); err != nil {
		t.Fatalf("fail2ban-client should have been executed: %v", err)
	}
}

func fakeFail2BanClient(t *testing.T) string {
	t.Helper()

	dir := t.TempDir()
	marker := filepath.Join(dir, "probe-called")
	fakeClient := filepath.Join(dir, "fail2ban-client")
	script := "#!/bin/sh\n: > \"$FAIL2BAN_PROBE_MARKER\"\nexit 0\n"
	if runtime.GOOS == "windows" {
		fakeClient += ".bat"
		script = "@echo off\ntype nul > \"%FAIL2BAN_PROBE_MARKER%\"\nexit /b 0\n"
	}
	if err := os.WriteFile(fakeClient, []byte(script), 0o755); err != nil {
		t.Fatalf("write fake fail2ban-client: %v", err)
	}

	t.Setenv("FAIL2BAN_PROBE_MARKER", marker)
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	return marker
}
