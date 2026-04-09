"""Quick verification script — tests all 5 scenarios without TF noise."""
import os
os.environ["TF_CPP_MIN_LOG_LEVEL"] = "3"

from simulator import run_all_scenarios

results = run_all_scenarios(use_semantic=False)
blocked = sum(1 for r in results if r["result"]["blocked"])
passed  = len(results) - blocked

print("\n" + "=" * 60)
print("  SENTINELLAYER VERIFICATION SUMMARY")
print("=" * 60)
print(f"  Total scenarios : {len(results)}")
print(f"  BLOCKED         : {blocked}")
print(f"  PASSED          : {passed}")
print()
for r in results:
    res = r["result"]
    status = "BLOCKED" if res["blocked"] else "PASSED "
    conf   = res["confidence_score"]
    lat    = res["latency_ms"]
    nf     = len(res["findings"])
    print(f"  [{status}] {r['name']}")
    print(f"           confidence={conf:.3f}  latency={lat}ms  findings={nf}")
    if res["findings"]:
        for f in res["findings"]:
            print(f"           -> [{f['severity']:8}] {f['detector']:12} {f['threat_type']}")
    print()
