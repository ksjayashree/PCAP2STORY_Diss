import sys, os
sys.path.insert(0, os.path.dirname(__file__))
import multi_catE_batch2 as B
import All_Scenarios as AS
import json

AS.discover_pe_interfaces()
for delay in [60, 120, 300]:
    try:
        B.gen_rd_collision(delay)
    except Exception as e:
        B.RESULTS.append({"name": f"catE_rd_collision_{delay}", "status": "EXCEPTION", "error": str(e)})
print("\n=== RESULTS ===")
print(json.dumps(B.RESULTS, indent=2))
