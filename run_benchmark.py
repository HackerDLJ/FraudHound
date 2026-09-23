from backend.main import controller
from backend.benchmark.runner import run_benchmark
import json
from pathlib import Path
out=Path('outputs'); out.mkdir(exist_ok=True)
result=run_benchmark(controller)
(out/'benchmark_summary.json').write_text(json.dumps(result,indent=2),encoding='utf-8')
print(json.dumps(result,indent=2))
