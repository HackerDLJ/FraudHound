from __future__ import annotations
import json, os
from pathlib import Path
from backend.models.schemas import InvestigationRequest

def discover_benchmark_files(root: Path):
    exts={'.json','.csv','.parquet'}
    return [p for p in root.rglob('*') if p.is_file() and p.suffix.lower() in exts and ('benchmark' in p.name.lower() or 'case' in p.name.lower())]

def run_benchmark(controller):
    root=Path(os.getenv('HHGOA_DATA_DIR','data/HHGOA_IEEE'))
    files=discover_benchmark_files(root) if root.exists() else []
    if not files:
        return {'status':'DATASET_NOT_FOUND','message':f'Place HHGOA_IEEE under {root} or set HHGOA_DATA_DIR. No benchmark labels were fabricated.','files_found':0}
    # Discovery only. Actual field mapping is dataset-specific and must be driven by README/schema inspection.
    return {'status':'DISCOVERED','files_found':len(files),'files':[str(p) for p in files[:50]],'message':'Benchmark source files discovered. Map the exact HHGOA_IEEE benchmark schema before executing cases; hidden labels are not used.'}
