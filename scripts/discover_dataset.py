from pathlib import Path
import os
root=Path(os.getenv('HHGOA_DATA_DIR','data/HHGOA_IEEE'))
print(f'HHGOA_IEEE root: {root.resolve()}')
if not root.exists():
    print('DATASET NOT FOUND. Copy the supplied HHGOA_IEEE directory here or set HHGOA_DATA_DIR.')
    raise SystemExit(0)
for p in sorted(root.rglob('*')):
    if p.is_file(): print(p.relative_to(root))
print('\nREADME candidates:')
for p in root.rglob('*'):
    if p.is_file() and 'readme' in p.name.lower(): print(p)
