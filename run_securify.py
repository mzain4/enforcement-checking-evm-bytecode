"""Execute the fixed compiler-compatible requests with the pinned Securify API."""
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
import argparse
import hashlib
import json
import subprocess
import sys
import tarfile
import time
import evaluation as e


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--view', choices=['released', 'withdrawal'], required=True)
    parser.add_argument('--python', default=sys.executable, help='Python with pinned Securify 2 dependencies installed')
    parser.add_argument('--output', required=True, help='Fresh run name beneath runs/')
    parser.add_argument('--workers', type=int, default=1)
    args = parser.parse_args()
    out = (e.HERE / 'runs' / args.output).resolve()
    if not out.is_relative_to((e.HERE / 'runs').resolve()) or out.exists():
        parser.error('Choose a new output directory beneath runs/')
    out.mkdir(parents=True)
    protocol = e.read(e.SOURCE / 'securify-preparation/protocol.json')
    requests = [r for r in protocol['requests'] if r['view'] == args.view]
    archive_path = e.SOURCE / 'credential-securify-batch-20261029.tar.gz'
    jobs = []
    with tarfile.open(archive_path) as tar:
        files = {m.name: m for m in tar.getmembers() if m.isfile()}
        roots = [n[:-len('protocol.json')] for n in files if n.endswith('/protocol.json')]
        if len(roots) != 1:
            raise ValueError('Ambiguous request archive')
        for item in requests:
            raw = tar.extractfile(files[roots[0] + item['request_path']]).read()
            assert hashlib.sha256(raw).hexdigest() == item['request_sha256']
            folder = out / item['runtime_sha256']
            folder.mkdir()
            (folder / 'request.json').write_bytes(raw)
            jobs.append((item, folder))
    e.save(out / 'configuration.json', {'method': 'securify2', 'commit': '1913dfe797e512e549d02e97ce8ea467be73d3df',
        'view': args.view, 'outer_cap_seconds': 180, 'requests': requests, 'labels_read': False,
        'native_archive_sha256': e.sha(archive_path), 'python': args.python})
    def execute(job):
        item, folder = job
        start = time.monotonic()
        command = [args.python, '-B', str(e.HERE / 'support/native-tools/run_securify_case.py'),
                   str(folder / 'request.json'), str(folder / 'result.json')]
        run = {**item, 'command': command}
        try:
            proc = subprocess.run(command, capture_output=True, timeout=180)
            (folder / 'stdout.txt').write_bytes(proc.stdout)
            (folder / 'stderr.txt').write_bytes(proc.stderr)
            run['status'] = 'ok' if proc.returncode == 0 else 'error'
            run['returncode'] = proc.returncode
        except subprocess.TimeoutExpired as error:
            run['status'] = 'timeout'
            (folder / 'stdout.txt').write_bytes(error.stdout or b'')
            (folder / 'stderr.txt').write_bytes(error.stderr or b'')
        run['process_seconds'] = time.monotonic() - start
        e.save(folder / 'run.json', run)
        request = e.read(folder / 'request.json')
        result = e.read(folder / 'result.json') if (folder / 'result.json').exists() else None
        decoded = e.decode_native(request, run, result)
        e.save(out / 'runs' / (item['runtime_sha256'] + '.json'), {'runtime_sha256': item['runtime_sha256'], 'result': decoded})
        return run
    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        records = list(pool.map(execute, jobs))
    e.save(out / 'run.json', {'requests': len(records), 'records': records})
    print(json.dumps({'requests': len(records), 'statuses': {s: sum(r['status'] == s for r in records) for s in ['ok', 'timeout', 'error']}}, indent=2))


if __name__ == '__main__':
    main()
