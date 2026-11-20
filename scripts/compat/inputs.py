"""Shared bounded input validation for native and software guest workloads."""
from pathlib import Path
import stat


def seed_files(values):
    """Bound local regular-file inputs before reading them or starting a VM."""
    files, destinations, total = [], set(), 0
    for source, destination in values:
        source = Path(source).resolve(strict=True)
        info = source.stat()
        if not stat.S_ISREG(info.st_mode) or info.st_size > 256 * 1024 * 1024:
            raise ValueError(f'seed must be a regular file of at most 256 MiB: {source}')
        path = Path(destination)
        if not destination.startswith('/nested-input/') or '..' in path.parts or destination.endswith('/'):
            raise ValueError('seed destination must be a file beneath /nested-input/')
        destination = str(path)
        if destination in destinations:
            raise ValueError(f'duplicate seed destination: {destination}')
        destinations.add(destination)
        total += info.st_size
        if total > 512 * 1024 * 1024:
            raise ValueError('combined seed inputs exceed 512 MiB')
        files.append((source, destination))
    return files

