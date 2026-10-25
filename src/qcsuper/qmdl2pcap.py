#!/usr/bin/env python3
"""Convert Qualcomm DIAG .qmdl (or .qmdl.gz) logs to PCAP (GSMTAP) using qcsuper.

Examples:
    qmdl2pcap.py diag_log.qmdl.gz                  # -> diag_log.pcap next to input
    qmdl2pcap.py diag_log.qmdl.gz -o out.pcap
    qmdl2pcap.py -l verizon.files -d pcaps/        # file of filenames, one per line
    qmdl2pcap.py -l verizon.files -d pcaps/ -j 4   # 4 conversions at a time
"""
import logging
import os
import sys
from argparse import ArgumentParser
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path

from .inputs.qmdl_read import QmdlReader
from .modules._utils import FileType
from .modules.pcap_dump import PcapDumper

log = logging.getLogger('qmdl2pcap')


class _QmdlReader(QmdlReader):
    """QmdlReader that records read errors (qcsuper only logs them)."""

    read_error = None

    def read_loop(self):
        try:
            super().read_loop()
        except Exception as e:
            self.read_error = e
            raise


def read_list_file(path):
    lines = sys.stdin if path == '-' else open(path)
    with lines:
        for line in lines:
            line = line.strip()
            if line and not line.startswith('#'):
                yield Path(line)


def default_output_name(src):
    name = src.name
    if name.endswith('.gz'):
        name = name[:-3]
    if name.endswith('.qmdl'):
        name = name[:-5]
    return name + '.pcap'


def convert(src, dst, reassemble_sibs, decrypt_nas, include_ip_traffic):
    qmdl_file = FileType('rb')(str(src))  # transparently gunzips *.gz
    pcap_file = open(dst, 'wb')
    pcap_file.appending_to_file = False  # always write a fresh PCAP header
    try:
        diag_input = _QmdlReader(qmdl_file)
        diag_input.add_module(
            PcapDumper(
                diag_input,
                pcap_file,
                reassemble_sibs,
                decrypt_nas,
                include_ip_traffic,
            )
        )
        try:
            diag_input.run()
        finally:
            diag_input.dispose()
        if diag_input.read_error:
            raise diag_input.read_error
    finally:
        pcap_file.close()
        qmdl_file.close()


LOG_FORMAT = '[%(asctime)s | %(levelname)s @ %(filename)s:%(lineno)d ] %(message)s'


def setup_logging(verbose):
    logging.basicConfig(
        stream=sys.stderr,
        level=logging.DEBUG if verbose else logging.INFO,
        format=LOG_FORMAT,
        datefmt='%H:%M:%S',
        force=True,
    )


def convert_one(prefix, src, dst, pcap_opts):
    """Convert one file, logging the outcome. Returns True on success."""
    log.info('%s -> %s', prefix, dst)
    try:
        convert(src, dst, *pcap_opts)
    except Exception:
        log.exception('%s: conversion failed', prefix)
        dst.unlink(missing_ok=True)
        return False
    log.info('%s: done', prefix)
    return True


def main():
    parser = ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument('inputs', nargs='*', type=Path, help='.qmdl / .qmdl.gz files')
    parser.add_argument(
        '-l', '--list', action='append', default=[], metavar='LIST_FILE',
        help='file containing input filenames, one per line ("-" for stdin); may be repeated',
    )
    out = parser.add_mutually_exclusive_group()
    out.add_argument('-o', '--output', type=Path, help='output path (single input only)')
    out.add_argument('-d', '--out-dir', type=Path, help='directory for output files')
    parser.add_argument('-f', '--force', action='store_true', help='overwrite existing outputs')
    parser.add_argument('-j', '--jobs', type=int, default=1,
                        help='number of concurrent conversions (default: 1, 0 = one per CPU)')
    parser.add_argument('--reassemble-sibs', action='store_true',
                        help='include reassembled UMTS SIBs as supplementary frames')
    parser.add_argument('--decrypt-nas', action='store_true',
                        help='include unencrypted LTE NAS as supplementary frames')
    parser.add_argument('--include-ip-traffic', action='store_true',
                        help='include unframed IP traffic from the UE')
    parser.add_argument('-v', '--verbose', action='store_true')
    args = parser.parse_args()

    setup_logging(args.verbose)

    inputs = list(args.inputs)
    for list_file in args.list:
        inputs.extend(read_list_file(list_file))
    if not inputs:
        parser.error('no input files (give paths and/or -l LIST_FILE)')
    if args.output and len(inputs) != 1:
        parser.error('-o/--output requires exactly one input file')
    if args.jobs < 0:
        parser.error('-j/--jobs must be >= 0')
    if args.out_dir:
        args.out_dir.mkdir(parents=True, exist_ok=True)

    pcap_opts = (args.reassemble_sibs, args.decrypt_nas, args.include_ip_traffic)

    # Decide what to do with each input before starting any conversion
    jobs = []
    claimed = {}  # output path -> input that will write it
    skipped = failed = 0
    for i, src in enumerate(inputs, 1):
        if args.output:
            dst = args.output
        else:
            dst = (args.out_dir or src.parent) / default_output_name(src)

        prefix = f'[{i}/{len(inputs)}] {src}'
        if not src.is_file():
            log.error('%s: not found', prefix)
            failed += 1
            continue
        if dst.resolve() in claimed:
            log.error('%s: skipping, %s is already the output of %s',
                      prefix, dst, claimed[dst.resolve()])
            failed += 1
            continue
        if dst.exists() and not args.force:
            log.info('%s: skipping, %s exists (use -f to overwrite)', prefix, dst)
            skipped += 1
            continue
        claimed[dst.resolve()] = src
        jobs.append((prefix, src, dst, pcap_opts))

    n_workers = min(args.jobs or os.cpu_count() or 1, max(len(jobs), 1))
    if n_workers == 1:
        results = [convert_one(*job) for job in jobs]
    else:
        log.info('converting %d files with %d workers', len(jobs), n_workers)
        with ProcessPoolExecutor(n_workers, initializer=setup_logging,
                                 initargs=(args.verbose,)) as pool:
            futures = [pool.submit(convert_one, *job) for job in jobs]
            results = []
            for future, job in zip(futures, jobs):
                try:
                    results.append(future.result())
                except Exception:  # e.g. a worker process died
                    log.exception('%s: worker failed', job[0])
                    job[2].unlink(missing_ok=True)
                    results.append(False)

    converted = sum(results)
    failed += len(results) - converted
    log.info('done: %d converted, %d skipped, %d failed', converted, skipped, failed)
    return 1 if failed else 0


if __name__ == '__main__':
    sys.exit(main())
