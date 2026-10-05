"""Run the KIVZO benchmark.

    python bench.py                    # all systems, named + generated attacks (scripted, ~seconds)
    python bench.py --quick            # named attacks only
    python bench.py --mode llm --runs 3 --limit 30   # real model calls where configured
"""
import argparse
import sys

from kivzo.bench import RESULTS, pct, pct_ci, run_benchmark, save_all
from kivzo.engine import SYSTEMS


def main() -> None:
    ap = argparse.ArgumentParser(description="KIVZO benchmark")
    ap.add_argument("--quick", action="store_true", help="skip the generated attack set")
    ap.add_argument("--mode", choices=["scripted", "llm"], default="scripted")
    ap.add_argument("--runs", type=int, default=1)
    ap.add_argument("--limit", type=int, default=None, help="limit generated attacks")
    ap.add_argument("--systems", nargs="*", default=None, choices=list(SYSTEMS))
    args = ap.parse_args()

    def progress(i, n):
        if i % 200 == 0 or i == n:
            print(f"\r  {i}/{n} runs", end="", file=sys.stderr, flush=True)

    res = run_benchmark(args.systems, generated=not args.quick, mode=args.mode, runs=args.runs,
                        limit=args.limit, progress=progress)
    print(file=sys.stderr)
    save_all(res)
    m = res["meta"]
    print(f"\nKIVZO benchmark - {m['total_runs']} runs in {m['seconds']}s "
          f"({m['n_named_attacks']} named + {m['n_generated_attacks']} generated attacks, {m['n_tasks']} tasks)\n")
    print(f"{'System':38} {'Attack success':>16} {'Task compl.':>12} {'Compl. under atk':>17} {'False blocks':>13}")
    for s in res["systems"].values():
        print(f"{s['name']:38} {pct(s['asr_all']):>16} {pct(s['tcr_clean']):>12} "
              f"{pct(s['tcr_under_attack']):>17} {pct(s['false_block_rate']):>13}")
    print(f"\nReport: {RESULTS / 'BENCHMARK_REPORT.md'}")
    print(f"Charts: {RESULTS / 'charts'}")


if __name__ == "__main__":
    main()
