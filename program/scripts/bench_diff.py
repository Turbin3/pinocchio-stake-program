#!/usr/bin/env python3
import sys, csv

def read_csv(path_or_stdin):
    f = sys.stdin if path_or_stdin == '-' else open(path_or_stdin, 'r')
    rdr = csv.reader(f)
    rows = [r for r in rdr if r]
    # normalize header
    if rows and rows[0][0] != 'name':
        rows.insert(0, ['name','pin','native'])
    data = {}
    for r in rows[1:]:
        try:
            name = r[0].strip()
            pin = int(r[1])
            native = int(r[2])
            data[name] = (pin, native)
        except Exception:
            continue
    return data

def main():
    if len(sys.argv) == 1:
        print('Usage: bench_diff.py <current.csv|-] [baseline.csv]')
        sys.exit(1)
    cur = read_csv(sys.argv[1])
    base = read_csv(sys.argv[2]) if len(sys.argv) > 2 else {}
    print('instr,pin,native,delta(abs),delta(%)')
    for k in sorted(cur.keys()):
        pin, nat = cur[k]
        delta = pin - nat
        pct = 0.0 if nat == 0 else (delta / nat) * 100.0
        print(f"{k},{pin},{nat},{delta},{pct:.1f}")

if __name__ == '__main__':
    main()

