"""The shared work/ folder may be used by one benchmark process at a time.

    python test_lock.py
"""
import subprocess
import sys
import time

CODE = "import bench,time;bench.reset_workspace('normal','x');print('got',flush=True);time.sleep(%s)"


def run(sleep):
    return subprocess.Popen([sys.executable, "-c", CODE % sleep], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)


def main():
    failed = []
    first = run(8)
    assert first.stdout.readline().strip() == "got", "first process did not get the lock"
    second = run(0)
    out, err = second.communicate(timeout=60)
    ok = second.returncode != 0 and "already running" in err
    print(("PASS  " if ok else "FAIL  ") + "a second process is refused while the first holds the lock")
    if not ok:
        failed.append("refused")
    first.communicate(timeout=60)
    third = run(0)
    out, err = third.communicate(timeout=60)
    ok = third.returncode == 0 and "got" in out
    print(("PASS  " if ok else "FAIL  ") + "the lock is free again after the first process exits")
    if not ok:
        failed.append("released")
    print("\n%s" % ("ALL PASSED" if not failed else "FAILED"))
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
