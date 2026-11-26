import json, pathlib, subprocess

base = pathlib.Path('/var/tmp/sandswap-claude-evidence')
results = {}
for label, path in [('original', pathlib.Path('/opt/sandswap-pr38/src/e2e/multi-instance-orphan-safety.sh')),
                    ('fixed', base / 'multi-instance-orphan-safety.fixed.sh')]:
    text = path.read_text()
    start = text.index('rl_wait_exit() {')
    function = text[start:text.index('\n}', start) + 2]
    invocation = 'rl_wait_exit "$child" 1; measured="$RL_WAIT_RC"' if label == 'fixed' else 'measured="$(rl_wait_exit "$child" 1)"'
    cases = []
    for delay, code in [(0, 0), (0, 7), (0.05, 7), (3, 7)]:
        script = function + '\n' + f'( sleep {delay}; exit {code} ) & child=$!\n' + invocation + '\n' + '''
alive=no
if kill -0 "$child" 2>/dev/null; then alive=yes; kill "$child" 2>/dev/null || true; fi
if wait "$child"; then actual=0; else actual=$?; fi
echo "$measured $actual $alive"
'''
        run = subprocess.run(['bash', '-c', script], text=True, capture_output=True, timeout=10)
        measured, actual, alive = run.stdout.strip().split()
        expected = -1 if delay == 3 else code
        cases.append({'delay_s': delay, 'expected': expected, 'measured': int(measured),
                      'parent_wait': int(actual), 'alive_at_return': alive,
                      'passed': int(measured) == expected})
    results[label] = cases
results['bash'] = subprocess.check_output(['bash', '--version'], text=True).splitlines()[0]
(base / 'role-wait-reproducer.json').write_text(json.dumps(results, indent=2) + '\n')
print(json.dumps(results, indent=2))
assert all(case['passed'] for case in results['fixed'])
