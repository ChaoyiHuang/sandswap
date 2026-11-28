# Repair the SandSwap Python project

Use `list_sandfs` to identify sandbox `{{SANDFS_ID}}`. Its `/workspace` contains
a Python package with two bugs in `calc/core.py` and five tests in
`tests/test_calc.py`.

1. Read both files with `file_read` and run the original tests with `execute`
   to observe the failures.
2. Fix `add` and `fib` using `file_write`. Do not modify the tests.
3. Run `python3 -B -m unittest discover -s tests` from `/workspace` and require
   all five tests to pass. Check the command's exit code without masking it
   with a pipe.
4. Commit only `calc/core.py` with message `fix calc`, using Git identity
   `agent` / `agent@sandswap`. Remove any generated `__pycache__` directories
   and leave a clean Git working tree.
5. Report what changed and the test result.

Use SandSwap tools for every sandbox command and file operation.
