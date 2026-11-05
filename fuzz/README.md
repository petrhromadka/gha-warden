# Fuzzing

`fuzz_scan.py` is a coverage-guided fuzz target for [Atheris](https://github.com/google/atheris)
(libFuzzer for Python). Each input is decoded as UTF-8 (invalid bytes replaced), split on
`\n---\n` into one to three workflow files, parsed, linked for `workflow_run` lookups, scanned,
and rendered in every report format. The run fails when:

- anything other than `WorkflowError` (the documented parse-error path) is raised;
- a line of the text or markdown report starts with `::`, which a CI log would read as a workflow
  command;
- the JSON or SARIF report is not valid JSON, or the `github` report does not have exactly one
  `::` line per finding.

`yaml.dict` holds GitHub Actions and YAML tokens for libFuzzer's mutator. The seed corpus is the
existing `corpus/` and `examples/` workflows.

## Run locally

Atheris publishes wheels for CPython 3.12 to 3.14 on Linux x86_64 only, so the `fuzz` dependency
group installs nothing elsewhere. On Linux:

```sh
uv sync --group fuzz
mkdir -p fuzz/work fuzz/artifacts
uv run --group fuzz python fuzz/fuzz_scan.py -dict=fuzz/yaml.dict -max_total_time=300 \
    -timeout=30 -max_len=8192 -artifact_prefix=fuzz/artifacts/ fuzz/work corpus examples
```

The first directory (`fuzz/work`, gitignored) receives the inputs libFuzzer finds interesting;
`corpus` and `examples` are only read. A crash writes `fuzz/artifacts/crash-<sha1>`; reproduce it
with `uv run --group fuzz python fuzz/fuzz_scan.py fuzz/artifacts/crash-<sha1>`.

On any platform, `uv run python -m pytest tests/test_fuzz.py` runs the same check (`check_one`)
on every seed file and on 400 mutated inputs, without Atheris.

## In CI

- `.github/workflows/ci.yml`, job `fuzz`: 2 minutes on every push to `main` and pull request.
- `.github/workflows/fuzz.yml`: 15 minutes every Sunday, and on manual dispatch.

Both upload `fuzz/artifacts/` as the `fuzz-crashes` artifact when the run fails. A fixed crash
gets a regression test in `tests/test_fuzz.py`.
