# Independent verification

Frozen product: https://github.com/9873199/authlib-dpop-proof-binding/commit/a9776e42da5b929a4b98969e77c3b1d72734fb53

These checks were authored after the model session. They do not change the frozen product. The local request/response transport fixtures are reused from tests/core/test_oauth2/test_rfc9126.py; all14 contract assertions are separately authored in par_check.py. All clients and credentials are synthetic and stay in process.

Use Python3.14 on Windows. From this branch repository root:

```powershell
python -m venv .venv-check
.venv-check/Scripts/python -m pip install -r verification/requirements-lock.txt
$env:PYTHONPATH=(Get-Location).Path
.venv-check/Scripts/python -B verification/par_check.py
```

Expected observed result on the frozen implementation:12 probes pass and2 fail. The26 model-authored PAR tests also pass when rerun; these are separate counts. The callback issue changes registered client default configuration after pushing; this is not evidence that an arbitrary browser can edit client registration. Complete commands, outputs and observable native action locations are included. The initial implementation and final snapshot are exact public commits; no original trajectory is repackaged on this branch.
