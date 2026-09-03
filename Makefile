PYTHON ?= python3
export PYTHONPATH := src

.PHONY: format format-check lint typecheck test acceptance verify demo demo-phase2 demo-phase3 demo-phase3a

format:
	$(PYTHON) -m vault_next.dev format

format-check:
	$(PYTHON) -m vault_next.dev format --check

lint:
	$(PYTHON) -m vault_next.dev lint

typecheck:
	$(PYTHON) -m vault_next.dev typecheck

test:
	$(PYTHON) -m unittest discover -s tests -t . -v

acceptance:
	$(PYTHON) -m unittest discover -s tests/acceptance -t . -v

verify: format-check lint typecheck test acceptance

demo:
	$(PYTHON) -m vault_next --root .phase1-demo synthetic-run

demo-phase2:
	$(PYTHON) -m vault_next --root .phase2-demo synthetic-phase2-run

demo-phase3:
	$(PYTHON) -m vault_next --root .phase3-demo synthetic-phase3-run

demo-phase3a:
	$(PYTHON) -m vault_next --root .phase3a-demo synthetic-phase3a-run
