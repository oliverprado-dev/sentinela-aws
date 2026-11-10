PYTHON ?= python3
TERRAFORM ?= terraform
TRIVY ?= trivy

export PYTHONPATH := src:.
export PYTHONDONTWRITEBYTECODE := 1

.PHONY: demo test lint validate scan

demo:
	@$(PYTHON) scripts/demo.py

test:
	$(PYTHON) -m unittest discover -v

lint:
	$(PYTHON) -m ruff check src scripts tests
	$(PYTHON) -m ruff format --check src scripts tests

validate:
	$(TERRAFORM) -chdir=infra fmt -check -recursive
	$(TERRAFORM) -chdir=infra init -backend=false -input=false -lockfile=readonly
	$(TERRAFORM) -chdir=infra validate
	$(TERRAFORM) -chdir=infra test

scan:
	$(TRIVY) config --exit-code 1 --severity HIGH,CRITICAL --skip-check-update infra
	$(TRIVY) fs --scanners secret --exit-code 1 --skip-dirs infra/.terraform --skip-dirs .venv --skip-dirs .git .
