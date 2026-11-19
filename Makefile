PYTHON ?= python3
PYTHONPATH := src
export PYTHONPATH

.PHONY: all test bench verify paper clean

all: test bench verify

test:
	$(PYTHON) tests/run_all_tests.py

bench:
	$(PYTHON) experiments/run_nosih_evaluation.py

verify:
	$(PYTHON) experiments/verify_nosih_claims.py

paper:
	cd paper && pdflatex -interaction=nonstopmode nosih_paper.tex && pdflatex -interaction=nonstopmode nosih_paper.tex

clean:
	find . -type d -name "__pycache__" -exec rm -rf {} +
	find . -type f \( -name "*.pyc" -o -name "*.pyo" -o -name "*.db-wal" -o -name "*.db-shm" \) -delete
	rm -rf .pytest_cache build dist *.egg-info
	rm -f paper/*.aux paper/*.log paper/*.out paper/*.toc paper/*.bbl paper/*.blg paper/*.fls paper/*.fdb_latexmk
