PWD = $(shell pwd)
.PHONY: check autofix ruff clean dist docs upload test

check:
	ruff format --check .
	ruff check -q .
	mypy --explicit-package-bases .
	pytest -q

autofix:
	ruff format .
	ruff check --fix .

ruff:
	ruff format --check .
	ruff check -q .

clean:
	rm -rf $(PWD)/build $(PWD)/dist $(PWD)/pycrtsh.egg-info $(PWD)/docs/build

dist:
	python -m build

docs:
	$(MAKE) -C docs html

upload:
	python3 -m twine upload dist/*

test:
	pytest
