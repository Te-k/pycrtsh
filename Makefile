PWD = $(shell pwd)
.PHONY: check

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
	rm -rf $(PWD)/build $(PWD)/dist $(PWD)/pycrtsh.egg-info

dist:
	python3 setup.py sdist bdist_wheel

upload:
	python3 -m twine upload dist/*

test:
	pytest
