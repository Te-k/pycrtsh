PWD = $(shell pwd)
.PHONY: check

check:
	flake8
	black --check pycrtsh
	mypy --explicit-package-bases .
	pytest -q
	ruff check -q .

clean:
	rm -rf $(PWD)/build $(PWD)/dist $(PWD)/pycrtsh.egg-info

dist:
	python3 setup.py sdist bdist_wheel

upload:
	python3 -m twine upload dist/*

test:
	pytest
