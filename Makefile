PWD = $(shell pwd)
.PHONY: check

check:
	ruff check .
	mypy --explicit-package-bases .
	pytest -q

clean:
	rm -rf $(PWD)/build $(PWD)/dist $(PWD)/pycrtsh.egg-info

dist:
	python3 setup.py sdist bdist_wheel

upload:
	python3 -m twine upload dist/*

test:
	pytest
