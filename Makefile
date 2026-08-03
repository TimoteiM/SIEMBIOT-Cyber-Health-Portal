.PHONY: bootstrap check

bootstrap:
	python scripts/bootstrap.py

check:
	python scripts/verify_repo.py
