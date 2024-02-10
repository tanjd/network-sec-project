.DEFAULT_GOAL := help

help:
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m\033[0m\n\nTargets:\n"} /^[a-zA-Z_-]+:.*?##/ { printf "\033[36m%-10s\033[0m %s\n", $$1, $$2 }' $(MAKEFILE_LIST)

lint: ## lint project
	@SKIP=pytest poetry run pre-commit run --all-files

.PHONY: test
test: ## run pytest
	poetry run pytest

setup: ## setup project for development
	poetry install --no-root
	poetry run pre-commit install

install: pyproject.toml poetry.lock ## install dependencies
	poetry install --no-root

run: ## run main.py
	poetry run python main.py

.PHONY: clean
clean: ## remove pycache and venv
	rm -rf __pycache__
	rm -rf venv
