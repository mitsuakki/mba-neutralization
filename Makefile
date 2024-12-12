PYTHON = python3
PIP = pip
VENV_DIR = .venv
ACTIVATE = . $(VENV_DIR)/bin/activate

all: setup generate dataset_to_c

setup:
	$(PYTHON) -m venv $(VENV_DIR)
	$(ACTIVATE) && $(PIP) install -r requirements.txt

generate:
	$(ACTIVATE) && $(PYTHON) dataset/generator.py --numOfTerms 5 --numOfVars 2

dataset_to_c:
	$(ACTIVATE) && $(PYTHON) -c "from dataset.generator import CSVToCGenerator; CSVToCGenerator('dataset/dataset.csv', 'bin/generated.c').generate()"

clean:
	rm -rf $(VENV_DIR)
	rm -f dataset/dataset.csv bin/generated.c

.PHONY: all setup generate dataset_to_c clean
