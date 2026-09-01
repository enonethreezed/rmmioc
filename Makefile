PY ?= python3
OUTPUT ?= blocklist/rmm-domains.txt

.PHONY: all parse update clean

all: update

parse:
	$(PY) parser.py --no-sync --output $(OUTPUT)

update:
	$(PY) parser.py --output $(OUTPUT)

clean:
	rm -rf .cache blocklist
