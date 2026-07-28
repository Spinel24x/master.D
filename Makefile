PORT ?= 5353

.PHONY: run run53 test smoke

run: ## start the server on $(PORT) with the sample zones
	python3 -m dnscore --port $(PORT)

run53: ## start on the real DNS port (needs root)
	sudo python3 -m dnscore --port 53

test: ## run the unit test suite
	python3 -m unittest discover -s tests -v

smoke: ## end-to-end test with real queries against a live server
	bash scripts/smoke.sh $(PORT)
