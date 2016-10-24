.PHONY = tests
tests:
	go test -v


.PHONY = benchs
benchs:
	go test -bench . -run ^$ -timeout=1h
