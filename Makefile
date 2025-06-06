# 🦉 Noctilog Makefile

run:
	python3 main.py

dashboard:
	python3 dashboard.py

test-logs:
	python3 inject_severity_events.py

clean:
	rm -f output/*.jsonl output/*.db output/log_offset.txt output/logs_snapshot.txt output/archived_events.jsonl output/exports/*.txt

install:
	pip install -r requirements.txt

clean-fake:
	rm -f logs/fake_auth.log
