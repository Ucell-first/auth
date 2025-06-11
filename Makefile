include .env
export $(shell sed 's/=.*//' .env)

CURRENT_DIR=$(shell pwd)
PDB_URL := postgres://$(PDB_USER):$(PDB_PASSWORD)@localhost:$(PDB_PORT)/$(PDB_NAME)?sslmode=disable

proto-gen:
	./scripts/gen-proto.sh ${CURRENT_DIR}

mig-up:
	migrate -path migrations -database '${PDB_URL}' -verbose up

mig-down:
	migrate -path migrations -database '${PDB_URL}' -verbose down

mig-force:
	migrate -path migrations -database '${PDB_URL}' -verbose force 1

mig:
	@echo "Enter file name: "; \
	read filename; \
	migrate create -ext sql -dir migrations -seq $$filename

swag:
	~/go/bin/swag init -g ./api/router.go -o api/docs
	
run:
	go run cmd/main.go
git:
	@echo "Enter commit name: "; \
	read commitname; \
	git add .; \
	git commit -m "$$commitname"; \
	if ! git push origin main; then \
		echo "Push failed. Attempting to merge and retry..."; \
		$(MAKE) git-merge; \
		git add .; \
		git commit -m "$$commitname"; \
		git push origin main; \
	fi

git-merge:
	git fetch origin; \
	git merge origin/main
