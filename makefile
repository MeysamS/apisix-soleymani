init:
	docker compose up --build
build:
	docker compose build
up:
	docker compose up
down:
	docker compose down
clean: 
	docker compose down -v

reup:down up