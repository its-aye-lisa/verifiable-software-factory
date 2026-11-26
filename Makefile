.PHONY: build fast-check factory dast admit simulate-attacks clean

TARGET ?= ../new-vision-gaming

build:
	@mkdir -p bin
	@CGO_ENABLED=0 GOPROXY=off go build -trimpath -o bin/factory ./factory/cmd/factory

fast-check: build
	@./bin/factory fast-check --target $(TARGET)

factory: build
	@./bin/factory run-all --target $(TARGET)

dast: build
	@./bin/factory dast --target $(TARGET)

admit: build
	@./bin/factory admit --target $(TARGET)

simulate-attacks: build
	@./bin/factory simulate-attacks --target $(TARGET)

clean:
	@rm -rf bin
