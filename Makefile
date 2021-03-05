PHONY: build test install

build:
	mkdir -p /tmp/bundles
	cd example && tar czvf /tmp/bundles/example-bundle.tar.gz ./ && cd -
	cd INFN-Cloud && tar czvf /tmp/bundles/INFN_Cloud-bundle.tar.gz ./ && cd -
	cd PLANET && tar czvf /tmp/bundles/PLANET-bundle.tar.gz ./  && cd -

test: build
	opa test --bundle /tmp/bundles/example-bundle.tar.gz
	opa test --bundle /tmp/bundles/INFN_Cloud-bundle.tar.gz
	opa test --bundle /tmp/bundles/PLANET-bundle.tar.gz

install:
	sudo wget -O /usr/bin/opa https://github.com/open-policy-agent/opa/releases/download/v0.26.0/opa_linux_amd64
	sudo chmod +x /usr/bin/opa