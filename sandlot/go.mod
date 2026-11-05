module sandlot

go 1.25.0

require (
	common v0.0.0
	golang.org/x/sys v0.43.0
	google.golang.org/grpc v1.82.0
	gopkg.in/yaml.v3 v3.0.1
)

require (
	github.com/opencontainers/go-digest v1.0.0
	github.com/opencontainers/image-spec v1.1.1
	golang.org/x/sync v0.22.0
	oras.land/oras-go/v2 v2.6.2
)

replace common v0.0.0 => ../common

require (
	github.com/fsnotify/fsnotify v1.10.1 // indirect
	golang.org/x/net v0.53.0 // indirect
	golang.org/x/text v0.36.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20260414002931-afd174a4e478 // indirect
	google.golang.org/protobuf v1.36.11 // indirect
)
