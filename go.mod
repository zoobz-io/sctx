module github.com/zoobzio/sctx

go 1.23.1

require github.com/zoobzio/pipz v0.6.0

require (
	github.com/zoobzio/flume v0.0.0
	github.com/zoobzio/zlog v0.1.0
)

require (
	golang.org/x/time v0.12.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

replace github.com/zoobzio/pipz => ../pipz

replace github.com/zoobzio/flume => ../flume

replace github.com/zoobzio/zlog => ../zlog
