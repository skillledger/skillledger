package ioc

import _ "embed"

//go:embed data/ioc-hashes.json
var bundledIOCData []byte

//go:embed data/ioc-domains.json
var bundledDomainData []byte
