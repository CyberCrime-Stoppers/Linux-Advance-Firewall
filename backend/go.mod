module linux-firewall-backend

go 1.23.0

require (
	github.com/golang-jwt/jwt/v5 v5.1.0
	github.com/google/nftables v0.2.0
	github.com/google/uuid v1.4.0
	github.com/labstack/echo/v4 v4.11.4
	gorm.io/driver/sqlite v1.5.4
	gorm.io/gorm v1.25.5
)

require (
	github.com/golang-jwt/jwt v3.2.2+incompatible // indirect
	github.com/google/go-cmp v0.7.0 // indirect
	github.com/jinzhu/inflection v1.0.0 // indirect
	github.com/jinzhu/now v1.1.5 // indirect
	github.com/labstack/gommon v0.4.2 // indirect
	github.com/mattn/go-colorable v0.1.13 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	github.com/mattn/go-sqlite3 v1.14.17 // indirect
	github.com/mdlayher/netlink v1.8.1-0.20251028132421-dcc6cab9a6eb // indirect
	github.com/mdlayher/socket v0.5.1 // indirect
	github.com/valyala/bytebufferpool v1.0.0 // indirect
	github.com/valyala/fasttemplate v1.2.2 // indirect
	golang.org/x/crypto v0.41.0 // indirect
	golang.org/x/net v0.43.0 // indirect
	golang.org/x/sync v0.16.0 // indirect
	golang.org/x/sys v0.35.0 // indirect
	golang.org/x/text v0.28.0 // indirect
	golang.org/x/time v0.5.0 // indirect
)

replace github.com/google/nftables => github.com/CyberCrime-Stoppers/alf-nftables v0.0.0-20260824174840-63846bfa5f98
