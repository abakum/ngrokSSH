module github.com/abakum/ngrokSSH

go 1.21.4

replace internal/tool => ./internal/tool

// replace github.com/abakum/embed-encrypt => ../embed-encrypt

replace github.com/ThalesIgnite/crypto11 v1.2.5 => github.com/blacknon/crypto11 v1.2.6

require (
	github.com/Desuuuu/windrive v0.2.2
	github.com/Microsoft/go-winio v0.6.1
	github.com/abakum/embed-encrypt v0.0.0-20240330115809-059354cfa29a
	github.com/abakum/go-ansiterm v0.0.0-20240209124652-4fc46d492442
	github.com/abakum/go-netstat v0.0.0-20231106075911-001f10558dcf
	github.com/abakum/go-sshlib v0.0.11-lw
	github.com/abakum/menu v0.0.0-20240209213529-cf43393155b2
	github.com/abakum/pageant v0.0.0-20240210190511-4450a30bb403
	github.com/abakum/proxy v0.0.6-lw
	github.com/abakum/version v0.0.6-lw
	github.com/abakum/winssh v0.0.0-20240210184859-e6228961ea04
	github.com/f1bonacc1/glippy v0.0.0-20230614190937-e7ca07f99f6f
	github.com/gliderlabs/ssh v0.3.6
	github.com/mitchellh/go-ps v1.0.0
	github.com/ngrok/ngrok-api-go/v5 v5.2.0
	github.com/xlab/closer v1.1.0
	go.bug.st/serial v1.6.1
	golang.ngrok.com/ngrok v1.7.0
	golang.org/x/crypto v0.19.0
	golang.org/x/sys v0.18.0
	gopkg.in/ini.v1 v1.67.0
	internal/tool v0.0.0-00010101000000-000000000000
)

require (
	github.com/ScaleFT/sshkeys v1.2.0 // indirect
	github.com/ThalesIgnite/crypto11 v1.2.5 // indirect
	github.com/abakum/go-console v0.0.0-20240331141302-a7e7a5804946 // indirect
	github.com/abakum/term v0.0.0-20240212164236-135562d7e4cf // indirect
	github.com/anmitsu/go-shlex v0.0.0-20200514113438-38f4b401e2be // indirect
	github.com/armon/go-socks5 v0.0.0-20160902184237-e75332964ef5 // indirect
	github.com/creack/goselect v0.1.2 // indirect
	github.com/creack/pty v1.1.21 // indirect
	github.com/dchest/bcrypt_pbkdf v0.0.0-20150205184540-83f37f9c154a // indirect
	github.com/eiannone/keyboard v0.0.0-20220611211555-0d226195f203 // indirect
	github.com/go-stack/stack v1.8.1 // indirect
	github.com/iamacarpet/go-winpty v1.0.4 // indirect
	github.com/inconshreveable/log15 v3.0.0-testing.5+incompatible // indirect
	github.com/inconshreveable/log15/v3 v3.0.0-testing.5 // indirect
	github.com/jezek/xgb v1.1.1 // indirect
	github.com/jpillora/backoff v1.0.0 // indirect
	github.com/kr/fs v0.1.0 // indirect
	github.com/mattn/go-colorable v0.1.13 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	github.com/miekg/pkcs11 v1.1.1 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/pkg/sftp v1.13.6 // indirect
	github.com/thales-e-security/pool v0.0.2 // indirect
	go.uber.org/multierr v1.11.0 // indirect
	golang.ngrok.com/muxado/v2 v2.0.0 // indirect
	golang.org/x/mod v0.15.0 // indirect
	golang.org/x/net v0.21.0 // indirect
	golang.org/x/sync v0.6.0 // indirect
	golang.org/x/term v0.17.0 // indirect
	golang.org/x/tools v0.18.0 // indirect
	google.golang.org/protobuf v1.32.0 // indirect
)
