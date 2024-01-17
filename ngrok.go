package main

import (
	"context"
	"errors"
	"os"
	"time"

	"github.com/ngrok/ngrok-api-go/v5"
	"github.com/ngrok/ngrok-api-go/v5/tunnel_sessions"
	"github.com/ngrok/ngrok-api-go/v5/tunnels"
)

var (
	ErrNgrokOnlineNoTunnel = errors.New("not found online client")
	ErrEmptyNgrokApiKey    = errors.New("empty NGROK_API_KEY")
)

func Getenv(key, val string) string {
	s := os.Getenv(key)
	if s == "" {
		return val
	}
	return s
}

// get publicURL and metadata of first tunnel by NGROK_API_KEY
func ngrokGet(NGROK_API_KEY string) (publicURL, metadata string, err error) {
	if NGROK_API_KEY == "" {
		return "", "", srcError(ErrEmptyNgrokApiKey)
	}

	// construct the api client
	clientConfig := ngrok.NewClientConfig(NGROK_API_KEY)

	// construct the tunnels client
	client := tunnels.NewClient(clientConfig)

	// list all online client
	iter := client.List(nil)

	ctx, ca := context.WithTimeout(context.Background(), time.Second*3)
	defer ca()
	//free version allow only one tunnel
	if iter.Next(ctx) {
		return iter.Item().PublicURL, iter.Item().Metadata, nil
	}
	err = iter.Err()
	if err != nil {
		return "", "", srcError(err)
	}
	return "", "", srcError(ErrNgrokOnlineNoTunnel)
}

// restart first tunnel sessions by NGROK_API_KEY
func ngrokRestart(NGROK_API_KEY string) (id string, err error) {
	if NGROK_API_KEY == "" {
		return "", srcError(ErrEmptyNgrokApiKey)
	}

	// construct the api client
	clientConfig := ngrok.NewClientConfig(NGROK_API_KEY)

	// construct the tunnel_sessions client
	client := tunnel_sessions.NewClient(clientConfig)

	// list all online tClient
	iter := client.List(nil)

	ctx, ca := context.WithTimeout(context.Background(), time.Second*3)
	defer ca()
	//free version allow only one tunnel
	if iter.Next(ctx) {
		id = iter.Item().ID
		err = client.Restart(ctx, id)
		return
	}
	err = iter.Err()
	if err != nil {
		return "", srcError(err)
	}
	return "", srcError(ErrNgrokOnlineNoTunnel)
}
