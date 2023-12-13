package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/ngrok/ngrok-api-go/v5"
	"github.com/ngrok/ngrok-api-go/v5/tunnels"
)

func Getenv(key, val string) string {
	s := os.Getenv(key)
	if s == "" {
		return val
	}
	return s
}

func ngrokWeb() (publicURL string, forwardsTo string, err error) {
	web_addr := Getenv("web_addr", "localhost:4040")
	var client struct {
		Tunnels []struct {
			// Name      string `json:"name"`
			// ID        string `json:"ID"`
			// URI       string `json:"uri"`
			PublicURL string `json:"public_url"`
			// Proto     string `json:"proto"`
			Config struct {
				Addr string `json:"addr"`
				// Inspect bool   `json:"inspect"`
			} `json:"config"`
		} `json:"tunnels"`
		// URI string `json:"uri"`
	}
	resp, err := http.Get("http://" + web_addr + "/api/tunnels")
	if err != nil {
		return "", "", srcError(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		err = fmt.Errorf("http.Get resp.StatusCode: %v", resp.StatusCode)
		return "", "", Errorf("http.Get resp.StatusCode: %v", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", "", srcError(err)
	}
	err = json.Unmarshal(body, &client)
	if err != nil {
		return "", "", srcError(err)
	}
	for _, tunnel := range client.Tunnels {
		if true { //free version allow only one tunnel
			return tunnel.PublicURL, tunnel.Config.Addr, nil
		}
	}
	return "", "", Errorf("not found online client")
}

// get ngrok info of first tunnel
func ngrokAPI(NGROK_API_KEY string) (publicURL, metadata string, er error) {
	if NGROK_API_KEY == "" {
		return "", "", Errorf("empty NGROK_API_KEY")
	}

	// construct the api client
	clientConfig := ngrok.NewClientConfig(NGROK_API_KEY)

	// list all online client
	client := tunnels.NewClient(clientConfig)
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
	} else {
		return "", "", Errorf("not found online client")
	}
}
