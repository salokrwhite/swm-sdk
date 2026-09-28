package swm

import (
	"context"
	"log"
)

func Example() {
	client, err := NewClient(Options{
		BaseURL:            "https://swm-backend.anteasy.com",
		AppID:              "00000000-0000-0000-0000-000000000001",
		ReleaseID:          "00000000-0000-0000-0000-000000000002",
		Version:            "1.0.0",
		RootTrustKeyID:     "root-1",
		RootTrustPublicKey: "<root-trust-ed25519-public-key>",
	})
	if err != nil {
		log.Fatal(err)
	}
	defer client.Close()

	update, err := client.CheckUpdate(context.Background(), nil)
	if err != nil {
		log.Fatal(err)
	}
	if update.UpdateAvailable && !update.OpenInBrowser {
		if err := client.DownloadUpdate(context.Background(), update, "update.bin", nil); err != nil {
			log.Fatal(err)
		}
	}
}
