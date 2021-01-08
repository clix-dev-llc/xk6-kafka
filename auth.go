package kafka

import (
	"strings"
	"time"

	"github.com/segmentio/kafka-go"
	"github.com/segmentio/kafka-go/sasl/plain"
	"github.com/segmentio/kafka-go/sasl/scram"
)

type Credentials struct {
	Username  string
	Password  string
	Algorithm string
}

func authenticate(creds *Credentials) *kafka.Dialer {
	dialer := &kafka.Dialer{
		Timeout:   10 * time.Second,
		DualStack: true,
	}

	if creds.Username != "" && creds.Password != "" {
		if creds.Algorithm == "plain" || creds.Algorithm == "" {
			mechanism := plain.Mechanism{
				Username: creds.Username,
				Password: creds.Password,
			}
			dialer.SASLMechanism = mechanism
		} else {
			hashAlgorithms := make(map[string]scram.Algorithm)
			hashAlgorithms["SHA256"] = scram.SHA256
			hashAlgorithms["SHA-256"] = scram.SHA256
			hashAlgorithms["SHA512"] = scram.SHA512
			hashAlgorithms["SHA-512"] = scram.SHA512

			mechanism, _ := scram.Mechanism(
				hashAlgorithms[strings.ToUpper(creds.Algorithm)],
				creds.Username,
				creds.Password,
			)
			dialer.SASLMechanism = mechanism
		}
	}

	return dialer
}
