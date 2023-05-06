package redis

import (
	"context"
	"fmt"
	"strings"

	"github.com/rueian/rueidis"
)

const (
	nkeKey = "notify-keyspace-events"
)

// enableExpiredNKE enables expired notify-keyspace-events if not enabled
func enableExpiredNKE(ctx context.Context, rc rueidis.Client) error {
	needUpdate := false

	nke, err := getNKE(ctx, rc)
	if err != nil {
		return err
	}

	if !strings.Contains(nke, "K") {
		nke = fmt.Sprintf("K%s", nke)

		needUpdate = true
	}

	if !strings.Contains(nke, "x") && !strings.Contains(nke, "A") {
		nke = fmt.Sprintf("%sx", nke)

		needUpdate = true
	}

	if needUpdate {
		err = rc.Do(ctx, rc.B().
			ConfigSet().
			ParameterValue().
			ParameterValue(nkeKey, nke).
			Build()).Error()

		if err != nil {
			return err
		}
	}

	return nil
}

// getNKE reads notify-keyspace-events config
func getNKE(ctx context.Context, rc rueidis.Client) (string, error) {
	res, err := rc.Do(ctx, rc.B().ConfigGet().Parameter(nkeKey).Build()).AsStrMap()
	if err != nil {
		return "", err
	}

	return res[nkeKey], nil
}
