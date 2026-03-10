package logstream

import (
	"encoding/json"
	"net/http"

	"nhooyr.io/websocket"
)

// Handler returns an HTTP handler that upgrades to WebSocket and streams log entries.
func Handler(broadcaster *Broadcaster) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{
			InsecureSkipVerify: true, // Allow any origin (local network service)
		})
		if err != nil {
			return
		}
		defer conn.CloseNow() //nolint:errcheck

		ch, cancel := broadcaster.Subscribe()
		defer cancel()

		ctx := r.Context()

		for {
			select {
			case entry, ok := <-ch:
				if !ok {
					// Broadcaster shut down
					conn.Close(websocket.StatusGoingAway, "server shutting down") //nolint:errcheck

					return
				}

				data, err := json.Marshal(entry)
				if err != nil {
					continue
				}

				if err := conn.Write(ctx, websocket.MessageText, data); err != nil {
					return
				}

			case <-ctx.Done():
				conn.Close(websocket.StatusNormalClosure, "client disconnected") //nolint:errcheck

				return
			}
		}
	}
}
