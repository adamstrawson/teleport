// Copyright 2021 Gravitational, Inc
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package teleterm

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/gravitational/teleport/lib/utils"

	"github.com/stretchr/testify/require"
)

func TestStart(t *testing.T) {
	t.Parallel()

	sockDir := t.TempDir()
	sockPath := filepath.Join(sockDir, "teleterm.sock")

	tests := []struct {
		name string
		addr string
	}{
		{
			// No mTLS.
			name: "unix",
			addr: fmt.Sprintf("unix://%v", sockPath),
		},
		{
			// Requires mTLS.
			name: "tcp",
			addr: "tcp://localhost:0",
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			homeDir := t.TempDir()
			certsDir := t.TempDir()
			listeningC := make(chan utils.NetAddr)

			cfg := Config{
				Addr:       test.addr,
				HomeDir:    homeDir,
				CertsDir:   certsDir,
				ListeningC: listeningC,
			}

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			serveErr := make(chan error)
			go func() {
				err := Serve(ctx, cfg)
				serveErr <- err
			}()

			select {
			case addr := <-listeningC:
				// Verify that the server accepts connections on the advertised address.
				blockUntilServerAcceptsConnections(t, addr, certsDir)
			case <-time.After(time.Second):
				t.Fatal("listeningC didn't advertise the address within the timeout")
			}

			// Stop the server.
			cancel()
			require.NoError(t, <-serveErr)
		})
	}

}

// blockUntilServerAcceptsConnections dials the addr and then reads from the connection.
// In case of a unix addr, it waits for the socket file to be created before attempting to dial.
// In case of a tcp addr, it sets up an mTLS config for the dialer.
func blockUntilServerAcceptsConnections(t *testing.T, addr utils.NetAddr, certsDir string) {
	var conn net.Conn
	switch addr.AddrNetwork {
	case "unix":
		conn = dialUnix(t, addr)
	case "tcp":
		conn = dialTcp(t, addr, certsDir)
	default:
		t.Fatalf("Unknown addr network %v", addr.AddrNetwork)
	}

	t.Cleanup(func() { conn.Close() })

	err := conn.SetReadDeadline(time.Now().Add(time.Second))
	require.NoError(t, err)

	out := make([]byte, 1024)
	_, err = conn.Read(out)
	require.NoError(t, err)

	err = conn.Close()
	require.NoError(t, err)
}

func dialUnix(t *testing.T, addr utils.NetAddr) net.Conn {
	sockPath := addr.Addr

	// Wait for the socket to be created.
	require.Eventually(t, func() bool {
		_, err := os.Stat(sockPath)
		if errors.Is(err, os.ErrNotExist) {
			return false
		}
		require.NoError(t, err)
		return true
	}, time.Millisecond*500, time.Millisecond*50)

	conn, err := net.DialTimeout("unix", sockPath, time.Second)
	require.NoError(t, err)
	return conn
}

func dialTcp(t *testing.T, addr utils.NetAddr, certsDir string) net.Conn {
	// Hardcoded filenames under which Connect expects certs. In this test suite, we're trying to
	// reach the tsh gRPC server, so we need to use the renderer cert as the client cert.
	clientCertPath := filepath.Join(certsDir, rendererCertFileName)
	serverCertPath := filepath.Join(certsDir, tshdCertFileName)
	clientCert, err := generateAndSaveCert(clientCertPath)
	require.NoError(t, err)

	tlsConfig, err := createClientTlsConfig(clientCert, serverCertPath)
	dialer := tls.Dialer{
		Config: tlsConfig,
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	t.Cleanup(func() { cancel() })

	conn, err := dialer.DialContext(ctx, addr.AddrNetwork, addr.Addr)
	require.NoError(t, err)
	return conn
}
