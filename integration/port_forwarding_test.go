/*
Copyright 2021 Gravitational, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package integration

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"testing"
	"time"

	"github.com/gravitational/teleport/api/types"
	"github.com/gravitational/teleport/integration/helpers"
	"github.com/gravitational/teleport/lib/auth"
	"github.com/gravitational/teleport/lib/client"

	"github.com/gravitational/trace"
	"github.com/stretchr/testify/require"
)

func extractPort(svr *httptest.Server) (int, error) {
	u, err := url.Parse(svr.URL)
	if err != nil {
		return 0, trace.Wrap(err)
	}
	n, err := strconv.Atoi(u.Port())
	if err != nil {
		return 0, trace.Wrap(err)
	}
	return n, nil
}

// Wait for a session to be established on the given host by checking for a running session tracker.
func waitForSessionToBeEstablished(ctx context.Context, t *testing.T, site auth.ClientI, hostName string) types.SessionTracker {
	t.Helper()
	var tracker types.SessionTracker
	sessionEstablished := func() bool {
		trackers, err := site.GetActiveSessionTrackers(ctx)
		if err != nil || len(trackers) == 0 {
			return false
		}
		for _, tracker = range trackers {
			if tracker.GetHostname() == hostName {
				return tracker.GetState() == types.SessionState_SessionStateRunning
			}
		}
		return false
	}
	require.Eventually(t, sessionEstablished, time.Second*10, time.Millisecond*250)
	return tracker
}

func testPortForwarding(t *testing.T, suite *integrationTestSuite) {
	ctx := context.Background()

	testCases := []struct {
		desc                  string
		portForwardingAllowed bool
		expectSuccess         bool
	}{
		{
			desc:                  "Enabled",
			portForwardingAllowed: true,
			expectSuccess:         true,
		}, {
			desc:                  "Disabled",
			portForwardingAllowed: false,
			expectSuccess:         false,
		},
	}

	for _, tt := range testCases {
		t.Run(tt.desc, func(t *testing.T) {
			// Given a running teleport instance with port forwarding
			// permissions set per the test case

			recCfg, err := types.NewSessionRecordingConfigFromConfigFile(types.SessionRecordingConfigSpecV2{
				Mode: types.RecordOff,
			})
			require.NoError(t, err)

			cfg := suite.defaultServiceConfig()
			cfg.Auth.Enabled = true
			cfg.Auth.SessionRecordingConfig = recCfg
			cfg.Proxy.Enabled = true
			cfg.Proxy.DisableWebService = false
			cfg.Proxy.DisableWebInterface = true
			cfg.SSH.Enabled = true
			cfg.SSH.AllowTCPForwarding = tt.portForwardingAllowed

			teleport := suite.NewTeleportWithConfig(t, nil, nil, cfg)
			defer teleport.StopAll()

			site := teleport.GetSiteAPI(helpers.Site)

			// ...and a running dummy server
			remoteSvr := httptest.NewServer(http.HandlerFunc(
				func(w http.ResponseWriter, _ *http.Request) {
					w.WriteHeader(http.StatusOK)
					w.Write([]byte("Hello, World"))
				}))
			defer remoteSvr.Close()

			// ... and a client connection that was launched with port
			// forwarding enabled to that dummy server
			localPort := helpers.NewPortValue()
			remotePort, err := extractPort(remoteSvr)
			require.NoError(t, err)

			nodeSSHPort := helpers.Port(t, teleport.SSH)
			cl, err := teleport.NewClient(helpers.ClientConfig{
				Login:   suite.Me.Username,
				Cluster: helpers.Site,
				Host:    Host,
				Port:    nodeSSHPort,
			})
			require.NoError(t, err)
			cl.Config.LocalForwardPorts = []client.ForwardedPort{
				{
					SrcIP:    "127.0.0.1",
					SrcPort:  localPort,
					DestHost: "localhost",
					DestPort: remotePort,
				},
			}
			term := NewTerminal(250)
			cl.Stdout = term
			cl.Stdin = term

			sshSessionCtx, sshSessionCancel := context.WithCancel(ctx)
			go cl.SSH(sshSessionCtx, []string{}, false)
			defer sshSessionCancel()

			waitForSessionToBeEstablished(ctx, t, site, Host)

			// When everything is *finally* set up, and I attempt to use the
			// forwarded connection
			localURL := fmt.Sprintf("http://%s:%d/", "localhost", localPort)
			r, err := http.Get(localURL)

			if r != nil {
				r.Body.Close()
			}

			if tt.expectSuccess {
				require.NoError(t, err)
				require.NotNil(t, r)
			} else {
				require.Error(t, err)
			}
		})
	}
}
