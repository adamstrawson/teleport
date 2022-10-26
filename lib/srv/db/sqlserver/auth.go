/*
Copyright 2022 Gravitational, Inc.

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

package sqlserver

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"github.com/gravitational/teleport/lib/srv/db/common"
	"github.com/gravitational/teleport/lib/srv/db/sqlserver/kinit"
	"github.com/jcmturner/gokrb5/v8/credentials"
	"strings"

	"github.com/jcmturner/gokrb5/v8/client"
	"github.com/jcmturner/gokrb5/v8/config"
	"github.com/jcmturner/gokrb5/v8/keytab"
	"github.com/jcmturner/gokrb5/v8/spnego"

	"github.com/gravitational/trace"
)

// getAuth returns Kerberos authenticator used by SQL Server driver.
//
// TODO(r0mant): Unit-test this. In-memory Kerberos server?
func (c *connector) getAuth(sessionCtx *common.Session) (*krbAuth, error) {
	// Load keytab.
	kt, err := keytab.Load(sessionCtx.Database.GetAD().KeytabFile)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	// Load krb5.conf.
	conf, err := config.Load(sessionCtx.Database.GetAD().Krb5File)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	// Create Kerberos client.
	kbClient := client.NewWithKeytab(
		sessionCtx.DatabaseUser,
		sessionCtx.Database.GetAD().Domain,
		kt,
		conf,
		// Active Directory does not commonly support FAST negotiation.
		client.DisablePAFXFAST(true))
	// Login.
	err = kbClient.Login()
	if err != nil {
		return nil, trace.Wrap(err)
	}

	// Obtain service ticket for the database's Service Principal Name.
	ticket, encryptionKey, err := kbClient.GetServiceTicket(sessionCtx.Database.GetAD().SPN)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	// Create init negotiation token.
	initToken, err := spnego.NewNegTokenInitKRB5(kbClient, ticket, encryptionKey)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	// Marshal init negotiation token.
	initTokenBytes, err := initToken.Marshal()
	if err != nil {
		return nil, trace.Wrap(err)
	}

	return &krbAuth{
		initToken: initTokenBytes,
	}, nil
}

// the following will not work unless you have a properly configured domain controller with active directory, and have exported
// the CA into Certificate Manager, published it to the NTAUTH Store, configured a group policy to use it, enabled smart card access,
// and have a service account matching the Username from the provided Identity. Even then, I was only able to get this to work
// using a KDC certificate intermediary. Looking at the Remote Desktop instructions, it looks like they do this differently by
// provisioning certificates themselves by using a Teleport Service Account to do so.

// Handy commands for working with certificates in powershell:
// - certutil -dspublish -f <certificate> RootCA  // publish to trusted root CAs
// - certutil -dspublish -f <certificate> NTAuthCA  // publish specifically to the authorization store
// - certutil -pulse  // refresh the certificate store manually, so you don't have to wait for propagation
// - certutil -dcinfo  // view certificates in use on this domain controller
// - gpupdate.exe /force  // update group policy for changes to take effect
// - New-GPO -Name <name> | New-GPLink -Target $((Get-ADDomain).DistinguishedName)  // Create a new group policy object and link it to the active directory domain
func (c *connector) getPKAuth(ctx context.Context, sessionCtx *common.Session) (*krbAuth, error) {

	// super hacky, I just placed certs next to the teleport binary
	// some of this information we will want in config, such as the domain controller/admin server address and the realm

	ldapPem, _ := pem.Decode([]byte(sessionCtx.Database.GetAD().LDAPCert))

	cert, err := x509.ParseCertificate(ldapPem.Bytes)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	var k kinit.ProviderI = kinit.NewCommandProvider(
		c.AuthClient,
		sessionCtx.Identity.Username,
		strings.ToUpper(sessionCtx.Database.GetAD().Domain),
		sessionCtx.Database.GetAD().Domain,
		sessionCtx.Database.GetAD().Domain,
		cert,
	)

	// create the kinit credentials cache using the previously prepared cert/key pair
	err = k.CreateOrAppendCredentialsCache(ctx)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	// Load CCache.
	cc, err := credentials.LoadCCache(k.CacheName())
	if err != nil {
		return nil, trace.Wrap(err)
	}

	// Load krb5.conf.
	conf, err := config.Load(sessionCtx.Database.GetAD().Krb5File)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	// Create Kerberos client from ccache.
	kbClient, err := client.NewFromCCache(cc, conf, client.DisablePAFXFAST(true))
	if err != nil {
		return nil, trace.Wrap(err)
	}

	// Obtain service ticket for the database's Service Principal Name.
	ticket, encryptionKey, err := kbClient.GetServiceTicket(sessionCtx.Database.GetAD().SPN)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	// Create init negotiation token.
	initToken, err := spnego.NewNegTokenInitKRB5(kbClient, ticket, encryptionKey)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	// Marshal init negotiation token.
	initTokenBytes, err := initToken.Marshal()
	if err != nil {
		return nil, trace.Wrap(err)
	}

	return &krbAuth{
		initToken: initTokenBytes,
	}, nil
}

// krbAuth implements SQL Server driver's "auth" interface used during login
// to provide Kerberos authentication.
type krbAuth struct {
	initToken []byte
}

func (a *krbAuth) InitialBytes() ([]byte, error) {
	return a.initToken, nil
}

func (a *krbAuth) NextBytes(bytes []byte) ([]byte, error) {
	return nil, nil
}

func (a *krbAuth) Free() {}
