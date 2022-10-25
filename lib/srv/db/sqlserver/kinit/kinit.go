// Copyright 2022 Gravitational, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package kinit provides utilities for interacting with a KDC (Key Distribution Center) for Kerberos5, or krb5, to allow
// teleport to connect to sqlserver using x509 certificates.
package kinit

import (
	"context"
	"errors"
	"fmt"
	"github.com/gravitational/teleport/api/types"
	"github.com/gravitational/teleport/lib/auth"
	"github.com/gravitational/teleport/lib/srv/desktop"
	"github.com/gravitational/trace"
	"github.com/sirupsen/logrus"
	"os"
	"os/exec"
	"time"
)

/*
//#cgo CFLAGS: -g -Wno-deprecated-declarations
//#cgo LDFLAGS: -L -lgssapi_krb5 -lkrb5 -lk5crypto -libkrb5support
//#include "kinit.c"
*/
//import "C"

//func KInit(ca, userCert, userKey, cacheName string) error {
//	ret := C.kinit(C.CString(ca), C.CString(userCert), C.CString(userKey), C.CString(cacheName))
//	if ret != C.KDC_ERR_NONE {
//		return trace.Wrap(fmt.Errorf("error returned from kinit: %d", int(ret)))
//	}
//	return nil
//}

const (
	DefaultKRBConfig = "/etc/krb5.conf"
	KRB5ConfigEnv    = "KRB5_CONFIG"
)

type KInit struct {
	AuthClient auth.ClientI

	UserName  string
	CacheName string

	RealmName string

	KDCHostName     string
	AdminServerName string

	CertPath string
	KeyPath  string

	Log logrus.FieldLogger
}

func New(authClient auth.ClientI, user, realm, kdcHost, adminServer string) *KInit {
	return &KInit{
		AuthClient:      authClient,
		UserName:        user,
		CacheName:       fmt.Sprintf("%s@%s", user, realm),
		RealmName:       realm,
		KDCHostName:     kdcHost,
		AdminServerName: adminServer,

		CertPath: fmt.Sprintf("%s.pem", user),
		KeyPath:  fmt.Sprintf("%s-key.pem", user),
		Log:      logrus.StandardLogger(),
	}
}

// CreateOrAppendCredentialsCache creates or appends to an existing credentials cache.
func (k *KInit) CreateOrAppendCredentialsCache(ctx context.Context) error {

	certPath := fmt.Sprintf("%s.pem", k.UserName)
	keyPath := fmt.Sprintf("%s-key.pem", k.UserName)
	userCAPath := "userca.pem"

	clusterName, err := k.AuthClient.GetClusterName()
	if err != nil {
		return trace.Wrap(err)
	}

	certPEM, keyPEM, err := desktop.WindowsCertKeyPEM(ctx, k.UserName, k.RealmName, time.Second*60*60, clusterName.GetClusterName(), desktop.LDAPConfig{
		Addr:               k.KDCHostName,
		Domain:             k.RealmName,
		Username:           k.UserName,
		InsecureSkipVerify: true, // TODO set to false and provide LDAP CA
		ServerName:         k.KDCHostName,
		CA:                 nil,
	}, k.AuthClient)

	userCA, err := k.AuthClient.GetCertAuthority(ctx, types.CertAuthID{
		Type:       types.UserCA,
		DomainName: clusterName.GetClusterName(),
	}, true)
	if err != nil {
		return trace.Wrap(err)
	}

	var caCert []byte
	keyPairs := userCA.GetActiveKeys().TLS
	for _, keyPair := range keyPairs {
		if keyPair.KeyType == types.PrivateKeyType_RAW {
			caCert = keyPair.Cert
		}
	}

	if caCert == nil {
		return trace.Wrap(errors.New("no certificate authority was found in userCA active keys"))
	}

	// TODO remove all files
	err = os.WriteFile(certPath, certPEM, 0644)
	if err != nil {
		return trace.Wrap(err)
	}

	err = os.WriteFile(keyPath, keyPEM, 0644)
	if err != nil {
		return trace.Wrap(err)
	}

	err = os.WriteFile(userCAPath, caCert, 0644)
	if err != nil {
		return trace.Wrap(err)
	}

	krbConfPath := fmt.Sprintf("krb_%s", k.UserName)
	err = k.WriteKRB5Config(krbConfPath)
	if err != nil {
		return trace.Wrap(err)
	}

	cmd := exec.CommandContext(ctx,
		"kinit",
		"-X", fmt.Sprintf("X509_anchors=FILE:%s", userCAPath),
		"-X", fmt.Sprintf("X509_user_identity=FILE:%s,%s", certPath, keyPath), k.UserName,
		"-c", k.CacheName)
	cmd.Env = append(os.Environ(), []string{fmt.Sprintf("%s=%s", KRB5ConfigEnv, krbConfPath)}...)

	data, err := cmd.CombinedOutput()
	if err != nil {
		return trace.Wrap(err)
	}
	// todo better error handling from output/fully wrap libkrb5 for linux
	k.Log.Debug(string(data))
	return nil
}

// krb5ConfigString returns a config suitable for a kdc
func (k *KInit) krb5ConfigString() string {
	return fmt.Sprintf(`[libdefaults]
 default_realm = %s
 rdns = false


[realms]
 %s = {
  kdc = %s
  admin_server = %s
  pkinit_eku_checking = kpServerAuth
  pkinit_kdc_hostname = %s
 }`, k.RealmName, k.RealmName, k.KDCHostName, k.AdminServerName, k.KDCHostName)
}

func (k *KInit) WriteKRB5Config(path string) error {
	return os.WriteFile(path, []byte(k.krb5ConfigString()), 0644)
}
