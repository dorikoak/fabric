/*
Copyright IBM Corp. 2017 All Rights Reserved.

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

package msp

import (
	"bytes"
	"crypto/ecdsa"	// 타원 곡선 알고리즘이 구현된 패키지,
	"crypto/x509"	// x.509로 인코딩된 키와 인증서를 분석하는 패키지
	// CRL(인증서 폐기 목록), OCSP (온라인 인증서 상태 프로토콜)
	"crypto/x509/pkix"	// CRL, OCSP의 ASN.1 구문 분석 및 직렬화에 사용되는 구조가 포함된 패키지
	// 인증서 인코딩 방식
	"encoding/asn1"	// 추상 구문 기법?
	"encoding/pem"	// 인증서 파일 포멧
	"fmt"
	"math/big"
	"time"

	"github.com/hyperledger/fabric/bccsp/utils"	// 타원 곡선 알고리즘을 통한 서명 구현
	"github.com/pkg/errors"
)

type validity struct {	 
	NotBefore, NotAfter time.Time
}

type publicKeyInfo struct { 	// 공개키 정보
	Raw       asn1.RawContent	// 바이트 배열
	Algorithm pkix.AlgorithmIdentifier	
	PublicKey asn1.BitString	// 비트 문자열 변수 선언
}

type certificate struct {		// 인증서
	Raw                asn1.RawContent	// 바이트 배열	
	TBSCertificate     tbsCertificate	// tbsCertificate 객체 생성
	SignatureAlgorithm pkix.AlgorithmIdentifier	
	SignatureValue     asn1.BitString	
}

type tbsCertificate struct { 	//tbs 인증서..?
	Raw                asn1.RawContent	// 바이트 배열	
	Version            int `asn1:"optional,explicit,default:0,tag:0"`	
	SerialNumber       *big.Int		
	SignatureAlgorithm pkix.AlgorithmIdentifier	
	Issuer             asn1.RawValue	
	Validity           validity	
	Subject            asn1.RawValue	
	PublicKey          publicKeyInfo	// 공개키 정보
	UniqueId           asn1.BitString   `asn1:"optional,tag:1"`	
	SubjectUniqueId    asn1.BitString   `asn1:"optional,tag:2"`	
	Extensions         []pkix.Extension `asn1:"optional,explicit,tag:3"`	
}

func isECDSASignedCert(cert *x509.Certificate) bool {	// ECDSA를 통해 서명되었는지 확인
	return cert.SignatureAlgorithm == x509.ECDSAWithSHA1 ||
		cert.SignatureAlgorithm == x509.ECDSAWithSHA256 ||
		cert.SignatureAlgorithm == x509.ECDSAWithSHA384 ||
		cert.SignatureAlgorithm == x509.ECDSAWithSHA512
}

// sanitizeECDSASignedCert checks that the signatures signing a cert
// is in low-S. This is checked against the public key of parentCert.
// If the signature is not in low-S, then a new certificate is generated
// that is equals to cert but the signature that is in low-S.
// Low-S를 통해 서명되었는지 확인
func sanitizeECDSASignedCert(cert *x509.Certificate, parentCert *x509.Certificate) (*x509.Certificate, error) {
	if cert == nil {
		return nil, errors.New("certificate must be different from nil")
	}
	if parentCert == nil {
		return nil, errors.New("parent certificate must be different from nil")
	}

	expectedSig, err := utils.SignatureToLowS(parentCert.PublicKey.(*ecdsa.PublicKey), cert.Signature)
	if err != nil {
		return nil, err
	}

	// if sig == cert.Signature, nothing needs to be done
	if bytes.Equal(cert.Signature, expectedSig) {
		return cert, nil
	}
	// otherwise create a new certificate with the new signature

	// 1. Unmarshal cert.Raw to get an instance of certificate,
	//    the lower level interface that represent an x509 certificate
	//    encoding
	var newCert certificate
	newCert, err = certFromX509Cert(cert)
	if err != nil {
		return nil, err
	}

	// 2. Change the signature
	newCert.SignatureValue = asn1.BitString{Bytes: expectedSig, BitLength: len(expectedSig) * 8}

	// 3. marshal again newCert. Raw must be nil
	newCert.Raw = nil
	newRaw, err := asn1.Marshal(newCert)
	if err != nil {
		return nil, errors.Wrap(err, "marshalling of the certificate failed")
	}

	// 4. parse newRaw to get an x509 certificate
	return x509.ParseCertificate(newRaw)
}

func certFromX509Cert(cert *x509.Certificate) (certificate, error) {
	var newCert certificate
	_, err := asn1.Unmarshal(cert.Raw, &newCert)
	if err != nil {
		return certificate{}, errors.Wrap(err, "unmarshalling of the certificate failed")
	}
	return newCert, nil
}

// String returns a PEM representation of a certificate
func (c certificate) String() string {
	b, err := asn1.Marshal(c)
	if err != nil {
		return fmt.Sprintf("Failed marshaling cert: %v", err)
	}
	block := &pem.Block{
		Bytes: b,
		Type:  "CERTIFICATE",
	}
	b = pem.EncodeToMemory(block)
	return string(b)
}

// certToPEM converts the given x509.Certificate to a PEM
// encoded string
func certToPEM(certificate *x509.Certificate) string {
	cert, err := certFromX509Cert(certificate)
	if err != nil {
		mspIdentityLogger.Warning("Failed converting certificate to asn1", err)
		return ""
	}
	return cert.String()
}
