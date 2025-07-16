(ns saml20-clj.opensaml-context-test
  (:require [clojure.test :refer :all]
            [saml20-clj.opensaml-context :as ctx]
            [saml20-clj.coerce :as coerce])
  (:import [org.opensaml.messaging.context MessageContext]
           [org.opensaml.xmlsec.context SecurityParametersContext]
           [org.opensaml.saml.common.messaging.context SAMLPeerEntityContext]
           [org.opensaml.security.credential Credential]
           [org.opensaml.security.credential.impl CollectionCredentialResolver]
           [org.opensaml.xmlsec.signature.support.impl ExplicitKeySignatureTrustEngine]
           [org.opensaml.xmlsec SignatureValidationParameters]))

(def test-cert
  "-----BEGIN CERTIFICATE-----
MIICmzCCAYMCBgF4G12X6TANBgkqhkiG9w0BAQsFADARMQ8wDQYDVQQDDAZtYXN0
ZXIwHhcNMjEwMzEwMTcxMjU5WhcNMzEwMzEwMTcxNDM5WjARMQ8wDQYDVQQDDAZt
YXN0ZXIwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDFMtAM1r0eQBJi
NWqCXBq9uN5Fa6wLNWkRx4Hq9zLv6oqNwlxBkYC+VpVnV0JJFwXHJV/DUVEpjxkZ
2oLMANZNQiowQ5r9RBcJSTCYSLli+dAButnBOUSYUvxPk+aVMUy7n2kPNPnZKoI2
LBh9hE8VmLHrVMnMAt4XQfzT2lQ7LoHVxGrBEf6FTDaxIO8mPPCxLVHZrhy0jKFl
y9xGIsHhNhFimESFLZKSH+dFLXAW5rGeHf1hjI+xhNTJuq1MjBDFUHqvw6xCLTy5
fMjrqxG7RKlKmZ5b6hPRlNItiGPq8WzPxZLCMQZ1RLhiVuVmQ9EP6rLHOa5Ps0hL
H1BhUPs3AgMBAAEwDQYJKoZIhvcNAQELBQADggEBAJi5Cb7g1YCVXD5vgk9mE4fJ
8F5UJQ8G4GkHvAJN0Ce13fGzAl8Cx7kfihPaJABbh+3xe0BXHk6hNdcl8EHF8iFl
i4AjmY6TkLKaSxQEN6zF9gvKMpzxCCIIB6BWv0bAaeDXK1xHKjBODkNMGELRhQ1h
sLOg7f1AxePCvhGHSfJNK2BKP9fKnv8T47Cc3gsFVcQM2Z2xgpBcKyhUJdGCCPK2
LPPq20fQXZ46Li8bcoKkN+6YqVzjzWPKZ/N8sZPfk5pItCLUV0P5bG0VC3KGvlvx
4Gq1WmXhO2WvBexSI9LV5sHKrKaUlinHCKKS4r7bzHSYZVOkYtLVQvCB8av6rA0=
-----END CERTIFICATE-----")

(def test-private-key
  "-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAxTLQDNa9HkASYjVqglwavbjeRWusCzVpEceB6vcy7+qKjcJc
QZGA8Qjfiy1p8djEejwqP4S7a+2hVJg72/Y8ktUdCCeglnmNbCrXBMxQ48SmwjyT
WaQYs3pJRnGzuxXTQwHON8LcUedRCtjrBcNZEpK5Z5wJJEaYyJ2F6nczB0vJTt6A
zqeFShgy3/Nkp1Prg7Uoq6kCqQXBEaDsMJ3HkEX7F9pVJhD7IDiYoT1yRBf7Gmdc
AXd0qT6Fg0e3vyj5FFRiDObbxKLs5FAQcl0NH2h0ijcvMpSZP2vo1S9K8sNPbdmx
ecvCDwUctYN2MjJxXdJHqNHQnqh+lIeFwgYzZQIDAQABAoIBABGk//9XX8j3j0TM
0LAMl3aXenL9OkirjHSeqFQvCB7xMBPxoz1vhj1C2dGRa7aHJ3TLFcw5gj+M5V9s
cjsVN0bxPRhoNNuTSPp+C7vx0bOEB9nwNxp8cg9lxBAT9qu8Y75v08KQF0LlNqHp
84V8f9h6JV2gFnhLcbw3P0hqDkcuXX3/OLGhY5MWhhBBKBPKLMAM2p2mZwrI1w3w
jNrxVMm9P6/v6Vi+LQN0vBX/9DuFMVMo7isaKqJ5w4tZL0yyLORKsX1MmVZszKZk
lT3wNcrH3sNkHnEadC9fCFQzjFyQVoHXjDSFGcDEMpfPA8hhQuMwFcTR9730DW/5
/d7spekCgYEA6l7Y0kydb7Y5xrYyJ4bz5+rvxQvmOSrH0pVZCAT7D/b8HqCYUW5s
dausXPEONXR6LmXPK1RCNNQdlTKKOuSSCMsgGN35ZnDHiTmN4I9fqH21A5dnFwgB
CxgEakWHe9F5vDsVJx5EQdOC/fWHZ2xLNsdMogqxNASzL6r6E8m2bZMCgYEA16tm
MH3zVvRPuK/6Mlmsvsp/dCCqCC9XbhqLO/oJg+rcGaC4b3TZ9w8fWgEKPRfzIWdR
cJKy75l3eWth4cEpprxb3VdlXztFTSkF3AMYPUnJFel3HaUfFZUIBnF5GKNge3Ue
dJa8xugzaQJffz3/1XXtsJ5NoMmfTF5e4j8+hrcCgYAlOzaAcqb9H8LAhkKKjPqz
2THux7g+6fPFYjweS7JYob6VpPKmBDDOa6r5XlqroBDgGEV/Aen2fDSDSNl3qZMv
r2dYEwLvOdetT0qmnGXDSLB2oHqAC5M0ScWVPDJZaInyLWkqBut1BMdjfPR3UCpB
E/1loGCvfXpTO8urNo3nvwKBgQDCtE8CwLVckFHRg9QU0xAqJt1TdZGGLYg+xWh6
zlW7TBjWvOQ31RRnYkP7kVtKGLch4lE7RHcnRuntN9LiIHqvFOqP/JAVnNF3Sw5L
FG5FwpKDzb1+68njsHPuqMqvQqpIL0HxMC3TV8qKrO7WIFJPzwr5SG5RNhusBXG0
7leoJQKBgEsppwwp7qSaZLz5ecsFbaRLfMSd8sQp2re9TcNV7vObbqPmYD9RVxym
cNHDr5xLirbLcjFD+xpaTMPHEqaKlYYCPDwZJDy3zBCMxoI1vkU7WRf5S0YP/CeH
LbB7p5FPG8XXCMl7kDfQj0OpQwX3LCa0HABVr3TMQHF9R6cNkYpJ
-----END RSA PRIVATE KEY-----")

(deftest create-credential-resolver-test
  (testing "Creating credential resolver from certificates"
    (let [certs [test-cert]
          resolver (ctx/create-credential-resolver certs)]
      (is (instance? CollectionCredentialResolver resolver))
      (is (seq (.resolve resolver nil))))))

(deftest create-trust-engine-test
  (testing "Creating trust engine from IdP certificate"
    (let [trust-engine (ctx/create-trust-engine test-cert)]
      (is (instance? ExplicitKeySignatureTrustEngine trust-engine)))))

(deftest create-signature-validation-params-test
  (testing "Creating signature validation parameters"
    (let [sig-params (ctx/create-signature-validation-params test-cert)]
      (is (instance? SignatureValidationParameters sig-params))
      (is (some? (.getSignatureTrustEngine sig-params))))))

;; Decryption tests removed - DecryptionParameters not available in OpenSAML 5 

(deftest create-security-parameters-context-test
  (testing "Creating security parameters context with cert"
    (let [options {:idp-cert test-cert}
          sec-ctx (ctx/create-security-parameters-context options)]
      (is (instance? SecurityParametersContext sec-ctx))
      (is (some? (.getSignatureValidationParameters sec-ctx))))))

(deftest enhance-message-context-test
  (testing "Enhancing message context with security parameters"
    (let [msg-ctx (MessageContext.)
          options {:idp-cert test-cert}
          enhanced-ctx (ctx/enhance-message-context msg-ctx options)]
      (is (identical? msg-ctx enhanced-ctx))
      (is (some? (.getSubcontext enhanced-ctx SecurityParametersContext))))))

(deftest get-peer-entity-context-test
  (testing "Getting existing peer entity context"
    (let [msg-ctx (MessageContext.)
          peer-ctx (SAMLPeerEntityContext.)]
      (.addSubcontext msg-ctx peer-ctx)
      (is (identical? peer-ctx (ctx/get-peer-entity-context msg-ctx)))))

  (testing "Creating new peer entity context when none exists"
    (let [msg-ctx (MessageContext.)
          peer-ctx (ctx/get-peer-entity-context msg-ctx)]
      (is (instance? SAMLPeerEntityContext peer-ctx))
      (is (identical? peer-ctx (.getSubcontext msg-ctx SAMLPeerEntityContext))))))

(deftest set-peer-entity-id-test
  (testing "Setting peer entity ID"
    (let [msg-ctx (MessageContext.)
          entity-id "http://idp.example.com"]
      (ctx/set-peer-entity-id msg-ctx entity-id)
      (let [peer-ctx (.getSubcontext msg-ctx SAMLPeerEntityContext)]
        (is (= entity-id (.getEntityId peer-ctx))))))

  (testing "Setting nil entity ID does nothing"
    (let [msg-ctx (MessageContext.)]
      (ctx/set-peer-entity-id msg-ctx nil)
      (is (nil? (.getSubcontext msg-ctx SAMLPeerEntityContext))))))

(deftest get-security-parameters-test
  (testing "Getting security parameters from context"
    (let [msg-ctx (MessageContext.)
          sec-ctx (SecurityParametersContext.)]
      (.addSubcontext msg-ctx sec-ctx)
      (is (identical? sec-ctx (ctx/get-security-parameters msg-ctx)))))

  (testing "Getting nil when no security parameters"
    (let [msg-ctx (MessageContext.)]
      (is (nil? (ctx/get-security-parameters msg-ctx))))))

(deftest get-signature-trust-engine-test
  (testing "Getting signature trust engine from context"
    (let [msg-ctx (MessageContext.)
          options {:idp-cert test-cert}
          _ (ctx/enhance-message-context msg-ctx options)
          trust-engine (ctx/get-signature-trust-engine msg-ctx)]
      (is (some? trust-engine))
      (is (instance? ExplicitKeySignatureTrustEngine trust-engine))))

  (testing "Getting nil when no security parameters"
    (let [msg-ctx (MessageContext.)]
      (is (nil? (ctx/get-signature-trust-engine msg-ctx))))))

(deftest integration-test
  (testing "Full integration of context creation and usage"
    (let [msg-ctx (MessageContext.)
          entity-id "http://idp.example.com"
          options {:idp-cert test-cert}]
      ;; Enhance context
      (ctx/enhance-message-context msg-ctx options)
      (ctx/set-peer-entity-id msg-ctx entity-id)

      ;; Verify everything is set up correctly
      (let [peer-ctx (.getSubcontext msg-ctx SAMLPeerEntityContext)
            sec-ctx (.getSubcontext msg-ctx SecurityParametersContext)
            sig-params (.getSignatureValidationParameters sec-ctx)]
        (is (= entity-id (.getEntityId peer-ctx)))
        (is (some? sig-params))
        (is (some? (.getSignatureTrustEngine sig-params)))))))

(deftest edge-case-tests
  (testing "Handling invalid inputs gracefully"
    (testing "Empty certificate list"
      (let [resolver (ctx/create-credential-resolver [])]
        (is (instance? CollectionCredentialResolver resolver))
        (is (empty? (.resolve resolver nil)))))

    (testing "Multiple certificates"
      (let [certs [test-cert test-cert]
            resolver (ctx/create-credential-resolver certs)]
        (is (= 2 (count (.resolve resolver nil))))))

    (testing "Enhancing already enhanced context is idempotent"
      (let [msg-ctx (MessageContext.)
            options {:idp-cert test-cert}]
        (ctx/enhance-message-context msg-ctx options)
        (let [first-ctx (.getSubcontext msg-ctx SecurityParametersContext)]
          (ctx/enhance-message-context msg-ctx options) ; Enhance again
          (let [second-ctx (.getSubcontext msg-ctx SecurityParametersContext)]
            (is (identical? first-ctx second-ctx))))))

    (testing "Getting trust engine from unenhanced context"
      (let [msg-ctx (MessageContext.)]
        (is (nil? (ctx/get-signature-trust-engine msg-ctx)))))))
