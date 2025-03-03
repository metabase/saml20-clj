(ns saml20-clj.crypto-test
  (:require [clojure.test :refer :all]
            [saml20-clj.coerce :as coerce]
            [saml20-clj.crypto :as crypto]
            [saml20-clj.test :as test])
  (:import org.opensaml.saml.common.messaging.context.SAMLPeerEntityContext))

(deftest assert-signature-invalid-swapped-signature
  (doseq [{:keys [response], :as response-map} (test/responses)
          :when (test/malicious-signature? response-map)]
    (testing (test/describe-response-map response-map)
      (is (thrown-with-msg?
           clojure.lang.ExceptionInfo
           #"Signature does not match credential"
           (crypto/assert-signature-valid-when-present response test/idp-cert))))))

(deftest has-private-key-test
  (testing "has private key"
    (is (= true (crypto/has-private-key? {:filename test/keystore-filename
                                          :password test/keystore-password
                                          :alias    "sp"})))

    (is (= true (crypto/has-private-key? test/sp-private-key)))

    (testing "has only public key"
      (is (= false (crypto/has-private-key? {:filename test/keystore-filename
                                             :password test/keystore-password
                                             :alias    "idp"}))))))

(deftest handle-signature-security-test
  (testing "with signed LogoutResponse POST bindings"
    (let [request (test/ring-logout-response-post :success "relay-state" :signature true)
          msg-ctx (coerce/ring-request->MessageContext request)]
      (crypto/handle-signature-security msg-ctx request "http://idp.example.com/metadata.php" test/idp-cert)
      (is (.isAuthenticated (.getSubcontext msg-ctx SAMLPeerEntityContext)))))

  (testing "with signed LogoutResponse Redirect bindings"
    (let [request (test/ring-logout-response-get :success :signature true)
          msg-ctx (coerce/ring-request->MessageContext request)]
      (crypto/handle-signature-security msg-ctx request "http://idp.example.com/metadata.php" test/idp-cert)
      (is (.isAuthenticated (.getSubcontext msg-ctx SAMLPeerEntityContext)))))

  (testing "with unsigned LogoutResponse POST bindings"
    (let [request (test/ring-logout-response-post :success "relay-state" :signature false)
          msg-ctx (coerce/ring-request->MessageContext request)]
      (crypto/handle-signature-security msg-ctx request "http://idp.example.com/metadata.php" test/idp-cert)
      (is (not (.isAuthenticated (.getSubcontext msg-ctx SAMLPeerEntityContext))))))

  (testing "with unsigned LogoutResponse Redirect bindings"
    (let [request (test/ring-logout-response-get :success :signature false)
          msg-ctx (coerce/ring-request->MessageContext request)]
      (crypto/handle-signature-security msg-ctx request "http://idp.example.com/metadata.php" test/idp-cert)
      (is (not (.isAuthenticated (.getSubcontext msg-ctx SAMLPeerEntityContext)))))))
