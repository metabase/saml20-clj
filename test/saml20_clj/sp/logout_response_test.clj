(ns saml20-clj.sp.logout-response-test
  (:require [clojure.test :as t]
            [saml20-clj.sp.logout-response :as sut]
            [saml20-clj.test :as test]))

(t/deftest test-validate-response
  (t/testing "raise with an incorrect issuer response"
    (let [response (test/ring-logout-response :success "relay-state")
          exception (try
                      (sut/validate-logout response test/logout-request-id "http://idp.incorrect.example.org/" test/idp-cert)
                      (catch clojure.lang.ExceptionInfo e
                        {:msg (ex-message e) :data (ex-data e)}))]
      (t/is (not  (instance? org.opensaml.saml.saml2.core.LogoutResponse
                             exception)))
      (t/is (= {:msg "LogoutResponse failed to validate issuer"
                :data {:validator :issuer
                       :expected "http://idp.incorrect.example.org/"
                       :actual "http://idp.example.com/metadata.php"}}
               exception))))
  (t/testing "raise with a broken signature response"
    (let [response (test/ring-logout-response :success "relay-state" :signature :bad)
          exception (try
                      (sut/validate-logout response test/logout-request-id test/logout-issuer-id test/idp-cert)
                      (catch clojure.lang.ExceptionInfo e
                        {:msg (ex-message e) :data (ex-data e)}))]
      (t/is (not  (instance? org.opensaml.saml.saml2.core.LogoutResponse
                             exception)))
      (t/is (= {:msg "LogoutResponse failed to validate signature"
                :data {:validator :signature}}
               exception))))
  (t/testing "raise with an unsigned response"
    (let [response (test/ring-logout-response :success "relay-state" :signature false)
          exception (try
                      (sut/validate-logout response test/logout-request-id test/logout-issuer-id test/idp-cert)
                      (catch clojure.lang.ExceptionInfo e
                        {:msg (ex-message e) :data (ex-data e)}))]
      (t/is (not  (instance? org.opensaml.saml.saml2.core.LogoutResponse
                             exception)))
      (t/is (= {:msg "LogoutResponse is not Authenticated"
                :data {:validator :require-authenticated
                       :is-authenticated false}}
               exception))))
  (t/testing "returns a logout-response without raising"
    (let [response (test/ring-logout-response :success "relay-state")]
      (t/is (instance? org.opensaml.saml.saml2.core.LogoutResponse
                       (sut/validate-logout response test/logout-request-id test/logout-issuer-id test/idp-cert))))))

(t/deftest test-success?
  (t/testing "when the logout-response is successful"
    (let [response (-> (test/ring-logout-response :success "relay-state")
                       (sut/validate-logout test/logout-request-id test/logout-issuer-id test/idp-cert))]
      (t/is (sut/success? response))))
  (t/testing "when the logout-response is not successful"
    (let [response (-> (test/ring-logout-response :authnfailed "relay-state")
                       (sut/validate-logout test/logout-request-id test/logout-issuer-id test/idp-cert))]
      (t/is (not (sut/success? response))))))
