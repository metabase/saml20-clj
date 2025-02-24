(ns saml20-clj.sp.logout-response-test
  (:require [clojure.test :as t]
            [saml20-clj.sp.logout-response :as sut]
            [saml20-clj.test :as test]))

(t/deftest validate-response
  (t/testing "returns a logout-response without raising"
    (let [response (test/ring-logout-response :success "relay-state")]
      (t/is (instance? org.opensaml.saml.saml2.core.LogoutResponse
                       (sut/validate-logout response test/idp-cert)))))
  (t/testing "raises when the logout-response is not successful"
    (let [response (test/ring-logout-response :authnfailed "relay-state")
          exception (try (sut/validate-logout response test/idp-cert)
                         (catch clojure.lang.ExceptionInfo e
                           {:msg (ex-message e) :data (ex-data e)}))]
      (t/is (not (instance? org.opensaml.saml.saml2.core.LogoutResponse
                            exception)))
      (t/is (= {:msg "LogoutResponse <Status> was not Success"
                :data {:status-value org.opensaml.saml.saml2.core.StatusCode/AUTHN_FAILED}}
               exception)))))
