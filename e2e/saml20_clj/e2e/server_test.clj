(ns saml20-clj.e2e.server-test
  (:require [clojure.test :as t]
            [etaoin.api :as etaoin]))

(t/deftest test-saml-login-logout
  (doseq [provider [:okta
                    :keycloak]]
    (etaoin/with-chrome
        {:port 4444
         :host "localhost"
         :args ["--no-sandbox"
                "--ignore-ssl-errors=yes"
                "--ignore-certificate-errors"]
         :capabilities {"acceptInsecureCerts" true}}
        driver
        (t/testing "full saml login/logout flow"
          (etaoin/go driver "https://test-server:3001")
          (t/is (etaoin/visible? driver {:tag :a :id provider :fn/has-text "Login"}))
          (etaoin/click driver {:tag :a :id provider})
          (etaoin/wait-visible driver {:tag :input :name :username})
          (etaoin/fill driver {:tag :input :name :username} "metatest@example.com")
          (etaoin/fill driver {:tag :input :name :password} "thismustbetheotherpassword")
          (etaoin/click driver {:type :submit})
          (etaoin/wait-visible driver {:tag :a :id provider})
          (t/is (etaoin/visible? driver {:tag :a :id provider :fn/has-text "Logout"}))
          (etaoin/click driver {:tag :a :id provider})
          (etaoin/wait-visible driver {:tag :a :fn/has-text "Login"})
          (t/is (etaoin/visible? driver {:tag :a :id provider :fn/has-text "Login"}))))))
