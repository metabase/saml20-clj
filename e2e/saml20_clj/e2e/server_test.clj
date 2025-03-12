(ns saml20-clj.e2e.server-test
  (:require [clojure.test :as t]
            [etaoin.api :as etaoin]))

(def ^:private test-overrides
  {:entra {:username "metatest@luizarakakimetabase.onmicrosoft.com"
           :password "ThisMustBeThePassword2!" }})

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
          (etaoin/fill driver {:tag :input :name :username}
                       (get-in test-overrides [provider :username] "metatest@example.com"))
          (etaoin/fill driver {:tag :input :name :password}
                       (get-in test-overrides [provider :password] "thismustbetheotherpassword"))
          (etaoin/click driver {:type :submit})
          (etaoin/wait-visible driver {:tag :a :id provider})
          (t/is (etaoin/visible? driver {:tag :a :id provider :fn/has-text "Logout"}))
          (etaoin/click driver {:tag :a :id provider})
          (etaoin/wait-visible driver {:tag :a :fn/has-text "Login"})
          (t/is (etaoin/visible? driver {:tag :a :id provider :fn/has-text "Login"}))))))


(t/deftest test-saml-login-logout-entra
  (let [provider :entra]
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
          (etaoin/wait-visible driver {:tag :input :name :loginfmt})
          (etaoin/fill driver {:tag :input :name :loginfmt}
                       (get-in test-overrides [provider :username] "metatest@example.com"))
          (etaoin/click driver {:type :submit})
          (etaoin/wait-visible driver {:tag :input :name :passwd})
          (etaoin/fill driver {:tag :input :name :passwd}
                       (get-in test-overrides [provider :password] "thismustbetheotherpassword"))
          (etaoin/click driver {:type :submit})
          (etaoin/wait-visible driver {:type :submit})
          (etaoin/click driver {:type :submit})
          (etaoin/wait-visible driver {:tag :a :id provider})
          (t/is (etaoin/visible? driver {:tag :a :id provider :fn/has-text "Logout"}))
          (etaoin/click driver {:tag :a :id provider})
          (etaoin/wait-visible driver {:tag :a :fn/has-text "Login"})
          (t/is (etaoin/visible? driver {:tag :a :id provider :fn/has-text "Login"}))))))
