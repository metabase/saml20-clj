(ns saml20-clj.e2e.server-test
  (:require [clojure.test :as t]
            [etaoin.api :as etaoin]))

(def ^:private test-overrides
  {:entra {:username "metatest@luizarakakimetabase.onmicrosoft.com"
           :password "ThisMustBeThePassword2!" }})

;; Okta is excluded: the free developer org backing these tests
;; (dev-08548225.okta.com) has been deactivated, so its sign-in page answers every
;; credential submit with "This developer org has been deactivated." Re-add :okta here
;; once a live org is provisioned and its credentials are wired up.
(t/deftest test-saml-login-logout
  (doseq [provider [:keycloak]]
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
