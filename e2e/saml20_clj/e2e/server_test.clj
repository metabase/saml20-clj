(ns saml20-clj.e2e.server-test
  (:require [clojure.test :as t]
            [etaoin.api :as etaoin]))

(def ^:private test-overrides
  {:entra {:username "metatest@luizarakakimetabase.onmicrosoft.com"
           :password "ThisMustBeThePassword2!" }
   ;; Okta's default password policy rejects the all-lowercase default below
   ;; (it wants an uppercase letter and a digit), so this org's test user has its own.
   :okta  {:username "metatest@example.com"
           :password "Thismustbetheotherpassword1"}})

(defn- sign-in!
  "Enter `username` and `password` on whichever sign-in form the IdP presented.

  Okta's Identity Engine widget asks for the username first and the password on a second
  screen, and names the fields `identifier` and (nothing stable) rather than `username` and
  `password`. Keycloak still serves a single classic form."
  [driver username password]
  (if (etaoin/exists? driver {:tag :input :name :identifier})
    (do
      (etaoin/wait-visible driver {:tag :input :name :identifier})
      (etaoin/fill driver {:tag :input :name :identifier} username)
      (etaoin/click driver {:type :submit})
      (etaoin/wait-visible driver {:css "input[type=password]"})
      (etaoin/fill driver {:css "input[type=password]"} password)
      (etaoin/click driver {:type :submit}))
    (do
      (etaoin/wait-visible driver {:tag :input :name :username})
      (etaoin/fill driver {:tag :input :name :username} username)
      (etaoin/fill driver {:tag :input :name :password} password)
      (etaoin/click driver {:type :submit}))))

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
          (etaoin/wait-visible driver {:css "input[type=text], input[type=email]"})
          (sign-in! driver
                    (get-in test-overrides [provider :username] "metatest@example.com")
                    (get-in test-overrides [provider :password] "thismustbetheotherpassword"))
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
