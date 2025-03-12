(ns saml20-clj.e2e.server
  (:require
   [clojure.tools.logging :as logging]
   [ring.adapter.jetty :refer [run-jetty]]
   [ring.middleware.cookies :as ring.cookies]
   [ring.middleware.params :as ring.params]
   [ring.middleware.reload :as ring.reload]
   [ring.middleware.stacktrace :as ring.stacktrace]
   [ring.util.response :as ring.resp]
   [saml20-clj.sp.logout-response :as logout-response]
   [saml20-clj.sp.request :as request]
   [saml20-clj.sp.response :as response]
   [saml20-clj.test :as test]))

(def home-page-logged-out
  (str "<html><body>"
       "<ul>"
       "<li><a id=\"keycloak\" href=\"/login?idp-type=keycloak\">Login</a></li>"
       "<li><a id=\"okta\" href=\"/login?idp-type=okta\">Login</a></li>"
       "<li><a id=\"entra\" href=\"/login?idp-type=entra\">Login</a></li>"
       "</ul>"
       "</body></html>"))
(def home-page-logged-in
  (str "<html><body>"
       "<ul>"
       "<li><a id=\"keycloak\" href=\"/logout?idp-type=keycloak\">Logout</a></li>"
       "<li><a id=\"okta\" href=\"/logout?idp-type=okta\">Logout</a></li>"
       "<li><a id=\"entra\" href=\"/logout?idp-type=entra\">Logout</a></li>"
       "</ul>"
       "</body></html>"))
(def cookie-name "COOKIE")

(defn idp-login-config
  [idp-type]
  (condp = idp-type
    :entra {:sp-name "SAMLTest"
            :acs-url "https://test-server:3001/login"
            :issuer "SAMLTest"
            :idp-url "https://login.microsoftonline.com/baac9aeb-12ed-4fe9-844f-fde9aa3fc2c7/saml2"
            :request-id "a-test-request"
            :protocol-binding :post
            :credential test/sp-private-key}
    :okta {:sp-name "SAMLTest"
           :acs-url "https://test-server:3001/login"
           :issuer "SAMLTest"
           :idp-url "https://dev-08548225.okta.com/app/dev-08548225_mbcitest_1/exknlfxer1RcyaTAS5d7/sso/saml"
           :request-id "a-test-request"
           :credential test/sp-private-key}
    :keycloak {:sp-name "SAMLTest"
               :acs-url "https://test-server:3001/login"
               :issuer "SAMLTest"
               :idp-url "http://keycloak:8080/realms/test/protocol/saml"
               :request-id "a-test-request"
               :credential test/sp-private-key}))

(defn idp-logout-config
  [idp-type]
  (condp = idp-type
    :entra {:sp-name "SAMLTest"
            :acs-url "https://test-server:3001/logout"
            :issuer "SAMLTest"
            :idp-url "https://login.microsoftonline.com/baac9aeb-12ed-4fe9-844f-fde9aa3fc2c7/saml2"
            :relay-state "entra"
            :user-email "metatest@example.com"
            :request-id "a-test-request"
            :credential test/sp-private-key}
    :okta {:sp-name "SAMLTest"
           :acs-url "https://test-server:3001/logout"
           :issuer "SAMLTest"
           :idp-url "https://dev-08548225.okta.com/app/dev-08548225_mbcitest_1/exknlfxer1RcyaTAS5d7/slo/saml"
           :relay-state "okta"
           :user-email "metatest@example.com"
           :request-id "a-test-request"
           :credential test/sp-private-key}
    :keycloak {:sp-name "SAMLTest"
               :acs-url "https://test-server:3001/logout"
               :issuer "SAMLTest"
               :idp-url "http://keycloak:8080/realms/test/protocol/saml"
               :relay-state "keycloak"
               :user-email "metatest@example.com"
               :request-id "a-test-request"
               :credential test/sp-private-key}))

(defn validation-config
  [idp-type]
  (condp = idp-type
    :entra {:idp-cert (slurp "e2e/saml20_clj/e2e/entra.cert")
            :acs-url "https://test-server:3001/login"
            :issuer "https://sts.windows.net/baac9aeb-12ed-4fe9-844f-fde9aa3fc2c7/"
            :request-id "a-test-request"}
    :okta {:idp-cert (slurp "e2e/saml20_clj/e2e/okta.cert")
           :acs-url "https://test-server:3001/login"
           :issuer "http://www.okta.com/exknlfxer1RcyaTAS5d7"
           :request-id "a-test-request"}
    :keycloak {:idp-cert test/idp-cert
               :acs-url "https://test-server:3001/login"
               :issuer "http://keycloak:8080/realms/test"
               :request-id "a-test-request"}))

(defn serve-home
  [cookie]
  (let [body (if (get cookie cookie-name)
               home-page-logged-in
               home-page-logged-out)]
    (logging/debug "Serving Home")
    (-> {:status 200
         :body body}
        (ring.resp/content-type "text/html")
        (ring.resp/charset "utf-8"))))

(defmulti handle-login (fn [method _] method))
(defmulti handle-logout (fn [method _] method))

(defmethod handle-logout :get [_ request]
  (if-let [idp-type (get-in request [:params "idp-type"])]
    (request/idp-logout-redirect-response (idp-logout-config (keyword idp-type)))
    (handle-logout :post request)))

(defmethod handle-logout :post [_ request]
  (when (logout-response/validate-logout request
                                         (-> (get-in request [:params "RelayState"])
                                             keyword
                                             validation-config))
    (-> (ring.resp/redirect "/")
        (ring.resp/set-cookie cookie-name nil {:expires "Thu, 1 Jan 1970 00:00:00 GMT"}))))

(defmethod handle-login :get [_ request]
  (if-let [idp-type (get-in request [:params "idp-type"])]
    (request/idp-redirect-response (assoc (idp-login-config (keyword idp-type)) :relay-state idp-type))
    (handle-login :post request)))

(defmethod handle-login :post [_ request]
  (when (response/validate-response request
                                    (-> (get-in request [:params "RelayState"])
                                        keyword
                                        validation-config))
    (-> (ring.resp/redirect "/")
        (ring.resp/set-cookie cookie-name "true"))))

(defn handler
  [{:keys [uri cookies request-method] :as request}]
  (condp = uri
    "/" (serve-home cookies)
    "/login" (handle-login request-method request)
    "/logout" (handle-logout request-method request)
    {:status 404}))

(defn start-server
  []
  (logging/debug "Starting server")
  (run-jetty (-> handler
                 ring.cookies/wrap-cookies
                 ring.params/wrap-params
                 ring.stacktrace/wrap-stacktrace
                 (ring.reload/wrap-reload {:dirs ["src" "test" "e2e"]}))
             {:ssl? true
              :ssl-port 3001
              :port 3002
              :keystore "e2e/saml20_clj/e2e/keystore.jks"
              :key-password "testpassword"}))

(defn -main
  []
  (start-server))
