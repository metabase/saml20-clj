(ns saml20-clj.specs
  (:require [clojure.spec.alpha :as s]
            [saml20-clj
             [coerce :as coerce]
             [state :as state]]
            [saml20-clj.sp
             [metadata :as metadata]
             [request :as request]])
  (:import java.net.URL
           javax.security.cert.X509Certificate
           org.opensaml.security.credential.Credential
           org.w3c.dom.Element))

(defn url? [s]
  (try
    (URL. s)
    true
    (catch Exception _
      false)))

(s/def ::acs-url url?)
(s/def ::idp-url url?)
(s/def ::issuer url?)
(s/def ::slo-url url?)

(s/def ::request-id string?)
(s/def ::sp-name string?)
(s/def ::app-name string?)

(s/def ::state-manager (partial satisfies? state/StateManager))
(s/def ::credential (partial instance? Credential))
(s/def ::instant inst?)

(s/def ::saml-request (partial satisfies? coerce/SerializeXMLString))
(s/def ::relay-state string?)

(s/def ::status int?)
(s/def ::headers map?)
(s/def ::body string?)

(s/def ::sp-cert (partial instance? X509Certificate))
(s/def ::requests-signed boolean?)
(s/def ::want-assertions-signed boolean?)

(s/def ::request (s/keys :req-un [::sp-name
                                  ::acs-url
                                  ::idp-url
                                  ::issuer]
                         :opt-un [::state-manager
                                  ::credential
                                  ::instant]))

(s/def ::ring-response (s/keys :req-un [::status ::headers ::body]))

(s/def ::metadata (s/keys :req-un [::acs-url
                                   ::app-name
                                   ::sp-cert]
                          :opt-un [::requests-signed
                                   ::slo-url
                                   ::want-assertions-signed]))

(s/fdef metadata/metadata
  :args (s/cat :args ::metadata)
  :ret string?)

(s/fdef request/request
  :args (s/cat :request ::request)
  :ret (partial instance? Element))

(s/fdef request/id-redirect-response
  :args (s/cat :request ::saml-request
               :idp-url ::idp-url
               :relay-state ::relay-state)
  :ret ::ring-response)
