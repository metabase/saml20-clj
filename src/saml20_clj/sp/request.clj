(ns saml20-clj.sp.request
  (:require [clojure.string :as str]
            [java-time.api :as t]
            [ring.util.codec :as codec]
            [saml20-clj.coerce :as coerce]
            [saml20-clj.crypto :as crypto]
            [saml20-clj.encode-decode :as encode-decode]
            [saml20-clj.state :as state]))

(defn- format-instant
  "Converts a date-time to a SAML 2.0 time string."
  [instant]
  (t/format (t/format "YYYY-MM-dd'T'HH:mm:ss'Z'" (t/offset-date-time instant (t/zone-offset 0)))))

(defn- non-blank-string? [s]
  (and (string? s)
       (not (str/blank? s))))

(defn random-request-id
  "Generates a random ID for a SAML request, if none is provided."
  []
  (str "id" (random-uuid)))

(defn- make-auth-xml [request-id instant sp-name idp-url acs-url issuer]
  [:samlp:AuthnRequest
   {:xmlns:samlp                 "urn:oasis:names:tc:SAML:2.0:protocol"
    :ID                          (or request-id (random-request-id))
    :Version                     "2.0"
    :IssueInstant                (format-instant instant)
    :ProtocolBinding             "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
    :ProviderName                sp-name
    :IsPassive                   false
    :Destination                 idp-url
    :AssertionConsumerServiceURL acs-url}
   [:saml:Issuer
    {:xmlns:saml "urn:oasis:names:tc:SAML:2.0:assertion"}
    issuer]
   ;;[:samlp:NameIDPolicy {:AllowCreate false :Format saml-format}]
   ])

(defn request
  "Return XML elements that represent a SAML 2.0 auth request."
  ^org.w3c.dom.Element [{:keys [ ;; e.g. something like a UUID. Random UUID will be used if no other ID is provided
                                request-id
                                ;; e.g. "Metabase"
                                sp-name
                                ;; e.g. http://sp.example.com/demo1/index.php?acs
                                acs-url
                                ;; e.g. http://idp.example.com/SSOService.php
                                idp-url
                                ;; e.g. http://sp.example.com/demo1/metadata.php
                                issuer
                                ;; If present, record the request
                                state-manager
                                ;; If present, we can sign the request
                                credential
                                instant]
                         :or   {instant (t/instant)}}]
  (assert (non-blank-string? acs-url) "acs-url is required")
  (assert (non-blank-string? idp-url) "idp-url is required")
  (assert (non-blank-string? sp-name) "sp-name is required")
  (assert (non-blank-string? issuer) "issuer is required")
  (let [request (coerce/->Element
                  (coerce/->xml-string
                    (make-auth-xml request-id instant sp-name idp-url acs-url issuer)))]
    (when state-manager
      (state/record-request! state-manager (.getAttribute request "ID")))
    (if-not credential
      request
      (or (crypto/sign request credential)
          (throw (ex-info "Failed to sign request" {:request request}))))))

(defn- add-query-params
  "Add query parameters to a URL.

  (add-query-params \"http://example.com\" {:a \"b\" :c \"d\"}
  ;; => \"http://example.com?a=b&c=d\""
  [url params]
  (str url (if (str/includes? url "?") "&" "?") (codec/form-encode params)))

(defn idp-redirect-response
  "Return Ring response for HTTP 302 redirect."
  [saml-request idp-url relay-state]
  {:pre [(some? saml-request)
         (string? idp-url)
         (string? relay-state)]}
  (let [saml-request-str (cond-> saml-request
                           (not (string? saml-request)) coerce/->xml-string)
        saml-request-str (encode-decode/str->deflate->base64 saml-request-str)
        url              (add-query-params idp-url {:SAMLRequest saml-request-str
                                                    :RelayState relay-state})]
    {:status  302 ; found
     :headers {"Location" url}
     :body    ""}))

;; I wanted to call this make-request-xml, but it gets exported in core.clj, which
;; warrants the request prefix
(defn make-logout-request-xml
  "Generates a SAML 2.0 logout request, as a hiccupey datastructure."
  [& {:keys [request-id instant idp-url issuer user-email]
      :or {instant (format-instant (t/instant))}}]
  (assert (non-blank-string? idp-url) "idp-url is required")
  (assert (non-blank-string? issuer) "issuer is required")
  (assert (non-blank-string? user-email) "user-email is required")
  [:samlp:LogoutRequest {:xmlns "urn:oasis:names:tc:SAML:2.0:protocol"
                         :xmlns:samlp "urn:oasis:names:tc:SAML:2.0:protocol"
                         :xmlns:saml "urn:oasis:names:tc:SAML:2.0:assertion"
                         :Version "2.0"
                         :ID (or request-id (str "id" (random-uuid)))
                         :IssueInstant instant
                         :Destination idp-url}
   [:Issuer {:xmlns "urn:oasis:names:tc:SAML:2.0:assertion"} issuer]
   [:NameID {:xmlns "urn:oasis:names:tc:SAML:2.0:assertion"
             :Format "urn:oasis:names:tc:SAML:2.0:nameid-format:emailAddress"} user-email]])

(defn logout-redirect-location
  "This returns a url that you'd want to redirect a client to. Either using
  `ring/redirect` with a 302 status code or passing it to a client in a post body
  to have them redirect to."
  [& {:keys [issuer user-email idp-url relay-state request-id]}]
  (assert (non-blank-string? idp-url) "idp-url is required")
  (assert (non-blank-string? user-email) "user-email is required")
  (assert (non-blank-string? issuer) "issuer is required")
  (assert (non-blank-string? relay-state) "relay-state is required")
  (add-query-params idp-url {:SAMLRequest (encode-decode/str->deflate->base64
                                            (coerce/->xml-string (make-logout-request-xml
                                                                   :idp-url idp-url
                                                                   :request-id request-id
                                                                   :issuer issuer
                                                                   :user-email user-email)))
                             :RelayState relay-state}))

(defn idp-logout-redirect-response
  "Return Ring response for HTTP 302 redirect."
  ([issuer user-email idp-url relay-state]
   (idp-logout-redirect-response issuer user-email idp-url relay-state (random-request-id)))
  ([issuer user-email idp-url relay-state request-id]
   (let [url (logout-redirect-location
               :idp-url idp-url
               :user-email user-email
               :issuer issuer
               :relay-state relay-state
               :request-id request-id)]
     {:status  302 ; found
      :headers {"Location" url}
      :body    ""})))
