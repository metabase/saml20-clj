(ns saml20-clj.sp.request
  (:require [clojure.string :as str]
            [hiccup.core :as hiccup]
            [java-time :as t]
            [ring.util.codec :as codec]
            [saml20-clj
             [coerce :as coerce]
             [crypto :as crypto]
             [encode-decode :as encode-decode]
             [state :as state]]))

;; TODO -- this should be moved to a separate "metadata" namespace??
(defn metadata
  "Create Metadata to send to the IdP to configure things? I think that's what this is for. Not sure."
  ^String [app-name acs-uri certificate-str]
  (coerce/->xml-string
   [:md:EntityDescriptor {:xmlns:md "urn:oasis:names:tc:SAML:2.0:metadata"
                          :ID       (str/replace acs-uri #"[:/]" "_")
                          :entityID app-name}
    [:md:SPSSODescriptor {:AuthnRequestsSigned        "true"
                          :WantAssertionsSigned       "true"
                          :protocolSupportEnumeration "urn:oasis:names:tc:SAML:2.0:protocol"}
     [:md:KeyDescriptor  {:use "signing"}
      [:ds:KeyInfo  {:xmlns:ds "http://www.w3.org/2000/09/xmldsig#"}
       [:ds:X509Data
        [:ds:X509Certificate certificate-str]]]]
     [:md:KeyDescriptor  {:use "encryption"}
      [:ds:KeyInfo  {:xmlns:ds "http://www.w3.org/2000/09/xmldsig#"}
       [:ds:X509Data
        [:ds:X509Certificate certificate-str]]]]
     [:md:SingleLogoutService {:Binding "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
                               :Location "https://example.org/saml/SingleLogout"}]
     [:md:NameIDFormat "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"]
     [:md:NameIDFormat "urn:oasis:names:tc:SAML:2.0:nameid-format:transient"]
     [:md:NameIDFormat "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"]
     [:md:NameIDFormat "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified"]
     [:md:NameIDFormat "urn:oasis:names:tc:SAML:1.1:nameid-format:X509SubjectName"]
     [:md:AssertionConsumerService {:Binding   "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
                                    :Location  acs-uri
                                    :index     "0"
                                    :isDefault "true"}]]]))

(defn- format-instant
  "Converts a date-time to a SAML 2.0 time string."
  [instant]
  (t/format (t/format "YYYY-MM-dd'T'HH:mm:ss'Z'" (t/offset-date-time instant (t/zone-offset 0)))))

(defn request
  "Return XML elements that represent a SAML 2.0 auth request."
  ^org.w3c.dom.Element [{:keys [ ;; e.g. something like a UUID
                                request-id
                                ;; e.g. "Metabase"
                                sp-name
                                ;; e.g. ttp://sp.example.com/demo1/index.php?acs
                                acs-url
                                ;; e.g. http://sp.example.com/demo1/index.php?acs
                                idp-url
                                ;; e.g. http://idp.example.com/SSOService.php
                                issuer
                                ;; If present, record the request
                                state-manager
                                ;; If present, we can sign the request
                                private-key]
                         :or   {request-id (str (java.util.UUID/randomUUID))}}]
  (assert acs-url)
  (assert idp-url)
  (assert sp-name)
  (let [request (coerce/->Element (hiccup/html
                                   [:samlp:AuthnRequest
                                    {:xmlns:samlp                 "urn:oasis:names:tc:SAML:2.0:protocol"
                                     :ID                          request-id
                                     :Version                     "2.0"
                                     :IssueInstant                (format-instant (t/instant))
                                     :ProtocolBinding             "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
                                     :ProviderName                sp-name
                                     :IsPassive                   false
                                     :Destination                 idp-url
                                     :AssertionConsumerServiceURL acs-url}
                                    [:saml:Issuer
                                     {:xmlns:saml "urn:oasis:names:tc:SAML:2.0:assertion"}
                                     issuer]
                                    ;;[:samlp:NameIDPolicy {:AllowCreate false :Format saml-format}]
                                    ]))]
    (when state-manager
      (state/record-request! state-manager (.getAttribute request "ID")))
    (cond-> request
      private-key (crypto/sign private-key))))

(defn uri-query-str
  ^String [clean-hash]
  (codec/form-encode clean-hash))

(defn idp-redirect-response
  "Return Ring response for HTTP 302 redirect."
  [saml-request idp-url relay-state]
  (let [saml-request-str (if (string? saml-request)
                           saml-request
                           (coerce/->xml-string saml-request))
        url              (str idp-url
                              (if (str/includes? idp-url "?")
                                "&"
                                "?")
                              (let [saml-request-str (encode-decode/str->deflate->base64 saml-request-str)]
                                (uri-query-str
                                 {:SAMLRequest saml-request-str, :RelayState relay-state})))]
    {:status  302 ; found
     :headers {"Location" url}
     :body    ""}))
