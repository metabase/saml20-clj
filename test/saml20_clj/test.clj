 (ns saml20-clj.test
  "Test utils."
  (:require [clojure.string :as str]
            ring.util.codec
            [saml20-clj.coerce :as coerce]
            [saml20-clj.encode-decode :as encode-decode]))

(def idp-entity-id "idp.example.com")
(def idp-uri "https://idp.example.com")

(def sp-entity-id "sp.example.com")
(def sp-attribute-consume-service-endpoint "http://sp.example.com/demo1/index.php?acs")

;; keystore has SP x.509 cert and private keys under "sp" and IdP X.509 cert under "idp"
(def keystore-filename "test/saml20_clj/test/keystore.jks")
(def keystore-password "123456")

(defn- sample-file [file-name]
  (slurp (str "test/saml20_clj/test/" file-name)))

(def idp-cert
  (sample-file "idp.cert"))

(def sp-cert
  (sample-file "sp.cert"))

(def sp-private-key
  (sample-file "sp.private.key"))

(defmulti response
  "Return a sample response (as a raw XML string) with options.

    (response {:message-signed? true})"
  {:arglists '([options])}
  ;; dispatch value is options as a map with only truthy keys
  ;; e.g. (response {:message-signed? false}) -> {}
  (fn [options]
    (into {} (for [[k v] options
                   :when v]
               [k true]))))

;; Metadata tests

(def metadata-with-key-info (sample-file "metadata-with-keyinfo.xml"))
(def metadata-without-key-info (sample-file "metadata-without-keyinfo.xml"))

;; Logout Response

(def logout-issuer-id "http://idp.example.com/metadata.php")
(def logout-request-id "ONELOGIN_21df91a89767879fc0f7df6a1490c6000c81644d")

(defn ring-logout-response-post
  "Return a ring map of the logout response as an HTTP-Post binding."
  [status relay-state & {:keys [signature] :or {signature true}}]
  (let [response (sample-file (condp = [status signature]
                                [:success true] "logout-response-success-with-signature.xml"
                                [:success :bad] "logout-response-success-with-bad-signature.xml"
                                [:authnfailed true] "logout-response-authnfailure-with-signature.xml"
                                [:success false] "logout-response-success-without-signature.xml"))]
    {:params {:SAMLResponse (encode-decode/str->base64 response)
              :RelayState (encode-decode/str->base64 relay-state)}
     :request-method :post
     :content-type "application/x-www-form-urlencoded"}))

(defn ring-logout-response-get
  "Return a ring map of the logout response as an HTTP-Redirect binding."
  [status & {:keys [signature] :or {signature true}}]
  (let [response (-> (condp = [status signature]
                       [:success true] "logout-response-success-with-signature.edn"
                       [:success :bad] "logout-response-success-with-bad-signature.edn"
                       [:authnfailed true] "logout-response-authnfailure-with-signature.edn"
                       [:success false] "logout-response-success-without-signature.edn")
                     sample-file
                     read-string)]
    {:query-string (->> (zipmap (->> response keys (map name))
                                (vals response))
                        (map (partial str/join "="))
                        (str/join "&"))
     :params (zipmap (->> response keys (map name))
                     (->> response vals (map ring.util.codec/url-decode)))
     :request-method :get}))

;;
;; Confirmation Data
;;

(defn ring-response-post
  "Return a ring map of a response as an HTTP-Post binding"
  [response & [relay-state]]
  {:params {:SAMLResponse (encode-decode/str->base64 (coerce/->xml-string response))
            :RelayState (encode-decode/str->base64 (or relay-state "test-relay-state"))}
   :request-method :post
   :content-type "application/x-www-form-urlencoded"})

(defmethod response {:invalid-confirmation-data? true}
  [_]
  (sample-file "response-invalid-confirmation-data.xml"))

(defmethod response {:valid-confirmation-data? true}
  [_]
  (sample-file "response-valid-confirmation-data.xml"))

;;
;; Signing and Encryption
;;

(defmethod response {}
  [_]
  (sample-file "response-unsigned.xml"))

(defmethod response {:message-signed? true}
  [_]
  (sample-file "response-with-signed-message.xml"))

(defmethod response {:malicious-signature? true}
  [_]
  (sample-file "response-with-swapped-signature.xml"))

(defmethod response {:assertion-signed? true}
  [_]
  (sample-file "response-with-signed-assertion.xml"))

(defmethod response {:message-signed? true, :assertion-signed? true}
  [_]
  (sample-file "response-with-signed-message-and-assertion.xml"))

(defmethod response {:assertion-encrypted? true}
  [_]
  (sample-file "response-with-encrypted-assertion.xml"))

(defmethod response {:message-signed? true, :assertion-encrypted? true}
  [_]
  (sample-file "response-with-signed-message-and-encrypted-assertion.xml"))

(defmethod response {:assertion-signed? true, :assertion-encrypted? true}
  [_]
  (sample-file "response-with-signed-and-encrypted-assertion.xml"))

(defmethod response {:assertion-signed? true, :assertion-encrypted? true :saml2-assertion? true}
  [_]
  (sample-file "response-with-signed-and-encrypted-saml2-assertion.xml"))

(defmethod response {:assertion-signed? true, :assertion-encrypted? true :no-namespace-assertion? true}
  [_]
  (sample-file "response-with-signed-and-encrypted-no-namespace-assertion.xml"))

(defmethod response {:message-signed? true, :assertion-signed? true, :assertion-encrypted? true}
  [_]
  (sample-file "response-with-signed-message-and-signed-and-encryped-assertion.xml"))

(defmethod response {:no-issuer-information? true}
  [_]
  (sample-file "response-no-issuer.xml"))

(defn responses
  "All the sample responses above but in a convenient format for writing test code that loops over them.

  TODO -- invalid responses with an `:invalid-reason`."
  []
  (for [[dispatch-value f] (methods response)]
    (assoc dispatch-value :response (f dispatch-value))))

(defn signed-and-encrypted-assertion? [response-map]
  (or (= {:assertion-signed? true :assertion-encrypted? true} (dissoc response-map :response))
      ((some-fn :saml2-assertion? :no-namespace-assertion?) response-map)))

(defn message-signed? [response-map]
  ((some-fn :message-signed?) response-map))

(defn assertions-encrypted? [response-map]
  ((some-fn :assertion-encrypted?) response-map))

(defn valid-confirmation-data? [response-map]
  ((some-fn :valid-confirmation-data?) response-map))

(defn invalid-confirmation-data? [response-map]
  ((some-fn :invalid-confirmation-data?) response-map))

(defn malicious-signature? [response-map]
  ((some-fn :malicious-signature?) response-map))

(defn describe-response-map
  "Human-readable string description of a response map (from `responses`), useful for `testing` context when writing
  test code that loops over various responses."
  [{:keys [message-signed? malicious-signature? assertion-signed? assertion-encrypted? valid-confirmation-data? invalid-confirmation-data?], :as m}]
  (format "Response with %s message, %s %s%s %s assertion\n%s"
          (if message-signed? "SIGNED" "unsigned")
          (if malicious-signature? "MALICIOUS" "not-malicious")
          (cond valid-confirmation-data?   "VALID confirmation data, "
                invalid-confirmation-data? "INVALID confiration data, "
                :else                      "")
          (if assertion-signed? "SIGNED" "unsigned")
          (if assertion-encrypted? "ENCRYPTED" "unencrypted")
          (pr-str (list 'saml20-clj.test/response (dissoc m :response)))))
