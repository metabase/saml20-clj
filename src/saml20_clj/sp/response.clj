(ns saml20-clj.sp.response
  "Code for parsing the XML response (as a String)from the IdP to an OpenSAML `Response`, and for basic operations like
  validating the signature and reading assertions."
  (:require [java-time :as t]
            [saml20-clj
             [coerce :as coerce]
             [crypto :as crypto]
             [state :as state]
             [xml :as xml]])
  (:import [org.opensaml.saml.saml2.core Assertion Attribute AttributeStatement Audience AudienceRestriction Response
            Subject SubjectConfirmation SubjectConfirmationData]))

(defn clone-response
  "Clone an OpenSAML `response` object."
  ^Response [^Response response]
  (coerce/->Response (xml/clone-document (.. response getDOM getOwnerDocument))))

(defn decrypt-response
  "Decrypt `response` using `sp-private-key` if it has encrypted Assertions. If it does not have encrypted assertions,
  return `response` as-is."
  ^Response [response sp-private-key]
  ;; clone the response, otherwise decryption will be destructive.
  (when-let [response (coerce/->Response response)]
    (if (empty? (.getEncryptedAssertions response))
      response
      (let [clone   (clone-response response)
            element (.getDOM clone)]
        (crypto/recursive-decrypt! sp-private-key element)
        (coerce/->Response element)))))

(defn ensure-encrypted-assertions
  ^Response [response]
  (when-let [response (coerce/->Response response)]
    (let [num-assertions           (count (.getAssertions response))
          num-encrypted-assertions (count (.getEncryptedAssertions response))]
      (when (> num-assertions num-encrypted-assertions)
        (throw (ex-info "Unencrypted assertions present in response body" {}))))))

(defn opensaml-assertions
  [response]
  (when-let [response (coerce/->Response response)]
    (assert (empty? (.getEncryptedAssertions response)) "Response is still encrypted")
    (not-empty (.getAssertions response))))

(defmulti validate-response
  "Perform a validation operation on a Response."
  {:arglists '([validation possibly-encrypted-response unencryped-response options])}
  (fn [validation _ _ _]
    (keyword validation)))

(defmethod validate-response :signature
  [_ encrypted-response _ {:keys [idp-cert]}]
  (try
    (crypto/assert-signature-valid-when-present encrypted-response idp-cert)
    (catch Throwable e
      (throw (ex-info "Invalid <Response> signature" {} e)))))

(defmethod validate-response :require-signature
  [_ encrypted-response decrypted-response _]
  (when-not (crypto/signed? encrypted-response)
    (let [assertions (opensaml-assertions decrypted-response)]
      (assert (seq assertions) "Unsigned response has no assertions (no signatures can be verified)")
      (assert (every? crypto/signed? assertions) "Neither response nor assertion(s) are signed"))))

(defmethod validate-response :valid-request-id
  [_ _ ^Response decrypted-response {:keys [state-manager]}]
  (when state-manager
    (let [request-id (.getInResponseTo decrypted-response)]
      (when-not request-id
        (throw (ex-info "<Response> is missing InResponseTo attribute" {})))
      (state/accept-response! state-manager request-id))))

;;
;; Subject Confirmation Data Checks
;;

(defn subject ^Subject [^Assertion assertion]
  (some-> assertion .getSubject))

(defn subject-confirmations [^Subject subject]
  (some-> subject .getSubjectConfirmations))

(defn subject-data ^SubjectConfirmationData [^SubjectConfirmation subject-confirmation]
  (some-> subject-confirmation .getSubjectConfirmationData))

(defn assertion->subject-confirmation-datas [assertion]
  (map subject-data (-> assertion subject subject-confirmations)))

(defmacro validate-confirmation-datas {:style/indent 1} [[data-binding assertion] & body]
  `(doseq [data# (assertion->subject-confirmation-datas ~assertion)]
     (let [~(vary-meta data-binding assoc :tag `SubjectConfirmationData) data#]
       ~@body)))

(defmulti validate-assertion
  "Perform a validation operation on an Assertion."
  {:arglists '([validation response options])}
  (fn [validation _ _]
    (keyword validation)))

(defmethod validate-assertion :signature
  [_ assertion {:keys [idp-cert]}]
  (try
    (crypto/assert-signature-valid-when-present assertion idp-cert)
    (catch Throwable e
      (throw (ex-info "Invalid <Assertion> signature(s)" {} e)))))

;; Verify that the `Recipient` attribute in any bearer `<SubjectConfirmationData>` matches the assertion consumer
;; service URL to which the `<Response>` or artifact was delivered.
(defmethod validate-assertion :recipient
  [_ assertion {:keys [acs-url]}]
  (when acs-url
    (validate-confirmation-datas [data assertion]
      (let [recipient (.getRecipient data)]
        ;; Recipient field is REQUIRED if <SubjectConfirmationData> is present.
        (when-not recipient
          (throw (ex-info "<SubjectConfirmationData> does not contain a Recipient"
                          {:data (coerce/->xml-string data)})))
        (when-not (= recipient acs-url)
          (throw (ex-info "<SubjectConfirmationData> Recipient does not match assertion consumer service URL"
                          {:data (coerce/->xml-string data), :acs-url acs-url})))))))

;; Verify that the NotOnOrAfter attribute in any bearer <SubjectConfirmationData> has not passed, subject to allowable
;; clock skew between the providers
(defmethod validate-assertion :not-on-or-after
  [_ assertion {:keys [allowable-clock-skew-seconds]
                :or   {allowable-clock-skew-seconds com.onelogin.saml2.util.Constants/ALOWED_CLOCK_DRIFT}}]
  (validate-confirmation-datas [data assertion]
    (let [not-on-or-after (some-> (.getNotOnOrAfter data) t/instant)]
      (when-not not-on-or-after
        (throw (ex-info "<SubjectConfirmationData> does not contain NotOnOrAfter"
                        {:data (coerce/->xml-string data)})))
      (when (t/after? (t/minus (t/instant) (t/seconds allowable-clock-skew-seconds))
                      not-on-or-after)
        (throw (ex-info "<SubjectConfirmationData> NotOnOrAfter has passed"
                        {:data                         (coerce/->xml-string data)
                         :not-on-or-after              not-on-or-after
                         :now                          (t/instant)
                         :allowable-clock-skew-seconds allowable-clock-skew-seconds}))))))

(defmethod validate-assertion :not-before
  [_ assertion {:keys [allowable-clock-skew-seconds]
                :or   {allowable-clock-skew-seconds com.onelogin.saml2.util.Constants/ALOWED_CLOCK_DRIFT}}]
  (validate-confirmation-datas [data assertion]
    (when-let [not-before (some-> (.getNotBefore data) t/instant)]
      (when (t/before? (t/plus (t/instant) (t/seconds allowable-clock-skew-seconds))
                       not-before)
        (throw (ex-info "<SubjectConfirmationData> NotBefore is in the future"
                        {:data                         (coerce/->xml-string data)
                         :not-before                   not-before
                         :now                          (t/instant)
                         :allowable-clock-skew-seconds allowable-clock-skew-seconds}))))))

(defmethod validate-assertion :in-response-to
  [_ assertion {:keys [request-id solicited?]
                :or   {solicited? true}}]
  (when (or request-id
            (not solicited?))
    (validate-confirmation-datas [data assertion]
      (let [in-response-to (.getInResponseTo data)]
        (when-not in-response-to
          (throw (ex-info "<SubjectConfirmationData> does not contain InResponseTo"
                          {:data (coerce/->xml-string data)})))
        (if solicited?
          (when (not= in-response-to request-id)
            (throw (ex-info "<SubjectConfirmationData> InResponseTo does not match request-id"
                            {:data       (coerce/->xml-string data)
                             :request-id request-id})))
          (when request-id
            (throw (ex-info "<SubjectConfirmationData> InResponseTo should not be present for an unsolicited request"
                            {:data       (coerce/->xml-string data)
                             :request-id request-id}))))))))

;; verifying the Address attribute is optional.
(defmethod validate-assertion :address
  [_ assertion {:keys [user-agent-address]}]
  (when user-agent-address
    (validate-confirmation-datas [data assertion]
      (when-let [address (.getAddress data)]
        (when-not (= address user-agent-address)
          (throw (ex-info "<SubjectConfirmationData> Address does not match user-agent-address"
                          {:data       (coerce/->xml-string data)
                           :request-id user-agent-address})))))))

(def default-validation-options
  {:response-validators  [:signature
                          :require-signature
                          :valid-request-id]
   :assertion-validators [:signature
                          :recipient
                          :not-on-or-after
                          :not-before
                          :in-response-to
                          :address]})

(defn- move-validator-config
  "Raises one of the validation settings from a nested map up into the main config.
  Because we dispatch on the validator keywords, but only after decrypting the response,
  we use this to preserve the config setting without having to implement a dummy method"
  [options validator-type validator]
  (if-let [config-setting (some #(= validator %) (get options validator-type))]
    (-> options
        (update-in [validator-type] (fn [e] (remove #(= % validator) e)))
        (assoc validator true))
    options))

(defn validate
  "Validate response. Returns decrypted response if valid."
  ([response idp-cert sp-private-key]
   (validate response idp-cert sp-private-key nil))

  ([response idp-cert sp-private-key options]
   (let [{:keys [response-validators assertion-validators], :as options} (-> (merge default-validation-options options)
                                                                             (assoc :idp-cert (coerce/->Credential idp-cert))
                                                                             (move-validator-config :assertion-validators :require-encryption))]
     (when (:require-encryption options)
       (ensure-encrypted-assertions response))
     (when-let [response (coerce/->Response response)]
       (let [decrypted-response (if sp-private-key
                                  (decrypt-response response sp-private-key)
                                  response)]
         (doseq [validator response-validators]
           (validate-response validator response decrypted-response options))
         (doseq [assertion (opensaml-assertions decrypted-response)
                 validator assertion-validators]
           (validate-assertion validator assertion options))
         decrypted-response)))))


;;; +----------------------------------------------------------------------------------------------------------------+
;;; |                                        Convenient Clojurey Map Util Fns                                        |
;;; +----------------------------------------------------------------------------------------------------------------+

(defn response-status
  "Parses and returns information about the status (i.e. successful or not), the version, addressing info etc. of the
  SAML response

  Check the javadoc of OpenSAML at:

  https://build.shibboleth.net/nexus/service/local/repositories/releases/archive/org/opensaml/opensaml/2.5.3/opensaml-2.5.3-javadoc.jar/!/index.html"
  [response]
  (when-let [response (coerce/->Response response)]
    (let [status (.. response getStatus getStatusCode getValue)]
      {:in-response-to (.getInResponseTo response)
       :status         status
       :success?       (= status org.opensaml.saml.saml2.core.StatusCode/SUCCESS)
       :version        (.. response getVersion toString)
       :issue-instant  (t/instant (.getIssueInstant response))
       :destination    (.getDestination response)})))

;; https://www.purdue.edu/apps/account/docs/Shibboleth/Shibboleth_information.jsp
;;  Or
;; https://wiki.library.ucsf.edu/display/IAM/EDS+Attributes
(def saml2-attr->name
  (let [names {"urn:oid:0.9.2342.19200300.100.1.1" "uid"
               "urn:oid:0.9.2342.19200300.100.1.3" "mail"
               "urn:oid:2.16.840.1.113730.3.1.241" "displayName"
               "urn:oid:2.5.4.3"                   "cn"
               "urn:oid:2.5.4.4"                   "sn"
               "urn:oid:2.5.4.12"                  "title"
               "urn:oid:2.5.4.20"                  "phone"
               "urn:oid:2.5.4.42"                  "givenName"
               "urn:oid:2.5.6.8"                   "organizationalRole"
               "urn:oid:2.16.840.1.113730.3.1.3"   "employeeNumber"
               "urn:oid:2.16.840.1.113730.3.1.4"   "employeeType"
               "urn:oid:1.3.6.1.4.1.5923.1.1.1.1"  "eduPersonAffiliation"
               "urn:oid:1.3.6.1.4.1.5923.1.1.1.2"  "eduPersonNickname"
               "urn:oid:1.3.6.1.4.1.5923.1.1.1.6"  "eduPersonPrincipalName"
               "urn:oid:1.3.6.1.4.1.5923.1.1.1.9"  "eduPersonScopedAffiliation"
               "urn:oid:1.3.6.1.4.1.5923.1.1.1.10" "eduPersonTargetedID"
               "urn:oid:1.3.6.1.4.1.5923.1.6.1.1"  "eduCourseOffering"}]
    (fn [attr-oid]
      (get names attr-oid attr-oid))))

;; http://kevnls.blogspot.gr/2009/07/processing-saml-in-java-using-opensaml.html
;; http://stackoverflow.com/questions/9422545/decrypting-encrypted-assertion-using-saml-2-0-in-java-using-opensaml
(defn Assertion->map
  "Returns the attributes and the 'audiences' for the given SAML assertion"
  [^Assertion assertion]
  (when assertion
    (let [statements   (.getAttributeStatements assertion)
          subject      (.getSubject assertion)
          subject-data (.getSubjectConfirmationData ^SubjectConfirmation (first (.getSubjectConfirmations subject)))
          name-id      (.getNameID subject)
          attrs        (into {} (for [^AttributeStatement statement statements
                                      ^Attribute attribute          (.getAttributes statement)]
                                               [(saml2-attr->name (.getName attribute)) ; Or (.getFriendlyName a) ??
                                                (map #(-> ^org.opensaml.core.xml.XMLObject % .getDOM .getTextContent)
                                                     (.getAttributeValues attribute))]))
          audiences    (for [^AudienceRestriction restriction (.. assertion getConditions getAudienceRestrictions)
                             ^Audience audience               (.getAudiences restriction)]
                                      (.getAudienceURI audience))]
      {:attrs        attrs
       :audiences    audiences
       :name-id      {:value  (some-> name-id .getValue)
                      :format (some-> name-id .getFormat)}
       :confirmation {:in-response-to  (.getInResponseTo subject-data)
                      :not-before      (some-> (.getNotBefore subject-data) (t/instant))
                      :not-on-or-after (t/instant (.getNotOnOrAfter subject-data))
                      :address         (.getAddress subject-data)
                      :recipient       (.getRecipient subject-data)}})))

(defn assertions
  "Returns the assertions (encrypted or not) of a SAML Response object"
  ([possibly-encrypted-response sp-private-key]
   (assertions (decrypt-response possibly-encrypted-response sp-private-key)))

  ([decrypted-response]
   (when-let [assertions (opensaml-assertions decrypted-response)]
     (map Assertion->map assertions))))
