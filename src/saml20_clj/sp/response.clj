(ns saml20-clj.sp.response
  "Code for parsing the XML response (as a String)from the IdP to an OpenSAML `Response`, and for basic operations like
  validating the signature and reading assertions."
  (:require [clj-time.coerce :as c.coerce]
            [clj-time.core :as t]
            [clojure.tools.logging :as log]
            [saml20-clj
             [coerce :as coerce]
             [crypto :as crypto]])
  (:import [org.opensaml.saml.saml2.core Assertion Attribute AttributeStatement Audience AudienceRestriction Response
            SubjectConfirmation]))

;; this is here mostly as a convenience
(defn ^Response parse-response
  "Parse/coerce something representing such as a String or Java object `xml` into a OpenSAML `Response`."
  [xml]
  (coerce/->Response xml))

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
       :issue-instant  (c.coerce/to-timestamp (.getIssueInstant response))
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
    (let [statements                (.getAttributeStatements assertion)
          subject                   (.getSubject assertion)
          subject-confirmation-data (.getSubjectConfirmationData ^SubjectConfirmation (first (.getSubjectConfirmations subject)))
          name-id                   (.getNameID subject)
          attrs                     (into {} (for [^AttributeStatement statement statements
                                                   ^Attribute attribute          (.getAttributes statement)]
                                               [(saml2-attr->name (.getName attribute)) ; Or (.getFriendlyName a) ??
                                                (map #(-> ^org.opensaml.core.xml.XMLObject % .getDOM .getTextContent)
                                                     (.getAttributeValues attribute))]))
          audiences                 (for [^AudienceRestriction restriction (.. assertion getConditions getAudienceRestrictions)
                                          ^Audience audience               (.getAudiences restriction)]
                                      (.getAudienceURI audience))]
      {:attrs        attrs
       :audiences    audiences
       :name-id      {:value  (some-> name-id .getValue)
                      :format (some-> name-id .getFormat)}
       :confirmation {:in-response-to  (.getInResponseTo subject-confirmation-data)
                      :not-before      (c.coerce/to-timestamp (.getNotBefore subject-confirmation-data))
                      :not-on-or-after (c.coerce/to-timestamp (.getNotOnOrAfter subject-confirmation-data))
                      :address         (.getAddress subject-confirmation-data)
                      :recipient       (.getRecipient subject-confirmation-data)}})))

(defn decrypt-response ^org.opensaml.saml.saml2.core.Response [response sp-private-key]
  (let [element (coerce/->Element response)]
    (crypto/recursive-decrypt! sp-private-key element)
    (coerce/->Response element)))

(defn opensaml-assertions
  [response sp-private-key]
  (some-> response (decrypt-response sp-private-key) .getAssertions not-empty))

(defn assertions
  "Returns the assertions (encrypted or not) of a SAML Response object"
  [response sp-private-key]
  (when-let [assertions (opensaml-assertions response sp-private-key)]
    (map Assertion->map assertions)))

(defn- signed? [object]
  (when-let [object (coerce/->SAMLObject object)]
    (.isSigned object)))

(defn- signature [object]
  (when-let [object (coerce/->SAMLObject object)]
    (.getSignature object)))

(defn- assert-valid-signature
  [object credential]
  (when-let [signature (signature object)]
    (when-let [credential (coerce/->Credential credential)]
      ;; validate that the signature conforms to the SAML signature spec
      (.validate (org.opensaml.saml.security.impl.SAMLSignatureProfileValidator.) signature)
      ;; validate that the signature matches the IdP cert
      (org.opensaml.xmlsec.signature.support.SignatureValidator/validate signature credential))))


(defn validate-response-signature
  "Returns truthy if the IdP `response` is signed (either the message, or all assertions, or both message and all
  assertions), and the signature(s) are valid for the `idp-cert-str` (as a base-64 encoded string)."
  [response idp-public-key sp-private-key]
  (when-let [response (coerce/->Response response)]
    (when-let [idp-public-key (coerce/->Credential idp-public-key)]
      (try
        (assert-valid-signature response idp-public-key)
        (let [assertions (opensaml-assertions response sp-private-key)]
          (doseq [assertion assertions]
            (assert-valid-signature assertion idp-public-key))
          (or (signed? response)
              (every? signed? assertions)))
        (catch org.opensaml.xmlsec.signature.support.SignatureException e
          (log/error e "Signature NOT valid")
          false)))))

;;
;; Subject Confirmation Data Checks
;;

(defn- assert-valid-recipient-attribute
  "Verify that the Recipient attribute in any bearer <SubjectConfirmationData> matches the
  assertion consumer service URL to which the <Response> or artifact was delivered"
  [^Assertion assertion acs-url]
  (let [assertion-map (Assertion->map assertion)
        recipient (-> assertion-map :confirmation :recipient)]
    (= recipient acs-url))) ; Recipient field is REQUIRED

(defn- assert-valid-not-on-or-after-attribute
  "Verify that the NotOnOrAfter attribute in any bearer <SubjectConfirmationData> has not
  passed, subject to allowable clock skew between the providers

  TODO does not include allowable clock skew"
  [^Assertion assertion]
  (let [assertion-map (Assertion->map assertion)]
    (if-let [not-on-or-after (-> assertion-map :confirmation :not-on-or-after)]
      (t/before? (t/now) (c.coerce/from-sql-time not-on-or-after))
      true))) ;; An assertion without a `not-on-or-after` field is still valid

(defn- assert-valid-not-before-attribute
  "TODO does not include allowable clock skew"
  [^Assertion assertion]
  (let [assertion-map (Assertion->map assertion)]
    (if-let [not-before (-> assertion-map :confirmation :not-before)]
      (not (t/before? (t/now) (c.coerce/from-sql-time not-before)))
      true))) ;; An assertion without a `not-on-or-after` field is still valid

(defn- assert-valid-in-response-to-attribute
  "Verify that the InResponseTo attribute in the bearer <SubjectConfirmationData> equals the ID
  of its original <AuthnRequest> message, unless the response is unsolicited (see Section 4.1.5 ), in
  which case the attribute MUST NOT be present"
  [^Assertion assertion auth-req-id solicited]
  (let [assertion-map (Assertion->map assertion)
        in-response-to (-> assertion-map :confirmation :in-response-to)]
    (if (and (not solicited) in-response-to) false
      (= (-> assertion-map :confirmation :in-response-to) ; This field is required
         auth-req-id))))

(defn- assert-valid-address-attribute
  "If any bearer <SubjectConfirmationData> includes an Address attribute, the service provider
  MAY check the user agent's client address against it.

  NOTE The usage of this function is not super obvious, since verifying the
  Address attribute is optional. So this function should only be called
  if the SP is enforcing address checks, indicated either by a config
  map or by exposing this at the API level
  "
  [^Assertion assertion user-agent-address]
  (let [assertion-map (Assertion->map assertion)
        address (-> assertion-map :confirmation :address)]
    (if address
      (and address (= address user-agent-address))
      true))) ; Address attribute may not be included, which is still valid

;; TODO
#_(defn validate [^Response response ^String idp-cert-str]
    "From the SAML spec: https://docs.oasis-open.org/security/saml/v2.0/saml-profiles-2.0-os.pdf

  Regardless of the SAML binding used, the service provider MUST do the following:

  • Verify any signatures present on the assertion(s) or the response

  • Verify that any assertions relied upon are valid in other respects

  • Any assertion which is not valid, or whose subject confirmation requirements cannot be met SHOULD
  be discarded and SHOULD NOT be used to establish a security context for the principal.

  • If an <AuthnStatement> used to establish a security context for the principal contains a
  SessionNotOnOrAfter attribute, the security context SHOULD be discarded once this time is
  reached, unless the service provider reestablishes the principal's identity by repeating the use of this
  profile.")

;; TODO
#_(def status-code-success "urn:oasis:names:tc:SAML:2.0:status:Success")

#_(defn saml-successful?
  [id-str]
  (= id-str status-code-success))
