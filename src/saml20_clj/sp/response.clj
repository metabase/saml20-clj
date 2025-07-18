(ns saml20-clj.sp.response
  "Code for parsing the XML response (as a String)from the IdP to an OpenSAML `Response`, and for basic operations like
  validating the signature and reading assertions."
  (:require [java-time.api :as t]
            [saml20-clj.coerce :as coerce]
            [saml20-clj.crypto :as crypto]
            [saml20-clj.sp.message :as message]
            [saml20-clj.state :as state]
            [saml20-clj.validation-errors :as errors]
            [saml20-clj.xml :as xml])
  (:import [org.opensaml.saml.saml2.core Assertion Attribute AttributeStatement Audience AudienceRestriction Response
            Subject SubjectConfirmation SubjectConfirmationData AuthnStatement AuthnContext
            ProxyRestriction Conditions AuthnContextClassRef]
           org.opensaml.messaging.context.MessageContext
           org.opensaml.saml.saml2.core.impl.AuthnRequestBuilder))

(set! *warn-on-reflection* true)

(defn- clone-response
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
      (let [clone (clone-response response)
            element (.getDOM clone)]
        (crypto/recursive-decrypt! sp-private-key element)
        (coerce/->Response element)))))

(defmethod message/validate-message :require-encryption
  [_ ^MessageContext msg-ctx _]
  (when-let [response (coerce/->Response msg-ctx)]
    (let [num-assertions (count (.getAssertions response))
          num-encrypted-assertions (count (.getEncryptedAssertions response))]
      (when (> num-assertions num-encrypted-assertions)
        (throw (errors/validation-error :encryption-required response {}))))))

(defn- opensaml-assertions
  [response]
  (when-let [response (coerce/->Response response)]
    (assert (empty? (.getEncryptedAssertions response)) "Response is still encrypted")
    (not-empty (.getAssertions response))))

;;
;; Subject Confirmation Data Checks
;;

(defn- subject ^Subject [^Assertion assertion]
  (some-> assertion .getSubject))

(defn- subject-confirmations [^Subject subject]
  (some-> subject .getSubjectConfirmations))

(defn- subject-data ^SubjectConfirmationData [^SubjectConfirmation subject-confirmation]
  (some-> subject-confirmation .getSubjectConfirmationData))

(defn- assertion->subject-confirmation-datas [assertion]
  (map subject-data (-> assertion subject subject-confirmations)))

(defmacro validate-confirmation-datas
  "Extracts an instance of `SubjectConfirmationData` from `assertion` and binds it to `data-binding`, then executes
  body."
  {:style/indent 1}
  [[data-binding assertion] & body]
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
      (throw (errors/validation-error :signature-validation assertion {:idp-cert idp-cert} e)))))

;; Verify that the `Recipient` attribute in any bearer `<SubjectConfirmationData>` matches the assertion consumer
;; service URL to which the `<Response>` or artifact was delivered.
(defmethod validate-assertion :recipient
  [_ assertion {:keys [acs-url]}]
  (validate-confirmation-datas [data assertion]
                               (let [recipient (.getRecipient data)]
    ;; Recipient field is REQUIRED if <SubjectConfirmationData> is present.
                                 (when-not recipient
                                   (throw (ex-info "<SubjectConfirmationData> does not contain a Recipient"
                                                   {:data (coerce/->xml-string data)})))
                                 (when-not acs-url
                                   (throw (ex-info "<SubjectConfirmationData> contains a Recipient but an acs-url was not passed to validate against"
                                                   {:data (coerce/->xml-string data)})))
                                 (when-not (= recipient acs-url)
                                   (throw (ex-info "<SubjectConfirmationData> Recipient does not match assertion consumer service URL"
                                                   {:data (coerce/->xml-string data), :acs-url acs-url}))))))

;; Verify that the NotOnOrAfter attribute in any bearer <SubjectConfirmationData> has not passed, subject to allowable
;; clock skew between the providers
(defmethod validate-assertion :not-on-or-after
  [_ assertion {:keys [allowable-clock-skew-seconds]
                :or {allowable-clock-skew-seconds com.onelogin.saml2.util.Constants/ALOWED_CLOCK_DRIFT}}]
  (validate-confirmation-datas [data assertion]
                               (let [not-on-or-after (some-> (.getNotOnOrAfter data) t/instant)]
                                 (when-not not-on-or-after
                                   (throw (ex-info "<SubjectConfirmationData> does not contain NotOnOrAfter"
                                                   {:data (coerce/->xml-string data)})))
                                 (when (t/after? (t/minus (t/instant) (t/seconds allowable-clock-skew-seconds))
                                                 not-on-or-after)
                                   (throw (ex-info "<SubjectConfirmationData> NotOnOrAfter has passed"
                                                   {:data (coerce/->xml-string data)
                                                    :not-on-or-after not-on-or-after
                                                    :now (t/instant)
                                                    :allowable-clock-skew-seconds allowable-clock-skew-seconds}))))))

(defmethod validate-assertion :not-before
  [_ assertion {:keys [allowable-clock-skew-seconds]
                :or {allowable-clock-skew-seconds com.onelogin.saml2.util.Constants/ALOWED_CLOCK_DRIFT}}]
  (validate-confirmation-datas [data assertion]
                               (when-let [not-before (some-> (.getNotBefore data) t/instant)]
                                 (when (t/before? (t/plus (t/instant) (t/seconds allowable-clock-skew-seconds))
                                                  not-before)
                                   (throw (ex-info "<SubjectConfirmationData> NotBefore is in the future"
                                                   {:data (coerce/->xml-string data)
                                                    :not-before not-before
                                                    :now (t/instant)
                                                    :allowable-clock-skew-seconds allowable-clock-skew-seconds}))))))

(defmethod validate-assertion :in-response-to
  [_ assertion {:keys [request-id solicited?]
                :or {solicited? true}}]
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
                                                       {:data (coerce/->xml-string data)
                                                        :request-id request-id})))
                                     (when in-response-to
                                       (throw (ex-info "<SubjectConfirmationData> InResponseTo should not be present for an unsolicited request"
                                                       {:data (coerce/->xml-string data)
                                                        :request-id request-id}))))))))

;; verifying the Address attribute is optional.
(defmethod validate-assertion :address
  [_ assertion {:keys [user-agent-address]}]
  (when user-agent-address
    (validate-confirmation-datas [data assertion]
                                 (when-let [address (.getAddress data)]
                                   (when-not (= address user-agent-address)
                                     (throw (ex-info "<SubjectConfirmationData> Address does not match user-agent-address"
                                                     {:data (coerce/->xml-string data)
                                                      :request-id user-agent-address})))))))

(defmethod validate-assertion :issuer
  [_ ^Assertion assertion {:keys [issuer]}]
  (when issuer
    (assert (string? issuer) "Expected :issuer to be a String")
    (let [assertion-issuer (or (some-> (.getIssuer assertion) .getValue)
                               (throw (ex-info "Assertion is missing required <Issuer> element" {})))]
      (when-not (= issuer assertion-issuer)
        (throw (ex-info "Incorrect Assertion <Issuer>" {}))))))

(defmethod validate-assertion :audience-restriction
  [_ ^Assertion assertion {:keys [sp-entity-id]}]
  (when sp-entity-id
    (let [conditions (.getConditions assertion)]
      (when conditions
        (let [audience-restrictions (.getAudienceRestrictions conditions)
              valid-audience? (some (fn [^AudienceRestriction restriction]
                                      (some (fn [^Audience audience]
                                              (= sp-entity-id (.getURI ^Audience audience)))
                                            (.getAudiences restriction)))
                                    audience-restrictions)]
          (when-not valid-audience?
            (throw (errors/validation-error :audience-restriction assertion
                                            {:expected-audience sp-entity-id
                                             :actual-audiences (mapv (fn [^AudienceRestriction restriction]
                                                                       (mapv #(.getURI ^Audience %)
                                                                             (.getAudiences restriction)))
                                                                     audience-restrictions)}))))))))

(defmethod validate-assertion :authn-statement
  [_ ^Assertion assertion {:keys [max-session-age-seconds]
                           :or {max-session-age-seconds 86400}}]
  (let [authn-statements (.getAuthnStatements assertion)]
    (when (empty? authn-statements)
      (throw (ex-info "Assertion must contain at least one AuthnStatement"
                      {:assertion-id (.getID assertion)})))
    (doseq [^AuthnStatement authn-stmt authn-statements]
      (when-let [authn-instant (.getAuthnInstant authn-stmt)]
        (let [age-seconds (t/as (t/duration (t/instant authn-instant) (t/instant)) :seconds)]
          (when (> age-seconds max-session-age-seconds)
            (throw (ex-info "AuthnStatement session has exceeded maximum age"
                            {:authn-instant authn-instant
                             :age-seconds age-seconds
                             :max-session-age-seconds max-session-age-seconds}))))))))

(defmethod validate-assertion :subject-confirmation-method
  [_ ^Assertion assertion _]
  (let [subject (.getSubject assertion)]
    (when subject
      (let [confirmations (.getSubjectConfirmations subject)
            valid-method? (some #(= "urn:oasis:names:tc:SAML:2.0:cm:bearer"
                                    (.getMethod ^SubjectConfirmation %))
                                confirmations)]
        (when-not valid-method?
          (throw (ex-info "No valid bearer SubjectConfirmation method found"
                          {:methods (map #(.getMethod ^SubjectConfirmation %) confirmations)})))))))

(defmethod validate-assertion :conditions
  [_ ^Assertion assertion {:keys [allowable-clock-skew-seconds]
                           :or {allowable-clock-skew-seconds com.onelogin.saml2.util.Constants/ALOWED_CLOCK_DRIFT}}]
  (when-let [conditions (.getConditions assertion)]
    (let [now (t/instant)
          not-before (some-> (.getNotBefore conditions) t/instant)
          not-on-or-after (some-> (.getNotOnOrAfter conditions) t/instant)]
      (when not-before
        (when (t/before? (t/plus now (t/seconds allowable-clock-skew-seconds)) not-before)
          (throw (ex-info "Conditions NotBefore is in the future"
                          {:not-before not-before
                           :now now
                           :allowable-clock-skew-seconds allowable-clock-skew-seconds}))))
      (when not-on-or-after
        (when (t/after? (t/minus now (t/seconds allowable-clock-skew-seconds)) not-on-or-after)
          (throw (ex-info "Conditions NotOnOrAfter has passed"
                          {:not-on-or-after not-on-or-after
                           :now now
                           :allowable-clock-skew-seconds allowable-clock-skew-seconds})))))))

(defmethod validate-assertion :one-time-use
  [_ ^Assertion assertion {:keys [state-manager]}]
  (when-let [^Conditions conditions (.getConditions assertion)]
    (let [one-time-use-condition (.getOneTimeUse conditions)]
      (when one-time-use-condition
        (when-not state-manager
          (throw (ex-info "OneTimeUse condition present but no state manager configured"
                          {:assertion-id (.getID assertion)})))
        (let [assertion-id (.getID assertion)]
          (when-not (state/accept-assertion! state-manager assertion-id)
            (throw (ex-info "Assertion has already been used (OneTimeUse violation)"
                            {:assertion-id assertion-id}))))))))

(defmethod validate-assertion :proxy-restriction
  [_ ^Assertion assertion _]
  (when-let [^Conditions conditions (.getConditions assertion)]
    (let [^ProxyRestriction proxy-restriction (.getProxyRestriction conditions)]
      (when proxy-restriction
        (let [proxy-count (.getProxyCount proxy-restriction)]
          (when (and proxy-count (zero? proxy-count))
            (throw (ex-info "ProxyRestriction violation: assertion cannot be proxied"
                            {:proxy-count proxy-count}))))))))

(defmethod validate-assertion :attribute-statement
  [_ ^Assertion assertion {:keys [require-attributes]}]
  (when require-attributes
    (let [attribute-statements (.getAttributeStatements assertion)]
      (when (empty? attribute-statements)
        (throw (errors/validation-error :missing-attribute-statement assertion
                                        {:assertion-id (.getID assertion)}))))))

(defmethod validate-assertion :authz-decision-statement
  [_ ^Assertion assertion {:keys [validate-authorization]}]
  (when validate-authorization
    (let [authz-statements (.getAuthzDecisionStatements assertion)]
      (doseq [^org.opensaml.saml.saml2.core.AuthzDecisionStatement stmt authz-statements]
        (let [decision (.getDecision stmt)]
          (when-not (= decision org.opensaml.saml.saml2.core.DecisionTypeEnumeration/PERMIT)
            (throw (errors/validation-error :authorization-denied assertion
                                            {:decision (str decision)
                                             :resource (.getResource stmt)
                                             :actions (map #(.getValue ^org.opensaml.saml.saml2.core.Action %)
                                                           (.getActions stmt))}))))))))

(defmethod validate-assertion :authn-context
  [_ ^Assertion assertion {:keys [required-authn-contexts]}]
  (when (seq required-authn-contexts)
    (let [authn-statements (.getAuthnStatements assertion)
          actual-contexts (for [^AuthnStatement stmt authn-statements
                                :let [^AuthnContext ctx (.getAuthnContext stmt)]
                                :when ctx]
                            (or (.getAuthnContextClassRef ctx)
                                (.getAuthnContextDeclRef ctx)))
          context-values (map (fn [ref] (when ref (.getURI ^AuthnContextClassRef ref)))
                              (remove nil? actual-contexts))]
      (when-not (some (set required-authn-contexts) context-values)
        (throw (errors/validation-error :invalid-authn-context assertion
                                        {:required-contexts required-authn-contexts
                                         :actual-contexts context-values}))))))

(defmethod validate-assertion :replay-prevention
  [_ ^Assertion assertion {:keys [state-manager]}]
  (when state-manager
    (let [assertion-id (.getID assertion)]
      (when (state/is-duplicate? state-manager assertion-id)
        (throw (errors/validation-error
                :replay-prevention
                assertion
                {:severity :high
                 :assertion-id assertion-id
                 :error-message "Assertion has been processed before (replay attack detected)"}
                nil)))
      ;; Record the assertion to prevent future replay
      (state/accept-assertion! state-manager assertion-id)
      ;; Return nil to indicate successful validation
      nil)))

(defmethod validate-assertion :signature-algorithm
  [_ ^Assertion assertion _]
  (when-let [signature (.getSignature assertion)]
    (crypto/validate-signature-algorithm signature)))

(defmethod validate-assertion :encryption-algorithm
  [_ assertion _]
  ;; This validator would need access to the encrypted assertion element
  ;; For now, we'll skip this validation on decrypted assertions
  nil)

(def ^:private default-validation-options
  {:response-validators [:signature
                         :issuer
                         :in-response-to
                         :require-authenticated
                         :status-code]
   :assertion-validators [:signature
                          :recipient
                          :not-on-or-after
                          :not-before
                          :in-response-to
                          :address
                          :issuer
                          :audience-restriction
                          :subject-confirmation-method
                          :conditions]})

(def ^:private web-browser-sso-validations
  "Standard validations for SAML 2.0 Web Browser SSO Profile"
  {:response-validators [:signature :issuer :in-response-to :status-code :require-authenticated]
   :assertion-validators [:signature :recipient :not-on-or-after :not-before
                          :audience-restriction :subject-confirmation-method
                          :authn-statement :conditions]})

(def ^:private sp-initiated-validations
  "Validations for SP-initiated Web Browser SSO flow"
  (assoc web-browser-sso-validations
         :assertion-validators (conj (:assertion-validators web-browser-sso-validations)
                                     :in-response-to)))

(def ^:private idp-initiated-validations
  "Validations for IdP-initiated Web Browser SSO flow"
  (assoc web-browser-sso-validations
         :assertion-validators (remove #{:in-response-to}
                                       (:assertion-validators web-browser-sso-validations))))

(defn- validate-response
  "Validate response. Returns decrypted response if valid. Options:

  * `:response-validators` - optional. The validators to run against the `<Response>` itself. Validators are
     implemented as methods of `validate-response`. If this is not passed, uses validators defined in
     `default-validation-options`.

  * `:assertion-validators` - optional. the validators to run against each `<Assertion>` in the response. Validators are
    implemented as methods of `validate-assertion`. If this is not passed, uses validators defined in
    `default-validation-options`.

  * `:acs-url` - REQUIRED. Assertion consumer service URL. The `:recipient` assertion validates this.

  * `:request-id` - optional. Validated by the `:in-response-to` validator if passed.

  * `:state-manager` - optional. An instance of `StateManager` (such as `in-memory-state-manager`) that can check
    whether a Response with the given ID was already processed.

  * `:user-agent-address` - optional. Address of the client. If present, the `:address` validator will check that any
    `Address` information in the `<SubjectConfimrationData>` passes.

  * `:issuer` - optional. Unique identifier for the IdP. If passed, the `:issuer` validators will validate any
    `Issuer` information present on the `<Response>`, and the `Issuer` of each `<Assertion>` (`Issuer` is required for
    Assertions).

  * `:solicited?` - optional. Whether this request is the result of an SSO login flow initiated by the SP (us). If
    this is `false`, the :in-response-to` validator checks that the `request-id` in `nil`.

  * `:allowable-clock-skew-seconds` - optional. By default, 3 minutes. The amount of leeway to use when validating
    `NotOnOrAfter` and `NotBefore` attributes."
  {:arglists '([response idp-cert sp-private-key]
               [response {:keys [response-validators
                                 assertion-validators
                                 acs-url
                                 request-id
                                 state-manager
                                 user-agent-address
                                 issuer
                                 solicited?
                                 allowable-clock-skew-seconds]}])}
  (^Response [req idp-cert sp-private-key]
   (validate-response req {:idp-cert idp-cert
                           :sp-private-key sp-private-key}))

  (^Response [req options]
   (let [options (-> (merge default-validation-options options)
                     (assoc :request req :request-builder (AuthnRequestBuilder.)))
         {:keys [response-validators
                 assertion-validators
                 sp-private-key]} options]
     (when-let [msg-ctx (coerce/ring-request->MessageContext req)]

       (let [decrypted-response (cond-> (coerce/->Response msg-ctx)
                                  sp-private-key (decrypt-response sp-private-key))]
         (doseq [validator response-validators]
           (message/validate-message validator msg-ctx (assoc options :decrypted-response decrypted-response)))
         (doseq [assertion (opensaml-assertions decrypted-response)
                 validator assertion-validators]
           (validate-assertion validator assertion options))
         ;; TODO: repalce this with usage of opensaml's client storage system
         (when-let [state-manager (:state-manager options)]
           (state/accept-response! state-manager (.getInResponseTo decrypted-response)))
         decrypted-response)))))

(defn create-validation-config
  "Create a validation configuration for a specific flow type with optional custom validations.
  
  Arguments:
  - flow-type: :sp-initiated, :idp-initiated, or :default
  - custom-validations: optional map to override or extend default validations
  
  Returns: a validation configuration map suitable for use with validate-response"
  [flow-type & [custom-validations]]
  (let [base-config (case flow-type
                      :sp-initiated sp-initiated-validations
                      :idp-initiated idp-initiated-validations
                      :default web-browser-sso-validations
                      web-browser-sso-validations)]
    (if custom-validations
      (merge base-config custom-validations)
      base-config)))

(defn validate-configuration
  "Validates that a configuration map has the required structure and supported validators.

  Arguments:
  - config: validation configuration map

  Returns: validated configuration map or throws exception"
  [config]
  (let [valid-response-validators #{:signature :issuer :in-response-to :status-code :require-authenticated}
        valid-assertion-validators #{:signature :recipient :not-on-or-after :not-before
                                     :in-response-to :address :issuer :audience-restriction
                                     :authn-statement :subject-confirmation-method :conditions
                                     :one-time-use :proxy-restriction :attribute-statement
                                     :authz-decision-statement :authn-context :replay-prevention}
        response-validators (set (:response-validators config))
        assertion-validators (set (:assertion-validators config))

        invalid-response (clojure.set/difference response-validators valid-response-validators)
        invalid-assertion (clojure.set/difference assertion-validators valid-assertion-validators)]

    (when (seq invalid-response)
      (throw (ex-info "Invalid response validators"
                      {:invalid-validators invalid-response
                       :valid-validators valid-response-validators})))

    (when (seq invalid-assertion)
      (throw (ex-info "Invalid assertion validators"
                      {:invalid-validators invalid-assertion
                       :valid-validators valid-assertion-validators})))

    config))

(defn create-strict-validation-config
  "Creates a strict validation configuration with maximum security.
  
  Arguments:
  - flow-type: :sp-initiated, :idp-initiated, or :default
  - custom-validations: optional map of custom validation overrides
  
  Returns: validated configuration map with strict validation settings"
  [flow-type & [custom-validations]]
  (let [base-config (create-validation-config flow-type)
        strict-config (-> base-config
                          (update :assertion-validators conj :replay-prevention)
                          (update :assertion-validators conj :one-time-use)
                          (update :assertion-validators conj :proxy-restriction)
                          (assoc :allowable-clock-skew-seconds 60) ; Stricter timing
                          (assoc :max-session-age-seconds 3600) ; 1 hour max session
                          (assoc :require-attributes true) ; Require attributes
                          (assoc :validate-authorization true)) ; Validate authz decisions
        merged-config (merge strict-config custom-validations)]
    (validate-configuration merged-config)))

(defn create-relaxed-validation-config
  "Creates a relaxed validation configuration for testing or development.
  
  Arguments:
  - flow-type: :sp-initiated, :idp-initiated, or :default
  - custom-validations: optional map of custom validation overrides
  
  Returns: validated configuration map with relaxed validation settings"
  [flow-type & [custom-validations]]
  (let [base-config (create-validation-config flow-type)
        relaxed-config (-> base-config
                           (update :assertion-validators (fn [validators]
                                                           (remove #{:replay-prevention :one-time-use} validators)))
                           (assoc :allowable-clock-skew-seconds 300) ; 5 minutes
                           (assoc :max-session-age-seconds 86400) ; 24 hours
                           (assoc :require-attributes false) ; Don't require attributes
                           (assoc :validate-authorization false)) ; Don't validate authz
        merged-config (merge relaxed-config custom-validations)]
    (validate-configuration merged-config)))

(defprotocol CustomValidator
  "Protocol for custom validation extensions"
  (validate-custom [this element options context]
    "Validates a SAML element with custom logic.
    
    Arguments:
    - this: the custom validator instance
    - element: the SAML element to validate (Response or Assertion)
    - options: validation options map
    - context: validation context map
    
    Returns: nil on success, throws exception on failure"))

(def ^:private custom-validators
  "Registry for custom validation plugins"
  (atom {}))

(defn register-validation-plugin
  "Register a custom validation plugin.
  
  Arguments:
  - plugin-name: keyword name for the plugin
  - plugin-fn: function that implements CustomValidator protocol
  
  Returns: nil"
  [plugin-name plugin-fn]
  (when-not (keyword? plugin-name)
    (throw (ex-info "Plugin name must be a keyword" {:plugin-name plugin-name})))
  (when-not (satisfies? CustomValidator plugin-fn)
    (throw (ex-info "Plugin must implement CustomValidator protocol" {:plugin-name plugin-name})))
  (swap! custom-validators assoc plugin-name plugin-fn)
  nil)

(defn unregister-validation-plugin
  "Unregister a custom validation plugin.
  
  Arguments:
  - plugin-name: keyword name of the plugin to remove
  
  Returns: nil"
  [plugin-name]
  (swap! custom-validators dissoc plugin-name))

(defn validate-plugin-configuration
  "Validates that all registered plugins implement the CustomValidator protocol.
  
  Returns: list of validation errors, empty if all plugins are valid"
  []
  (let [plugins @custom-validators]
    (reduce (fn [errors [plugin-name plugin-fn]]
              (if (satisfies? CustomValidator plugin-fn)
                errors
                (conj errors {:plugin-name plugin-name
                              :error "Plugin does not implement CustomValidator protocol"})))
            []
            plugins)))

(defn get-plugin-info
  "Gets information about a specific plugin or all plugins.
  
  Arguments:
  - plugin-name: optional keyword name of specific plugin
  
  Returns: plugin info map or collection of plugin info maps"
  ([]
   (map (fn [[name plugin-fn]]
          {:name name
           :implements-protocol? (satisfies? CustomValidator plugin-fn)
           :type (type plugin-fn)})
        @custom-validators))
  ([plugin-name]
   (when-let [plugin-fn (get @custom-validators plugin-name)]
     {:name plugin-name
      :implements-protocol? (satisfies? CustomValidator plugin-fn)
      :type (type plugin-fn)})))

(defn list-validation-plugins
  "List all registered validation plugins.
  
  Returns: set of plugin names"
  []
  (set (keys @custom-validators)))

(defn apply-custom-validations
  "Apply custom validation plugins to a SAML element.
  
  Arguments:
  - element: the SAML element to validate (Response or Assertion)
  - options: validation options map
  - context: validation context map
  
  Returns: nil on success, throws exception on failure"
  [element options context]
  (doseq [[plugin-name plugin-fn] @custom-validators]
    (try
      (validate-custom plugin-fn element options context)
      (catch Exception e
        (throw (ex-info (str "Custom validation plugin failed: " plugin-name)
                        {:plugin-name plugin-name
                         :original-error (ex-data e)
                         :original-message (.getMessage e)}
                        e))))))

(defn validate-response-for-profile
  "Validate response according to a specific SAML profile. Profiles:
   - :sp-initiated - SP-initiated Web Browser SSO flow (requires InResponseTo)
   - :idp-initiated - IdP-initiated Web Browser SSO flow (no InResponseTo required)
   - :default - Standard Web Browser SSO validations"
  [response profile options]
  (let [profile-config (case profile
                         :sp-initiated sp-initiated-validations
                         :idp-initiated idp-initiated-validations
                         :default web-browser-sso-validations
                         web-browser-sso-validations)
        merged-options (merge profile-config options)]
    (validate-response response merged-options)))

;;; +----------------------------------------------------------------------------------------------------------------+
;;; |                                        Convenient Clojurey Map Util Fns                                        |
;;; +----------------------------------------------------------------------------------------------------------------+

(defn response-status
  "Parses and returns information about the status (i.e. successful or not), the version, addressing info etc. of the
  SAML response

  Check the javadoc of OpenSAML at:

  https://web.archive.org/web/20150421234900/https://build.shibboleth.net/nexus/service/local/repositories/releases/archive/org/opensaml/opensaml/2.5.3/opensaml-2.5.3-javadoc.jar/!/index.html"
  [response]
  (when-let [response (coerce/->Response response)]
    (let [status (.. response getStatus getStatusCode getValue)]
      {:in-response-to (.getInResponseTo response)
       :status status
       :success? (= status org.opensaml.saml.saml2.core.StatusCode/SUCCESS)
       :version (.. response getVersion toString)
       :issue-instant (t/instant (.getIssueInstant response))
       :destination (.getDestination response)})))

;; https://www.purdue.edu/apps/account/docs/Shibboleth/Shibboleth_information.jsp
;;  Or
;; https://wiki.library.ucsf.edu/display/IAM/EDS+Attributes
(def ^:private -saml2-attr->name {"urn:oid:0.9.2342.19200300.100.1.1" "uid"
                                  "urn:oid:0.9.2342.19200300.100.1.3" "mail"
                                  "urn:oid:2.16.840.1.113730.3.1.241" "displayName"
                                  "urn:oid:2.5.4.3" "cn"
                                  "urn:oid:2.5.4.4" "sn"
                                  "urn:oid:2.5.4.12" "title"
                                  "urn:oid:2.5.4.20" "phone"
                                  "urn:oid:2.5.4.42" "givenName"
                                  "urn:oid:2.5.6.8" "organizationalRole"
                                  "urn:oid:2.16.840.1.113730.3.1.3" "employeeNumber"
                                  "urn:oid:2.16.840.1.113730.3.1.4" "employeeType"
                                  "urn:oid:1.3.6.1.4.1.5923.1.1.1.1" "eduPersonAffiliation"
                                  "urn:oid:1.3.6.1.4.1.5923.1.1.1.2" "eduPersonNickname"
                                  "urn:oid:1.3.6.1.4.1.5923.1.1.1.6" "eduPersonPrincipalName"
                                  "urn:oid:1.3.6.1.4.1.5923.1.1.1.9" "eduPersonScopedAffiliation"
                                  "urn:oid:1.3.6.1.4.1.5923.1.1.1.10" "eduPersonTargetedID"
                                  "urn:oid:1.3.6.1.4.1.5923.1.6.1.1" "eduCourseOffering"})

(defn- saml2-attr->name [attr-oid]
  (get -saml2-attr->name attr-oid attr-oid))

;; http://kevnls.blogspot.gr/2009/07/processing-saml-in-java-using-opensaml.html
;; http://stackoverflow.com/questions/9422545/decrypting-encrypted-assertion-using-saml-2-0-in-java-using-opensaml
(defn Assertion->map
  "Returns the attributes and the 'audiences' for the given SAML assertion"
  [^Assertion assertion]
  (when assertion
    (let [statements (.getAttributeStatements assertion)
          subject (.getSubject assertion)
          subject-data (.getSubjectConfirmationData ^SubjectConfirmation (first (.getSubjectConfirmations subject)))
          name-id (.getNameID subject)
          attrs (->> (for [^AttributeStatement statement statements
                           ^Attribute attribute (.getAttributes statement)]
                       {(saml2-attr->name (.getName attribute)) ; Or (.getFriendlyName a) ??
                        (map #(-> ^org.opensaml.core.xml.XMLObject % .getDOM .getTextContent)
                             (.getAttributeValues attribute))})
                     (apply (partial merge-with concat)))
          audiences (for [^AudienceRestriction restriction (.. assertion getConditions getAudienceRestrictions)
                          ^Audience audience (.getAudiences restriction)]
                      (.getURI audience))]
      {:attrs attrs
       :audiences audiences
       :name-id {:value (some-> name-id .getValue)
                 :format (some-> name-id .getFormat)}
       :confirmation {:in-response-to (.getInResponseTo subject-data)
                      :not-before (some-> (.getNotBefore subject-data) (t/instant))
                      :not-on-or-after (t/instant (.getNotOnOrAfter subject-data))
                      :address (.getAddress subject-data)
                      :recipient (.getRecipient subject-data)}})))

(defn assertions
  "Returns the assertions (encrypted or not) of a SAML Response object"
  ([possibly-encrypted-response sp-private-key]
   (assertions (decrypt-response possibly-encrypted-response sp-private-key)))

  ([decrypted-response]
   (when-let [assertions (opensaml-assertions decrypted-response)]
     (map Assertion->map assertions))))
