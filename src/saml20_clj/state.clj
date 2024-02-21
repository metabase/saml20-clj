(ns saml20-clj.state
  (:require [java-time.api :as t]
            [pretty.core :as pretty]))

(defprotocol StateManager
  "Protocol for managing state for recording which requests are in flight, so we can determine whether responses
  correspond to valid requests. This library ships with a simple in-memory implementation, but this interface is
  provided so that you can provide your own implementation if you need to do something more sophisticated (such as
  synchronizing across multiple instances)."
  (record-request! [this request-id]
    "Called whenever a new request to the IdP goes out. The state manager should record `request-id` (and probably the
    current timestamp as well) so it can be used for validating responses.")

  ;; TODO -- consider renaming this to handle-response! or something else clearer
  (accept-response! [this request-id]
    "Called whenever a new response from IdP is received. The state manager should verify that `request-id` was
 actually issued by us (e.g., one we've seen earlier when `record-request!`), and (hopefully) that it is not too old;
 if the response is not acceptable, it must throw an Exception. The state manager should remove the request from its
 state a response with the same ID cannot be used again (e.g. to prevent replay attacks)."))

;; in-memory-state-manager state works like this:
;;
;; - State consists of three buckets. After every timeout/2 seconds, the oldest bucket is dropped and a new one is
;; created. Buckets are thus:
;;
;; 1. Requests created after last rotation. Thus requests in this bucket are between 0 and timeout/2 seconds old.
;;
;; 2. Requests that have survived one rotation. Requests in this bucket are between ~0 and timeout seconds old. (They
;; can be ~0 if they were added to the bucket immediately before it was rotated, and rotation just occurred; or
;; ~timeout if they were added to the bucket when it was first created and the next rotation is about to occur).
;;
;; 3. Requests that have survived two rotations. Requests in this bucket are at least timeout/2 seconds old, and at
;; most (timeout*1.5) seconds old.
;;
;; Thus after the two rotations we know a request is at least timeout/2 seconds old, and after three we know it is
;; older than timeout and can drop it.
;;
;; buckets look like: [bucket-created-instant #{request-id}]
;;
;; Note that this means `timeout` means the earliest that a request ID gets dropped, but does not guarantee it will be
;; dropped by then; it make take up to timeout*1.5.

(defn- prune-buckets [state request-timeout-seconds]
  (let [now                                        (t/instant)
        [[bucket-1-created :as bucket-1] bucket-2] state]
    (letfn [(new-bucket []
              [now #{}])]
      (cond
        ;; state not initialized yet.
        (not bucket-1)
        [(new-bucket)]

        ;; all buckets are too old
        (t/before? bucket-1-created (t/minus now (t/seconds request-timeout-seconds)))
        [(new-bucket)]

        ;; bucket 1 is past the threshold and it's time to rotate the buckets
        (t/before? bucket-1-created (t/minus now (t/seconds (int (/ request-timeout-seconds 2)))))
        [(new-bucket) bucket-1 bucket-2]

        ;; not time to rotate the buckets yet
        :else
        state))))

(defn- in-memory-state-manager-record-request [state request-timeout-seconds request-id]
  (let [state (prune-buckets state request-timeout-seconds)]
    (update-in state [0 1] conj request-id)))

(defn- in-memory-state-manager-accept-response [state request-timeout-seconds request-id]
  (let [state (prune-buckets state request-timeout-seconds)]
    (or (some (fn [bucket-index]
                (when (contains? (get-in state [bucket-index 1]) request-id)
                  (update-in state [bucket-index 1] disj request-id)))
              [0 1 2])
        (throw (ex-info "Invalid request ID" {:request-id request-id})))))

;; 5 minutes, in case people decide they want to sit around on the IdP page for a bit.
(def default-request-timeout-seconds 300)

(defn in-memory-state-manager
  "A simple in-memory state manager, suitable for a single instance. Requests IDs are considered valid for a minimum of
  `request-timeout-seconds`."
  ([]
   (in-memory-state-manager default-request-timeout-seconds))

  ([request-timeout-seconds]
   (in-memory-state-manager request-timeout-seconds []))

  ([request-timeout-seconds initial-state]
   (let [state (atom initial-state)]
     (reify
       pretty/PrettyPrintable
       (pretty [_]
         (list `in-memory-state-manager request-timeout-seconds @state))

       StateManager
       (record-request! [_ request-id]
         (swap! state in-memory-state-manager-record-request request-timeout-seconds request-id))
       (accept-response! [_ request-id]
         (swap! state in-memory-state-manager-accept-response request-timeout-seconds request-id))

       ;; this is here mostly for convenience and testability: deref the state manager itself to see what's in the
       ;; state atom
       clojure.lang.IDeref
       (deref [_]
         @state)))))
