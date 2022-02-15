(ns saml20-clj.runners.test
  (:refer-clojure :exclude [test])
  (:require [cognitect.test-runner.api :as test-runner]
            [pjstadig.humane-test-output :as humane-test-output]))

(humane-test-output/activate!)

(defn test [& args]
  (apply test-runner/test args))
