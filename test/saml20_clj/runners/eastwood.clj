(ns saml20-clj.runners.eastwood
  (:require [clojure.java.classpath :as classpath]
            [clojure.string :as str]
            [eastwood.lint :as eastwood]))

(defn source-paths []
  (filter (fn [^java.io.File file]
            (and (.isDirectory ^java.io.File file)
                 (not (str/ends-with? (.getName file) "resources"))))
          (classpath/system-classpath)))

(defn eastwood [options]
  (eastwood/eastwood-from-cmdline
   (merge
    {:source-paths (source-paths)}
    options)))
