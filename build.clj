(ns build
  (:require [clojure.java.shell :as sh]
            [clojure.string :as str]
            [clojure.tools.build.api :as b]
            [deps-deploy.deps-deploy :as dd]))

(def scm-url "git@github.com:metabase/saml20-clj.git")
(def github-url "https://github.com/metabase/saml20-clj/")
(def lib 'metabase/saml20-clj)

(def version (str/trim (slurp "VERSION.txt")))

(def target    "target")
(def class-dir "target/classes")
(def jar-file  (format "target/%s-%s.jar" lib version))


(def sha
  (or (not-empty (System/getenv "GITHUB_SHA"))
      (not-empty (-> (sh/sh "git" "rev-parse" "HEAD")
                     :out
                     str/trim))))

(def pom-template
  [[:description "A library for delightful database interaction."]
   [:url github-url]
   [:licenses
    [:license
     [:name "Eclipse Public License"]
     [:url "http://www.eclipse.org/legal/epl-v10.html"]]]
   [:developers
    [:developer
     [:name "Cam Saul"]]]
   [:scm
    [:url github-url]
    [:connection (str "scm:git:" scm-url)]
    [:developerConnection (str "scm:git:" scm-url)]
    [:tag sha]]])

(def default-options
  {:lib       lib
   :version   version
   :jar-file  jar-file
   :basis     (b/create-basis {})
   :class-dir class-dir
   :target    target
   :src-dirs  ["src"]
   :pom-data  pom-template})

(defn build [opts]
  (let [opts (merge default-options opts)]
    (b/delete {:path target})
    (println "\nWriting pom.xml...")
    (b/write-pom opts)
    (println "\nCopying source...")
    (b/copy-dir {:src-dirs   ["src" "resources"]
                 :target-dir class-dir})
    (printf "\nBuilding %s...\n" jar-file)
    (b/jar opts)
    (println "Done.")))

(defn install [opts]
  (printf "Installing %s to local Maven repository...\n" version)
  (b/install (merge default-options opts)))

(defn build-and-install [opts]
  (build opts)
  (install opts))

(defn deploy [opts]
  (let [opts (merge default-options opts)]
    (printf "Deploying %s...\n" jar-file)
    (dd/deploy {:installer :remote
                :artifact  (b/resolve-path jar-file)
                :pom-file  (b/pom-path (select-keys opts [:lib :class-dir]))})
    (println "Done.")))
