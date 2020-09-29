(defproject metabase/saml20-clj "2.0.0-alpha2-SNAPSHOT"
  :description "Improved SAML 2.0 library for SSO."
  :url "https://github.com/metabase/saml20-clj"
  :min-lein-version "2.5.0"

  :license {:name "Eclipse Public License"
            :url  "https://raw.githubusercontent.com/metabase/saml20-clj/master/LICENSE"}

  :aliases
  {"test"                      ["with-profile" "+test" "test"]
   "bikeshed"                  ["with-profile" "+bikeshed" "bikeshed" "--max-line-length" "150"]
   "check-namespace-decls"     ["with-profile" "+check-namespace-decls" "check-namespace-decls"]
   "eastwood"                  ["with-profile" "+eastwood" "eastwood"]
   "check-reflection-warnings" ["with-profile" "+reflection-warnings" "check"]
   "cloverage"                 ["with-profile" "+cloverage" "cloverage"]
   ;; `lein lint` will run all linters
   "lint"                      ["do" ["eastwood"] ["bikeshed"] ["check-namespace-decls"] ["cloverage"]]}

  ;; OpenSAML isn't officially on Maven Central -- https://wiki.shibboleth.net/confluence/display/DEV/Use+of+Maven+Central
  :repositories
  [["opensaml" "https://build.shibboleth.net/nexus/content/repositories/releases/"]]

  :dependencies
  [[org.clojure/spec.alpha "0.2.187"]
   [org.clojure/tools.logging "1.1.0"]
   [com.onelogin/java-saml "2.5.0"]
   [clojure.java-time "0.3.2"]
   [commons-io/commons-io "2.8.0"]
   [hiccup "1.0.5"]
   [org.opensaml/opensaml-core "3.4.5"]
   [org.opensaml/opensaml-saml-api "3.4.5"]
   [org.opensaml/opensaml-saml-impl "3.4.5"]
   [org.opensaml/opensaml-xmlsec-api "3.4.5"]
   [org.opensaml/opensaml-xmlsec-impl "3.4.5"]
   [potemkin "0.4.5"]
   [pretty "1.0.4"]
   [ring/ring-codec "1.1.2"]]

  :profiles
  {:dev
   {:dependencies
    [[org.clojure/clojure "1.10.1"]
     [pjstadig/humane-test-output "0.10.0"]]

    :injections
    [(require 'pjstadig.humane-test-output)
     (pjstadig.humane-test-output/activate!)]

    :jvm-opts
    ["-Xverify:none"]}

   :repl
   {:global-vars {*warn-on-reflection* true}}

   :eastwood
   {:plugins
    [[jonase/eastwood "0.3.11" :exclusions [org.clojure/clojure]]]

    :eastwood
    {:add-linters
     [:unused-fn-args
      :unused-locals]

     :exclude-linters
     [:deprecations
      :unused-ret-vals
      :implicit-dependencies]}}

   :reflection-warnings
   {:global-vars {*warn-on-reflection* true}}

   :bikeshed
   {:plugins
    [[lein-bikeshed "0.5.2"]]}

   :check-namespace-decls
   {:plugins               [[lein-check-namespace-decls "1.0.2"]]
    :source-paths          ["test"]
    :check-namespace-decls {:prefix-rewriting false}}

   :cloverage
   ;; Using Cam's fork of Cloverage until 1.2.1 of the main repo is out. Once that's released we can switch back.
   {:dependencies [[camsaul/cloverage "1.2.1.1"]]
    :plugins      [[camsaul/lein-cloverage  "1.2.1.1"]]
    :cloverage    {:fail-threshold 66}}}

  :deploy-repositories
  [["clojars"
    {:url           "https://clojars.org/repo"
     :username      :env/clojars_username
     :password      :env/clojars_deploy_token
     :sign-releases false}]])
