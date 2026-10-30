(ns psk-secure-channel.handshake
  (:require [psk-secure-channel.protocol :as proto]
            [psk-secure-channel.framing :as framing]))

(defn generate-random 
  []
  (let [buf (byte-array proto/random-size)]
    (.nextBytes (java.security.SecureRandom.) buf)
    buf))

(defn build-hello 
  [msg-type random-bytes]
  (byte-array (concat [(unchecked-byte msg-type)]
                      (seq random-bytes))))

(defn parse-hello 
  [payload]
  (when (< (count payload) (inc proto/random-size))
    (throw (ex-info "Hello message too short" {})))
  {:type (bit-and (first payload) 0xFF)
   :random (byte-array (subvec (vec payload) 1 (inc proto/random-size)))})

(defn build-finished
 
  [msg-type transcript-hash]
  (byte-array (concat [(unchecked-byte msg-type)]
                      (seq transcript-hash))))

(defn transcript-hash 
  [client-random server-random]
  (let [md (java.security.MessageDigest/getInstance "SHA-256")
        combined (byte-array (concat (seq client-random) (seq server-random)))]
    (.digest md combined)))