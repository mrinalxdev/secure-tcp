#_{:clj-kondo/ignore [:namespace-name-mismatch]}
(ns psk-secure-channel.protocol)

(def protocol-version "psk-secure-channel-v1")

(def msg-client-hello 0x01)
(def msg-server-hello  0x02)
(def msg-client-finished 0x03)
(def msg-server-finished 0x04)
(def msg-app-data 0x10)
(def random-size 32)
(def key-size 32)
(def tag-size 16)
(def max-frame-size 65535)