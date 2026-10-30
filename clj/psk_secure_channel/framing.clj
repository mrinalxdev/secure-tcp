(ns psk-secure-channel.framing
  (:require [psk-secure-channel.protocol :as proto]))

(defn write-u16
  [out len]
  (let [b1 (bit-and (bit-shift-right len 8) 0xFF)
        b2 (bit-and len 0xFF)]
    (.write out (byte b1))
    (.write out (byte b2))))

(defn read-u16
  [in]
  (let [b1 (.read in)
        b2 (.read in)]
    (when (or (neg? b1) (neg? b2))
      (throw (ex-info "Unexpected EOF while reading length" {})))
    (bit-or (bit-shift-left (bit-and b1 0xFF) 8)
            (bit-and b2 0xFF))))

(defn write-frame 
  [^java.io.OutputStream out payload]
  (let [len (count payload)]
    (when (> len proto/max-frame-size)
      (throw (ex-info "Frame too large" {:len len})))
    (write-u16 out len)
    (.write out (byte-array payload))
    (.flush out)))

(defn read-frame
  [^java.io.InputStream in]
  (let [len (read-u16 in)]
    (when (or (neg? len) (> len proto/max-frame-size))
      (throw (ex-info "Invalid frame length" {:len len})))
    (let [buf (byte-array len)
          n (.read in buf)]
      (when (not= n len)
        (throw (ex-info "Short read on frame" {:expected len :got n})))
      buf)))