package com.demobank;

import java.security.*;

@org.springframework.stereotype.Component
public class SafeSigner {
  private static final ThreadLocal<Signature> SIG = ThreadLocal.withInitial(() -> {   // EXPECT PQS000 INFO
    try { return Signature.getInstance("ML-DSA"); } catch (Exception e) { throw new RuntimeException(e); }
  });
  private final KeyPairGenerator kpg;                  // not an engine type we flag

  public SafeSigner() throws Exception { kpg = KeyPairGenerator.getInstance("ML-KEM-768"); }

  public byte[] sign(PrivateKey k, byte[] m) throws Exception {
    Signature s = SIG.get();
    s.initSign(k); s.update(m); return s.sign();
  }

  public KeyAgreement ecdh() throws Exception { return KeyAgreement.getInstance("ECDH"); }
}
