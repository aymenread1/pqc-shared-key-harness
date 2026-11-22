package com.demobank;

import java.security.*;

public final class LegacyUtil {
  public static final Signature RSA_SIGNER;            // EXPECT PQS001 HIGH (static)
  static {
    try { RSA_SIGNER = Signature.getInstance("SHA256withRSA"); } catch (Exception e) { throw new RuntimeException(e); }
  }
  // private static Signature commentedOut;           // commented out: not reported
  /* static MessageDigest alsoCommented; */
  private MessageDigest md;                            // EXPECT PQS001 MEDIUM (plain instance field)

  public byte[] hashLocal(byte[] in) throws Exception {
    MessageDigest local = MessageDigest.getInstance("SHA-256");   // local variable: not reported
    return local.digest(in);
  }
}
