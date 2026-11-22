package com.demobank;

import java.security.*;
import javax.crypto.Cipher;
import org.springframework.stereotype.Service;

/** Typical bank service: ONE signer reused by every HTTP request thread (vulnerable). */
@Service
public class PaymentSigningService {
  private final Signature signer;                 // EXPECT PQS001 HIGH (singleton field)
  private final Cipher legacyCipher;              // EXPECT PQS001 HIGH (singleton field)
  private final PrivateKey key;

  public PaymentSigningService(PrivateKey key) throws Exception {
    this.key = key;
    this.signer = Signature.getInstance("ML-DSA");                         // inventory: post-quantum
    this.legacyCipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding"); // inventory: quantum-vulnerable
  }

  public byte[] signTransfer(byte[] transfer) throws Exception {
    signer.initSign(key);
    signer.update(transfer);
    return signer.sign();
  }
}
