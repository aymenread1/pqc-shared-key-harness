// JCStress test: two actors sign concurrently with ONE shared Bouncy Castle ML-DSA private key;
// the arbiter verifies both signatures. Any outcome other than "true, true" is a correctness
// failure caused by concurrent use of the shared key object.
// Author: Ayman Alsadig Mohamed Suliman
// Needs: jcstress-core 0.16 (+ jopt-simple), bcprov-jdk18on 1.79+. Run via ../../run-all.sh
// (compile with -proc:full so the JCStress annotation processor runs).
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.openjdk.jcstress.annotations.*;
import org.openjdk.jcstress.infra.results.ZZ_Result;

import java.nio.charset.StandardCharsets;
import java.security.*;

import static org.openjdk.jcstress.annotations.Expect.*;

@JCStressTest
@Outcome(id = "true, true", expect = ACCEPTABLE, desc = "Both signatures from the shared key verify.")
@Outcome(expect = FORBIDDEN, desc = "A signature made concurrently with the shared key failed to verify or threw.")
@State
public class BcSharedKeyStress {
  static final String ALG = System.getProperty("pqc.alg", "ML-DSA");
  static final PrivateKey SK;   // shared by every actor of every state instance
  static final PublicKey PK;
  static final byte[] M1 = "message-one".getBytes(StandardCharsets.US_ASCII);
  static final byte[] M2 = "message-two".getBytes(StandardCharsets.US_ASCII);

  static {
    try {
      Security.addProvider(new BouncyCastleProvider());
      KeyPair kp = KeyPairGenerator.getInstance(ALG, "BC").generateKeyPair();
      SK = kp.getPrivate();
      PK = kp.getPublic();
    } catch (GeneralSecurityException e) {
      throw new ExceptionInInitializerError(e);
    }
  }

  byte[] sig1, sig2;

  static byte[] sign(byte[] m) {
    try {
      Signature s = Signature.getInstance(ALG, "BC");
      s.initSign(SK);
      s.update(m);
      return s.sign();
    } catch (GeneralSecurityException | RuntimeException e) {
      return null;  // surfaces as "false" in the arbiter
    }
  }

  static boolean verify(byte[] m, byte[] sig) {
    if (sig == null) return false;
    try {
      Signature v = Signature.getInstance(ALG, "BC");
      v.initVerify(PK);
      v.update(m);
      return v.verify(sig);
    } catch (GeneralSecurityException | RuntimeException e) {
      return false;
    }
  }

  @Actor public void actor1() { sig1 = sign(M1); }
  @Actor public void actor2() { sig2 = sign(M2); }

  @Arbiter
  public void arbiter(ZZ_Result r) {
    r.r1 = verify(M1, sig1);
    r.r2 = verify(M2, sig2);
  }
}
