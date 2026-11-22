// Java portable harness: shared Bouncy Castle PQC key across threads.
// Author: Ayman Alsadig Mohamed Suliman
// Needs: JDK 17+, bcprov-jdk18on 1.79+ for plain FIPS 204 "ML-DSA"
//        (1.78.x only has round-3 DILITHIUM* and composite MLDSA*-... hybrids).
// COMPILE: javac -cp bcprov-jdk18on.jar BcSharedKeyTest.java
// RUN:     java  -cp .:bcprov-jdk18on.jar BcSharedKeyTest [ALG]   (default ALG = ML-DSA)
//          e.g. ALG = ML-DSA-65, DILITHIUM3, MLDSA65-Ed25519-SHA512
//          THREADS / OPS env vars override the defaults 16 / 500.
// Java has no ThreadSanitizer; rely on the correctness invariant + JCStress (jcstress/) for races.
// Invariant: every signature produced from the shared key verifies.
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import java.security.*;
import java.util.concurrent.atomic.AtomicInteger;

public class BcSharedKeyTest {
  static int envInt(String name, int def) {
    try { int v = Integer.parseInt(System.getenv(name)); return v > 0 ? v : def; }
    catch (Exception e) { return def; }
  }

  public static void main(String[] a) throws Exception {
    final String alg = a.length > 0 ? a[0] : "ML-DSA";
    Security.addProvider(new BouncyCastleProvider());
    KeyPairGenerator kpg = KeyPairGenerator.getInstance(alg, "BC");
    KeyPair kp = kpg.generateKeyPair();               // shared key pair
    final PrivateKey sk = kp.getPrivate();            // shared across threads
    final PublicKey  pk = kp.getPublic();
    final int G = envInt("THREADS", 16), N = envInt("OPS", 500);
    AtomicInteger verifyFail = new AtomicInteger(), opFail = new AtomicInteger(), done = new AtomicInteger();
    AtomicInteger firstErrPrinted = new AtomicInteger();
    Thread[] th = new Thread[G];
    for (int g = 0; g < G; g++) {
      th[g] = new Thread(() -> {
        SecureRandom rnd = new SecureRandom();
        for (int i = 0; i < N; i++) {
          // try/catch per operation: one exception must not end the thread or hide later ops
          try {
            byte[] msg = new byte[64]; rnd.nextBytes(msg);
            Signature s = Signature.getInstance(alg, "BC");
            s.initSign(sk); s.update(msg); byte[] sig = s.sign();   // shared private key
            Signature v = Signature.getInstance(alg, "BC");
            v.initVerify(pk); v.update(msg);
            if (!v.verify(sig)) verifyFail.incrementAndGet();
          } catch (Exception e) {
            opFail.incrementAndGet();
            if (firstErrPrinted.getAndIncrement() == 0) e.printStackTrace();
          } finally {
            done.incrementAndGet();
          }
        }
      });
    }
    for (Thread t : th) t.start();
    for (Thread t : th) t.join();
    System.out.printf("shared-key %s: %d threads x %d ops (ran %d), verifyFail=%d opFail=%d%n",
        alg, G, N, done.get(), verifyFail.get(), opFail.get());
    if (done.get() != G * N || verifyFail.get() != 0 || opFail.get() != 0)
      throw new AssertionError("INVARIANT VIOLATION");
  }
}
