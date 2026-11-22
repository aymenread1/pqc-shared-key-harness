// Misuse harness: ONE Bouncy Castle JCA Signature object shared by many threads with no lock.
// JCA engine objects are not documented as thread-safe; the question is HOW the library fails:
//   ok           signature verifies for the thread's own message
//   loud         an exception was thrown (fail-loud: the caller knows something went wrong)
//   invalid      a signature was returned silently but verifies for no candidate message
//   crossValid   returned signature verifies for ANOTHER thread's message (silent wrong output)
//   mixedValid   returned signature verifies for a message nobody asked to sign: the empty message
//                or a concatenation of two threads' messages (the most dangerous class)
// Mode "locked" wraps the same calls in synchronized(shared): a control that must give only "ok".
// Author: Ayman Alsadig Mohamed Suliman
// RUN: java -cp .:bcprov.jar BcSharedSignatureMisuse <ALG> <shared|locked>
//      MISUSE_THREADS (8) / MISUSE_OPS (300) / MISUSE_MSG_BYTES (32) env vars.
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.ByteArrayOutputStream;
import java.security.*;
import java.util.concurrent.CyclicBarrier;
import java.util.concurrent.atomic.AtomicLong;

public class BcSharedSignatureMisuse {
  static int envInt(String name, int def) {
    try { int v = Integer.parseInt(System.getenv(name)); return v > 0 ? v : def; }
    catch (Exception e) { return def; }
  }

  static byte[] concat(byte[] a, byte[] b) {
    ByteArrayOutputStream o = new ByteArrayOutputStream();
    o.writeBytes(a); o.writeBytes(b); return o.toByteArray();
  }

  public static void main(String[] args) throws Exception {
    final String alg = args.length > 0 ? args[0] : "ML-DSA";
    final boolean locked = args.length > 1 && args[1].equals("locked");
    final int G = envInt("MISUSE_THREADS", 8), N = envInt("MISUSE_OPS", 300), L = envInt("MISUSE_MSG_BYTES", 32);
    Security.addProvider(new BouncyCastleProvider());
    KeyPair kp = KeyPairGenerator.getInstance(alg, "BC").generateKeyPair();
    final PrivateKey sk = kp.getPrivate();
    final PublicKey pk = kp.getPublic();
    final Signature shared = Signature.getInstance(alg, "BC");   // the object under test

    final byte[][][] msgs = new byte[G][N][];
    final byte[][][] sigs = new byte[G][N][];
    SecureRandom seed = new SecureRandom();
    for (int t = 0; t < G; t++) for (int i = 0; i < N; i++) { msgs[t][i] = new byte[L]; seed.nextBytes(msgs[t][i]); }

    final AtomicLong ok = new AtomicLong(), loud = new AtomicLong(), invalid = new AtomicLong(),
        crossValid = new AtomicLong(), mixedValid = new AtomicLong(), emptyValid = new AtomicLong();
    final CyclicBarrier start = new CyclicBarrier(G), done = new CyclicBarrier(G);
    final String[] firstLoud = new String[1];

    Thread[] th = new Thread[G];
    for (int g = 0; g < G; g++) {
      final int t = g;
      th[g] = new Thread(() -> {
        try {
          Signature verifier = Signature.getInstance(alg, "BC");   // private, never shared
          for (int i = 0; i < N; i++) {
            start.await();                       // all threads hit the shared object together
            try {
              if (locked) {
                synchronized (shared) { shared.initSign(sk); shared.update(msgs[t][i]); sigs[t][i] = shared.sign(); }
              } else {
                shared.initSign(sk); shared.update(msgs[t][i]); sigs[t][i] = shared.sign();
              }
            } catch (Exception e) {
              sigs[t][i] = null; loud.incrementAndGet();
              synchronized (firstLoud) { if (firstLoud[0] == null) firstLoud[0] = e.toString(); }
            }
            done.await();                        // every message of iteration i is now fixed
            byte[] sig = sigs[t][i];
            if (sig == null) continue;
            if (verify(verifier, pk, msgs[t][i], sig)) { ok.incrementAndGet(); continue; }
            boolean empty = verify(verifier, pk, new byte[0], sig);
            if (empty) emptyValid.incrementAndGet();      // breakdown of mixedValid
            boolean cross = false, mixed = empty;
            for (int j = 0; j < G && !cross && !mixed; j++) {
              if (j != t && verify(verifier, pk, msgs[j][i], sig)) cross = true;
              else if (verify(verifier, pk, concat(msgs[t][i], msgs[j][i]), sig)
                    || verify(verifier, pk, concat(msgs[j][i], msgs[t][i]), sig)) mixed = true;
            }
            if (cross) crossValid.incrementAndGet();
            else if (mixed) mixedValid.incrementAndGet();
            else invalid.incrementAndGet();
          }
        } catch (Exception e) {
          throw new RuntimeException(e);         // harness error, not a library outcome
        }
      });
    }
    for (Thread x : th) x.start();
    for (Thread x : th) x.join();

    long total = (long) G * N;
    long sum = ok.get() + loud.get() + invalid.get() + crossValid.get() + mixedValid.get();
    System.out.printf("RESULT alg=%s mode=%s threads=%d ops=%d msgBytes=%d total=%d ok=%d loud=%d invalid=%d crossValid=%d mixedValid=%d (of which emptyMessage=%d)%n",
        alg, locked ? "locked" : "shared", G, N, L, total, ok.get(), loud.get(), invalid.get(), crossValid.get(), mixedValid.get(), emptyValid.get());
    if (firstLoud[0] != null) System.out.println("first exception: " + firstLoud[0]);
    if (sum != total) throw new AssertionError("HARNESS ERROR: classified " + sum + " of " + total);
    if (locked && ok.get() != total) throw new AssertionError("CONTROL FAILED: locked mode must be all ok");
  }

  static boolean verify(Signature v, PublicKey pk, byte[] m, byte[] sig) {
    try { v.initVerify(pk); v.update(m); return v.verify(sig); }
    catch (Exception e) { return false; }
  }
}
