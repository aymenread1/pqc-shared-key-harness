// Misuse harness: ONE JCA Signature object shared by many threads with no lock, for any provider
// (Bouncy Castle "BC" or the JDK's own "SUN"). JCA engine objects are not documented as
// thread-safe; the question is HOW each implementation fails:
//   ok           signature verifies for the thread's own message
//   loud         an exception was thrown (fail-loud: the caller learns something went wrong)
//   invalid      a signature was returned silently but verifies for no candidate message
//   crossValid   returned signature verifies for ANOTHER thread's message (silent wrong output)
//   mixedValid   returned signature verifies for a message nobody asked to sign: the empty message
//                or a concatenation of two threads' messages (the most dangerous class)
// Mode "locked" wraps the same calls in synchronized(shared): a control that must give only "ok".
// It also prints the provider SPI class chain and its fields (root-cause evidence).
// Author: Ayman Alsadig Mohamed Suliman
// RUN: java -cp .:bcprov.jar SharedSignatureMisuse <kpgAlg[,fallback...]> <sigAlg> <BC|SUN> <shared|locked>
//      MISUSE_THREADS (8) / MISUSE_OPS (300) / MISUSE_MSG_BYTES (32) env vars.
import java.io.ByteArrayOutputStream;
import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.security.*;
import java.util.concurrent.CyclicBarrier;
import java.util.concurrent.atomic.AtomicLong;

public class SharedSignatureMisuse {
  static int envInt(String name, int def) {
    try { int v = Integer.parseInt(System.getenv(name)); return v > 0 ? v : def; }
    catch (Exception e) { return def; }
  }

  static byte[] concat(byte[] a, byte[] b) {
    ByteArrayOutputStream o = new ByteArrayOutputStream();
    o.writeBytes(a); o.writeBytes(b); return o.toByteArray();
  }

  /** Prints the SPI implementation class chain and its instance fields: where per-call state lives. */
  static void describeSpi(Provider p, String sigAlg) {
    Provider.Service s = p.getService("Signature", sigAlg);
    if (s == null) { System.out.println("SPI: no service " + sigAlg + " in " + p.getName()); return; }
    try {
      Class<?> c = Class.forName(s.getClassName(), false, p.getClass().getClassLoader());
      for (; c != null && c != Object.class && c != SignatureSpi.class; c = c.getSuperclass()) {
        StringBuilder b = new StringBuilder("SPI " + c.getName() + " fields:");
        for (Field f : c.getDeclaredFields())
          if (!Modifier.isStatic(f.getModifiers())) b.append(' ').append(f.getType().getSimpleName()).append(' ').append(f.getName()).append(';');
        System.out.println(b);
      }
    } catch (Throwable t) { System.out.println("SPI: cannot inspect " + s.getClassName() + ": " + t); }
  }

  public static void main(String[] args) throws Exception {
    final String kpgAlg = args[0], alg = args[1], prov = args[2];
    final boolean locked = args.length > 3 && args[3].equals("locked");
    final int G = envInt("MISUSE_THREADS", 8), N = envInt("MISUSE_OPS", 300), L = envInt("MISUSE_MSG_BYTES", 32);
    if (prov.equals("BC") && Security.getProvider("BC") == null)
      Security.addProvider((Provider) Class.forName("org.bouncycastle.jce.provider.BouncyCastleProvider")
          .getDeclaredConstructor().newInstance());
    Provider provider = Security.getProvider(prov);
    if (provider == null) throw new IllegalArgumentException("no provider " + prov);
    KeyPair kp = null;
    for (String a : kpgAlg.split(",")) {           // first key-pair-generator name the provider knows
      try { kp = KeyPairGenerator.getInstance(a, provider).generateKeyPair(); break; }
      catch (NoSuchAlgorithmException e) { /* try the next name */ }
    }
    if (kp == null) throw new NoSuchAlgorithmException("none of " + kpgAlg + " in " + prov);
    final PrivateKey sk = kp.getPrivate();
    final PublicKey pk = kp.getPublic();
    final Signature shared = Signature.getInstance(alg, provider);   // the object under test
    if (locked) describeSpi(provider, alg);
    final int sigLen;                               // 2420 = ML-DSA-44, 3309 = ML-DSA-65, 4627 = ML-DSA-87
    { Signature probe = Signature.getInstance(alg, provider); probe.initSign(sk); probe.update(new byte[1]); sigLen = probe.sign().length; }

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
          Signature verifier = Signature.getInstance(alg, provider);   // private, never shared
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
    System.out.printf("RESULT provider=%s/%s java=%s alg=%s sigLen=%d mode=%s threads=%d ops=%d msgBytes=%d total=%d ok=%d loud=%d invalid=%d crossValid=%d mixedValid=%d emptyMessage=%d%n",
        provider.getName(), provider.getVersionStr(), System.getProperty("java.version"), alg, sigLen, locked ? "locked" : "shared",
        G, N, L, total, ok.get(), loud.get(), invalid.get(), crossValid.get(), mixedValid.get(), emptyValid.get());
    if (firstLoud[0] != null) System.out.println("first exception: " + firstLoud[0]);
    if (sum != total) throw new AssertionError("HARNESS ERROR: classified " + sum + " of " + total);
    if (locked && ok.get() != total) throw new AssertionError("CONTROL FAILED: locked mode must be all ok");
  }

  static boolean verify(Signature v, PublicKey pk, byte[] m, byte[] sig) {
    try { v.initVerify(pk); v.update(m); return v.verify(sig); }
    catch (Exception e) { return false; }
  }
}
