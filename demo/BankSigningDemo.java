// Live demo for banks: a payment-signing service migrated to post-quantum ML-DSA.
// Two implementations of the SAME service are driven by the same concurrent load:
//   VULNERABLE  one Signature object reused by every request thread (a common singleton pattern)
//   FIXED       a Signature object per call (or per thread)
// Every returned signature is then audited the way a counterparty bank would see it.
// Author: Ayman Alsadig Mohamed Suliman. License: MIT.
//
// RUN (Bouncy Castle 1.79+):  java -cp .:bcprov-jdk18on.jar BankSigningDemo [ALG] [PROVIDER]
//                             defaults: ML-DSA BC     (BC 1.78 only: DILITHIUM3 BC)
// RUN (JDK 24+ own provider): java BankSigningDemo ML-DSA SUN
// Env: DEMO_TELLERS (8 concurrent request threads), DEMO_ORDERS (200 orders per teller),
//      DEMO_ORDER_BYTES (4096: size of one ISO 20022-like payment order), DEMO_JSON (write results)
import java.io.ByteArrayOutputStream;
import java.io.FileWriter;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.concurrent.CyclicBarrier;
import java.util.concurrent.atomic.AtomicLong;

public class BankSigningDemo {
  interface PaymentSigner { byte[] sign(byte[] order) throws Exception; }

  /** The bug: one engine object shared by all request threads (e.g. a field of a @Service). */
  static final class VulnerableService implements PaymentSigner {
    private final Signature signer; private final PrivateKey key;
    VulnerableService(String alg, Provider p, PrivateKey key) throws Exception { this.signer = Signature.getInstance(alg, p); this.key = key; }
    public byte[] sign(byte[] order) throws Exception { signer.initSign(key); signer.update(order); return signer.sign(); }
  }

  /** The fix: a fresh engine object per call (cheap compared with ML-DSA signing itself). */
  static final class FixedService implements PaymentSigner {
    private final String alg; private final Provider p; private final PrivateKey key;
    FixedService(String alg, Provider p, PrivateKey key) { this.alg = alg; this.p = p; this.key = key; }
    public byte[] sign(byte[] order) throws Exception {
      Signature s = Signature.getInstance(alg, p); s.initSign(key); s.update(order); return s.sign();
    }
  }

  static int env(String n, int d) { try { int v = Integer.parseInt(System.getenv(n)); return v > 0 ? v : d; } catch (Exception e) { return d; } }

  static byte[] order(int teller, int i, int size, SecureRandom r) {
    String head = String.format("<Document><CstmrCdtTrfInitn><PmtId>T%02d-%06d</PmtId><Dbtr><IBAN>SA03%020d</IBAN></Dbtr>"
        + "<Cdtr><IBAN>SA44%020d</IBAN></Cdtr><InstdAmt Ccy=\"SAR\">%d.%02d</InstdAmt><RmtInf>", teller, i,
        Math.abs(r.nextLong() % 100000000000000000L), Math.abs(r.nextLong() % 100000000000000000L), 100 + r.nextInt(5_000_000), r.nextInt(100));
    StringBuilder b = new StringBuilder(head);
    while (b.length() < size - 40) b.append((char) ('A' + r.nextInt(26)));
    b.append("</RmtInf></CstmrCdtTrfInitn></Document>");
    return b.toString().getBytes(StandardCharsets.US_ASCII);
  }

  static boolean verify(Signature v, PublicKey pk, byte[] m, byte[] sig) {
    try { v.initVerify(pk); v.update(m); return v.verify(sig); } catch (Exception e) { return false; }
  }

  static byte[] cat(byte[] a, byte[] b) { ByteArrayOutputStream o = new ByteArrayOutputStream(); o.writeBytes(a); o.writeBytes(b); return o.toByteArray(); }

  /** Runs the load against one service and audits every result. Returns {ok, error, rejected, otherCustomer, unrequested, empty}. */
  static long[] run(String label, PaymentSigner svc, String alg, Provider p, PublicKey pk, int T, int N, int size) throws Exception {
    SecureRandom r = new SecureRandom();
    byte[][][] orders = new byte[T][N][];
    for (int t = 0; t < T; t++) for (int i = 0; i < N; i++) orders[t][i] = order(t, i, size, r);
    byte[][][] sigs = new byte[T][N][];
    AtomicLong ok = new AtomicLong(), err = new AtomicLong(), rejected = new AtomicLong(), other = new AtomicLong(),
        unrequested = new AtomicLong(), empty = new AtomicLong();
    CyclicBarrier go = new CyclicBarrier(T), fixed = new CyclicBarrier(T);
    Thread[] th = new Thread[T];
    for (int g = 0; g < T; g++) {
      final int t = g;
      th[g] = new Thread(() -> {
        try {
          Signature v = Signature.getInstance(alg, p);                  // the counterparty's verifier
          for (int i = 0; i < N; i++) {
            go.await();
            try { sigs[t][i] = svc.sign(orders[t][i]); } catch (Exception e) { sigs[t][i] = null; err.incrementAndGet(); }
            fixed.await();
            byte[] s = sigs[t][i];
            if (s == null) continue;
            if (verify(v, pk, orders[t][i], s)) { ok.incrementAndGet(); continue; }
            if (verify(v, pk, new byte[0], s)) { unrequested.incrementAndGet(); empty.incrementAndGet(); continue; }
            boolean o = false, u = false;
            for (int j = 0; j < T && !o && !u; j++) {
              if (j != t && verify(v, pk, orders[j][i], s)) o = true;
              else if (verify(v, pk, cat(orders[t][i], orders[j][i]), s) || verify(v, pk, cat(orders[j][i], orders[t][i]), s)) u = true;
            }
            (o ? other : u ? unrequested : rejected).incrementAndGet();
          }
        } catch (Exception e) { throw new RuntimeException(e); }
      });
    }
    long t0 = System.nanoTime();
    for (Thread x : th) x.start();
    for (Thread x : th) x.join();
    long ms = (System.nanoTime() - t0) / 1_000_000;
    long total = (long) T * N;
    System.out.printf("%n== %s service: %d tellers x %d payment orders of %d bytes (%d orders, %d ms)%n", label, T, N, size, total, ms);
    System.out.printf("   correctly signed ........................................ %6d  (%.2f%%)%n", ok.get(), 100.0 * ok.get() / total);
    System.out.printf("   service error (exception, order not sent) ............... %6d  (%.2f%%)%n", err.get(), 100.0 * err.get() / total);
    System.out.printf("   sent with a signature the partner bank REJECTS .......... %6d  (%.2f%%)%n", rejected.get(), 100.0 * rejected.get() / total);
    System.out.printf("   sent with a valid signature of ANOTHER customer's order .. %6d  (%.2f%%)%n", other.get(), 100.0 * other.get() / total);
    System.out.printf("   valid signature on an order NOBODY requested ............ %6d  (%.2f%%)  of which EMPTY order: %d%n",
        unrequested.get(), 100.0 * unrequested.get() / total, empty.get());
    return new long[] {ok.get(), err.get(), rejected.get(), other.get(), unrequested.get(), empty.get(), total, ms};
  }

  public static void main(String[] a) throws Exception {
    String alg = a.length > 0 ? a[0] : "ML-DSA", prov = a.length > 1 ? a[1] : "BC";
    if (prov.equals("BC") && Security.getProvider("BC") == null)
      Security.addProvider((Provider) Class.forName("org.bouncycastle.jce.provider.BouncyCastleProvider").getDeclaredConstructor().newInstance());
    Provider p = Security.getProvider(prov);
    int T = env("DEMO_TELLERS", 8), N = env("DEMO_ORDERS", 200), size = env("DEMO_ORDER_BYTES", 4096);
    KeyPairGenerator kpg;
    try { kpg = KeyPairGenerator.getInstance(alg.equals("ML-DSA") ? "ML-DSA-65" : alg, p); }
    catch (NoSuchAlgorithmException e) { kpg = KeyPairGenerator.getInstance(alg, p); }
    KeyPair kp = kpg.generateKeyPair();
    System.out.printf("Bank payment-signing demo - %s via %s %s - Java %s%n", alg, p.getName(), p.getVersionStr(), System.getProperty("java.version"));
    long[] bad = run("VULNERABLE (one shared Signature object)", new VulnerableService(alg, p, kp.getPrivate()), alg, p, kp.getPublic(), T, N, size);
    long[] good = run("FIXED (Signature object per call)", new FixedService(alg, p, kp.getPrivate()), alg, p, kp.getPublic(), T, N, size);
    String json = String.format("{\"algorithm\":\"%s\",\"provider\":\"%s %s\",\"java\":\"%s\",\"tellers\":%d,\"ordersPerTeller\":%d,\"orderBytes\":%d,"
        + "\"vulnerable\":{\"ok\":%d,\"error\":%d,\"rejected\":%d,\"otherCustomer\":%d,\"unrequested\":%d,\"empty\":%d,\"total\":%d,\"ms\":%d},"
        + "\"fixed\":{\"ok\":%d,\"error\":%d,\"rejected\":%d,\"otherCustomer\":%d,\"unrequested\":%d,\"empty\":%d,\"total\":%d,\"ms\":%d}}",
        alg, p.getName(), p.getVersionStr(), System.getProperty("java.version"), T, N, size,
        bad[0], bad[1], bad[2], bad[3], bad[4], bad[5], bad[6], bad[7], good[0], good[1], good[2], good[3], good[4], good[5], good[6], good[7]);
    System.out.println("\nDEMO_JSON " + json);
    String out = System.getenv("DEMO_JSON");
    if (out != null) try (FileWriter w = new FileWriter(out)) { w.write(json); }
    if (good[0] != good[6]) { System.out.println("FIXED service must be 100% correct"); System.exit(1); }
  }
}
