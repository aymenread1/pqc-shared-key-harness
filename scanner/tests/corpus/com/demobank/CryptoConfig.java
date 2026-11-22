package com.demobank;

import java.security.Signature;
import javax.crypto.Mac;
import org.springframework.context.annotation.*;

@Configuration
public class CryptoConfig {
  @Bean
  public Signature mldsaSigner() throws Exception {     // EXPECT PQS002 HIGH (singleton bean)
    return Signature.getInstance("ML-DSA-65");
  }

  @Bean
  @Scope("prototype")
  public Mac hmac() throws Exception {                 // prototype scope: not reported
    return Mac.getInstance("HmacSHA256");
  }
}
