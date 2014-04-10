package org.apache.hadoop.gateway.ssh;

//import org.apache.sshd.common.Cipher;
import java.security.Security;

import javax.crypto.Cipher;

import org.apache.sshd.common.util.SecurityUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Test;


public class SecurityTests {
  
  @Test // Test fails because BC's signature are invalidated when jars get pulled from apacheds-all
  public void bouncyCastleFailure() throws Exception {
    Security.addProvider(new BouncyCastleProvider());
    Cipher.getInstance("AES/CTR/NoPadding", SecurityUtils.getSecurityProvider());
  }
}