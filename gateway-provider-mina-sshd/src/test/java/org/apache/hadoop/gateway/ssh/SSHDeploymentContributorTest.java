package org.apache.hadoop.gateway.ssh;

import org.apache.directory.server.annotations.CreateKdcServer;
import org.apache.directory.server.annotations.CreateLdapServer;
import org.apache.directory.server.annotations.CreateTransport;
import org.apache.directory.server.core.annotations.ApplyLdifFiles;
import org.apache.directory.server.core.integ.FrameworkRunner;
import org.apache.directory.server.kerberos.kdc.AbstractKerberosITest;
import org.apache.directory.server.kerberos.kdc.AbstractKnoxKerberosITest;
import org.apache.directory.server.protocol.shared.transport.TcpTransport;
import org.apache.directory.shared.kerberos.codec.types.EncryptionType;
import org.apache.directory.shared.kerberos.crypto.checksum.ChecksumType;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;

@RunWith(FrameworkRunner.class)
@CreateLdapServer(transports = { @CreateTransport(protocol = "LDAP") })
@CreateKdcServer(transports = { @CreateTransport(protocol = "TCP", port = 6086) })
@ApplyLdifFiles("org/apache/directory/server/kerberos/kdc/KerberosIT.ldif")
public class SSHDeploymentContributorTest extends AbstractKnoxKerberosITest {

  @Before
  public void populateBasicKDC() throws Throwable {
    setupEnv(new KnoxObtainTicketParameters(TcpTransport.class,
        EncryptionType.DES3_CBC_SHA1, ChecksumType.HMAC_SHA1_DES3));
  }

  @Test
  public void testConnection() throws Throwable {

  }

}
