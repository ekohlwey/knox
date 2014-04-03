package org.apache.directory.server.kerberos.kdc;

import org.apache.directory.server.protocol.shared.transport.Transport;
import org.apache.directory.shared.kerberos.codec.types.EncryptionType;
import org.apache.directory.shared.kerberos.crypto.checksum.ChecksumType;

public abstract class AbstractKnoxKerberosITest extends AbstractKerberosITest {
  
  protected class KnoxObtainTicketParameters extends ObtainTicketParameters{

    public KnoxObtainTicketParameters(Class<? extends Transport> transport,
        EncryptionType encryptionType, ChecksumType checksumType) {
      super(transport, encryptionType, checksumType);
    }
    
  }

}
