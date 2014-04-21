package org.apache.hadoop.gateway.ssh;

import java.util.List;

import org.apache.sshd.ClientSession;
import org.apache.sshd.client.UserAuth;
import org.apache.sshd.common.NamedFactory;
import org.apache.sshd.common.SshConstants;
import org.apache.sshd.common.util.Buffer;

public class UserAuthGSS implements UserAuth {

  private static final int SSH_MSG_USERAUTH_GSSAPI_RESPONSE = 60;
  private static final int SSH_MSG_USERAUTH_GSSAPI_TOKEN = 61;
  private static final int SSH_MSG_USERAUTH_GSSAPI_EXCHANGE_COMPLETE = 63;
  private static final int SSH_MSG_USERAUTH_GSSAPI_ERROR = 64;
  private static final int SSH_MSG_USERAUTH_GSSAPI_ERRTOK = 65;
  private static final int SSH_MSG_USERAUTH_GSSAPI_MIC = 66;

  private static final byte[][] supported_oid = {
  { (byte) 0x6, (byte) 0x9, (byte) 0x2a, (byte) 0x86, (byte) 0x48, (byte) 0x86,
      (byte) 0xf7, (byte) 0x12, (byte) 0x1, (byte) 0x2, (byte) 0x2 } }; // OID 1.2.840.113554.1.2.2 in DER

  private static final String[] supported_method = { "gssapi-with-mic.krb5" };

  public static class Factory implements NamedFactory<UserAuth> {
    @Override
    public UserAuth create() {
      return new UserAuthGSS();
    }

    @Override
    public String getName() {
      return "gssapi-with-mic";
    }
  }

  private ClientSession session;
  private Buffer buf;

  @Override
  public void init(ClientSession session, String service,
      List<Object> identities) throws Exception {
    this.session = session;
    
  }

  @Override
  public boolean process(Buffer buffer) throws Exception {

    byte[] _username = str2byte(session.getUsername());

    // byte SSH_MSG_USERAUTH_REQUEST(50)
    // string user name(in ISO-10646 UTF-8 encoding)
    // string service name(in US-ASCII)
    // string "gssapi"(US-ASCII)
    // uint32 n, the number of OIDs client supports
    // string[n] mechanism OIDS
    buf = session.createBuffer((byte) SshConstants.SSH_MSG_USERAUTH_REQUEST);
    buf.putString(_username);
    buf.putString(str2byte("ssh-connection"));
    buf.putString(str2byte("gssapi-with-mic"));
    buf.putInt(supported_oid.length);
    for (int i = 0; i < supported_oid.length; i++) {
      buf.putString(supported_oid[i]);
    }

    session.writePacket(buf);

    String method = null;
    int msg;
    while (true) {
      msg = buf.getByte(); // I don't think this is the right way to pull the message out of the buffer. 
                           // Am I allowed to read right away like this?

      if (msg == SshConstants.SSH_MSG_USERAUTH_FAILURE) {
        return false;
      }

      if (msg == SSH_MSG_USERAUTH_GSSAPI_RESPONSE) {
        buf.getInt();
        buf.getByte();
        buf.getByte();
        byte[] message = buf.getStringAsBytes();

        for (int i = 0; i < supported_oid.length; i++) {
          if (array_equals(message, supported_oid[i])) {
            method = supported_method[i];
            break;
          }
        }

        if (method == null) {
          return false;
        }

        break; // success
      }

      if (msg == SshConstants.SSH_MSG_USERAUTH_BANNER) {
        buf.getInt();
        buf.getByte();
        buf.getByte();
        byte[] _message = buf.getStringAsBytes();
        byte[] lang = buf.getStringAsBytes();
        String message = byte2str(_message);
        System.out.println("Message: " + message);
        continue;
      }
      return false;
    }

    GSSContextWrapper contextWrapper = new GSSContextWrapper();

    try {
      contextWrapper.create(session.getUsername(), "0.0.0.0");
    } catch (Exception e) {
      return false;
    }

    byte[] token = new byte[0];

    while (!contextWrapper.isEstablished()) {
      try {
        token = contextWrapper.init(token, 0, token.length);
      } catch (Exception e) {
        // TODO
        // ERRTOK should be sent?
        // byte SSH_MSG_USERAUTH_GSSAPI_ERRTOK
        // string error token
        return false;
      }

      if (token != null) {
        buf = session.createBuffer((byte) SSH_MSG_USERAUTH_GSSAPI_TOKEN);
        buf.putString(token);
        session.writePacket(buf);
      }

      if (!contextWrapper.isEstablished()) {
        msg = buffer.getByte();
        if (msg == SSH_MSG_USERAUTH_GSSAPI_ERROR) {
          // uint32 major_status
          // uint32 minor_status
          // string message
          // string language tag

          msg = buffer.getByte();
          // return false;
        } else if (msg == SSH_MSG_USERAUTH_GSSAPI_ERRTOK) {
          // string error token
          msg = buffer.getByte();
          // return false;
        }

        if (msg == SshConstants.SSH_MSG_USERAUTH_FAILURE) {
          return false;
        }

        buf.getInt();
        buf.getByte();
        buf.getByte();
        token = buf.getStringAsBytes();
      }
    }

    Buffer mbuf = new Buffer();
    // string session identifier
    // byte SSH_MSG_USERAUTH_REQUEST
    // string user name
    // string service
    // string "gssapi-with-mic"
    mbuf.putString(new byte[12]); // TODO: Find out hash length
    mbuf.putByte((byte) SshConstants.SSH_MSG_USERAUTH_REQUEST);
    mbuf.putString(_username);
    mbuf.putString(str2byte("ssh-connection"));
    mbuf.putString(str2byte("gssapi-with-mic"));
    byte[] bytes = mbuf.getBytes();
    byte[] mic = contextWrapper.getMIC(bytes, 0, bytes.length);

    if (mic == null) {
      return false;
    }

    buf = session.createBuffer((byte) SshConstants.SSH_MSG_USERAUTH_GSSAPI_MIC);
    buf.putString(mic);
    session.writePacket(buf);

    contextWrapper.dispose();

    msg = buffer.getByte();

    if (msg == SshConstants.SSH_MSG_USERAUTH_SUCCESS) {
      return true;
    } else if (msg == SshConstants.SSH_MSG_USERAUTH_FAILURE) {
      buf.getInt();
      buf.getByte();
      buf.getByte();
      byte[] foo = buf.getStringAsBytes();
      int partial_success = buf.getByte();
      if (partial_success != 0) {
        throw new RuntimeException(byte2str(foo));
      }
    }
    return false;
  }

  static byte[] str2byte(String str) {
    return str2byte(str, "UTF-8");
  }

  static byte[] str2byte(String str, String encoding) {
    if (str == null)
      return null;
    try {
      return str.getBytes(encoding);
    } catch (java.io.UnsupportedEncodingException e) {
      return str.getBytes();
    }
  }

  private String byte2str(byte[] str) {
    return byte2str(str, "UTF-8");
  }

  private String byte2str(byte[] str, String encoding) {
    return byte2str(str, 0, str.length, encoding);
  }

  private String byte2str(byte[] str, int s, int l, String encoding) {
    try {
      return new String(str, s, l, encoding);
    } catch (java.io.UnsupportedEncodingException e) {
      return new String(str, s, l);
    }
  }

  private boolean array_equals(byte[] foo, byte bar[]) {
    int i = foo.length;
    if (i != bar.length)
      return false;
    for (int j = 0; j < i; j++) {
      if (foo[j] != bar[j])
        return false;
    }
    return true;
  }

  @Override
  public void destroy() {
    

  }
}