package org.apache.hadoop.gateway.ssh;

import java.util.List;

import org.apache.sshd.ClientSession;
import org.apache.sshd.client.UserAuth;
import org.apache.sshd.common.NamedFactory;
import org.apache.sshd.common.SshConstants;
import org.apache.sshd.common.session.AbstractSession;
import org.apache.sshd.common.util.Buffer;
import org.ietf.jgss.GSSContext;
import org.ietf.jgss.GSSException;
import org.ietf.jgss.GSSManager;
import org.ietf.jgss.GSSName;
import org.ietf.jgss.MessageProp;
import org.ietf.jgss.Oid;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class UserAuthGSS implements UserAuth {
  
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
  
  private final Logger log = LoggerFactory.getLogger(getClass());
  
  // TODO: put in SSHConstants file
  public static final byte SSH_MSG_USERAUTH_GSSAPI_RESPONSE = 60;
  public static final byte SSH_MSG_USERAUTH_GSSAPI_TOKEN = 61;
  public static final byte SSH_MSG_USERAUTH_GSSAPI_EXCHANGE_COMPLETE = 63;
  public static final byte SSH_MSG_USERAUTH_GSSAPI_ERROR = 64;
  public static final byte SSH_MSG_USERAUTH_GSSAPI_ERRTOK = 65;
  public static final byte SSH_MSG_USERAUTH_GSSAPI_MIC = 66;
  
  public static final Oid KRB5_MECH = createOID("1.2.840.113554.1.2.2");
  public static final Oid KRB5_NT_PRINCIPAL = createOID("1.2.840.113554.1.2.2.1");

  private ClientSession session;
  
  private byte[] username;
  private byte[] serviceName = "ssh-connection".getBytes();
  private byte[] gssApi = "gssapi-with-mic".getBytes();

  private GSSContext context;

  public UserAuthGSS() { }

  @Override
  public void init(ClientSession session, String service,
      List<Object> identities) throws Exception {
    this.session = session;
    if(session.getUsername() != null) {
      this.username = session.getUsername().getBytes();
    } else {
      throw new NullPointerException("Username cannot be null for client UserAuth");
    }
  }

  @Override
  public boolean process(Buffer buffer) throws Exception {

    // Handle preliminary messages
    if (buffer == null) { // send UserAuth request
      buffer = session.createBuffer((byte) SshConstants.SSH_MSG_USERAUTH_REQUEST);
      buffer.putString(username);
      buffer.putString(serviceName);
      buffer.putString(gssApi);

      byte[] oidBytes = KRB5_MECH.getDER();
      buffer.putInt(oidBytes.length);
      buffer.putString(oidBytes);

      session.writePacket(buffer);

      return Boolean.TRUE;
    } else { // handle next commands
      byte cmd = buffer.getByte();

      if (cmd == SshConstants.SSH_MSG_USERAUTH_FAILURE) {
        return Boolean.FALSE;
      } else if (cmd == SshConstants.SSH_MSG_USERAUTH_INFO_REQUEST && context == null) {

        // consume oid
        byte[] oid = buffer.getStringAsBytes();

        if (!KRB5_MECH.equals(new Oid(oid))) {
          if(log.isDebugEnabled()){
            log.debug("Oid not supported: " + new Oid(oid));
          }
          return Boolean.FALSE; // oid not supported
        }
        
        GSSManager manager = GSSManager.getInstance();
        
        GSSName name = manager.createName(
            "krbtgt/EXAMPLE.COM@EXAMPLE.COM", // TODO: pass in host
            GSSName.NT_USER_NAME);
        
        System.setProperty("javax.security.auth.useSubjectCredsOnly", "true"); // TODO: Toggle option

        context = manager.createContext(name, KRB5_MECH, null, GSSContext.DEFAULT_LIFETIME);

        context.requestMutualAuth(true);
        context.requestConf(true);
        context.requestInteg(true);
        context.requestCredDeleg(true);
        context.requestAnonymity(false);
        
        byte[] tok = new byte[0];
        byte[] out = context.initSecContext(tok, 0, tok.length);
        
        buffer = session.createBuffer(SSH_MSG_USERAUTH_GSSAPI_TOKEN);
        buffer.putBytes(out);
        session.writePacket(buffer);
        return Boolean.TRUE;
      } else if (cmd == SshConstants.SSH_MSG_USERAUTH_SUCCESS) {
        return Boolean.TRUE;
      } else { // Handle GSS tokens TODO: Handle errors from server

        if (context.isEstablished()) {
  
          if(log.isDebugEnabled()){
            AbstractSession abSession = ((AbstractSession) session);
            log.debug("Session id: " + abSession.getIoSession().getId());
          }
          
          // Send MIC TODO: header in wrong format must use SessionId
          buffer = session.createBuffer(SshConstants.SSH_MSG_USERAUTH_REQUEST);
          buffer.putString(username);
          buffer.putString(serviceName);
          buffer.putString(gssApi);
  
          MessageProp msgProp = new MessageProp(true);
          byte[] mic = context.getMIC(buffer.getBytes(), 0,
              buffer.getBytes().length, msgProp);
  
          buffer = session.createBuffer(SSH_MSG_USERAUTH_GSSAPI_MIC);
          buffer.putString(mic);
          session.writePacket(buffer);
       
          return Boolean.TRUE;
        } else {
          
          // Not established - new token to process
          byte[] tok = buffer.getBytes();
          byte[] out = context.initSecContext(tok, 0, tok.length);
          boolean established = context.isEstablished();
  
          // Send return token if necessary
          if (out != null && out.length > 0) {
            buffer = session.createBuffer(SSH_MSG_USERAUTH_GSSAPI_TOKEN);
            buffer.putBytes(out);
            session.writePacket(buffer);
            return Boolean.TRUE;
          } else {
            return established;
          }
        }
      }
    }
  }
  
  /**
   * Utility to construct an Oid from a string, ignoring the annoying exception.
   * Copied from org.apache.sshd.server.auth.gss.UserAuthGSS
   *
   * @param rep The string form
   * @return The Oid
   */
  private static Oid createOID(String rep) {
      try {
          return new Oid(rep);
      } catch (GSSException e) {
          return null; // won't happen
      }
  }

  @Override
  public void destroy() {
    try {
      context.dispose();
    } catch (GSSException e) {
      log.error("Could not dispose of context.", e);
    } finally {
      context = null;
    }
  }
}