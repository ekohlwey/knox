package org.apache.hadoop.gateway.ssh.auth;

import org.apache.sshd.common.util.Buffer;
import org.apache.sshd.server.auth.gss.UserAuthGSS;
import org.apache.sshd.server.session.ServerSession;

public class KnoxUserAuthGSS extends UserAuthGSS {

  private UserAuthAuditWrapper wrapper;

  public KnoxUserAuthGSS(UserAuthAuditWrapper wrapper) {
    this.wrapper = wrapper;
  }

  public KnoxUserAuthGSS() {
    this(new UserAuthAuditWrapper());
  }

  public static class Factory extends UserAuthGSS.Factory {
    public org.apache.sshd.server.UserAuth create() {
      return new KnoxUserAuthGSS();
    };
  }

  @Override
  public Boolean auth(ServerSession session, String username, String service,
      Buffer buffer) throws Exception {

    Boolean auth = super.auth(session, username, service, buffer);
    return wrapper.doAudit(username, auth);
  }

}
