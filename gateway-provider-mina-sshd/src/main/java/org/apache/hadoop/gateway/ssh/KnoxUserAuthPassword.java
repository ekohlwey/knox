package org.apache.hadoop.gateway.ssh;

import org.apache.sshd.common.util.Buffer;
import org.apache.sshd.server.UserAuth;
import org.apache.sshd.server.auth.UserAuthPassword;
import org.apache.sshd.server.session.ServerSession;

public class KnoxUserAuthPassword extends UserAuthPassword {

  private final UserAuthAuditWrapper wrapper;

  public KnoxUserAuthPassword(UserAuthAuditWrapper wrapper) {
    this.wrapper = wrapper;
  }

  public KnoxUserAuthPassword() {
    this(new UserAuthAuditWrapper());
  }

  public static class Factory extends UserAuthPassword.Factory {

    @Override
    public UserAuth create() {
      return new KnoxUserAuthPassword();
    }

  }

  @Override
  public Boolean auth(ServerSession session, String username, String service,
      Buffer buffer) throws Exception {
    Boolean auth = super.auth(session, username, service, buffer);
    return wrapper.doAudit(username, auth);
  }

}
