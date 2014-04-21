package org.apache.hadoop.gateway.ssh;

import java.util.List;

import org.apache.sshd.ClientSession;
import org.apache.sshd.client.UserAuth;
import org.apache.sshd.common.NamedFactory;
import org.apache.sshd.common.util.Buffer;

public class GSSUserAuth implements UserAuth {
  
  public class GSSUserAuthFactory implements NamedFactory<UserAuth>{

    @Override
    public UserAuth create() {
      return new GSSUserAuth();
    }

    @Override
    public String getName() {
      return GSSUserAuth.class.getName();
    }
    
  }

  @Override
  public void init(ClientSession session, String service,
      List<Object> identities) throws Exception {
    // TODO Auto-generated method stub
    
  }

  @Override
  public boolean process(Buffer buffer) throws Exception {
    // TODO Auto-generated method stub
    return false;
  }

  @Override
  public void destroy() {
    // TODO Auto-generated method stub
    
  }

  
}
