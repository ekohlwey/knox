package org.apache.hadoop.gateway.ssh.auth;

import org.apache.hadoop.gateway.audit.api.Action;
import org.apache.hadoop.gateway.audit.api.ActionOutcome;
import org.apache.hadoop.gateway.audit.api.AuditServiceFactory;
import org.apache.hadoop.gateway.audit.api.Auditor;
import org.apache.hadoop.gateway.audit.api.ResourceType;
import org.apache.hadoop.gateway.audit.log4j.audit.AuditConstants;

public class UserAuthAuditWrapper {
  
  private static final Auditor AUDITOR = AuditServiceFactory.getAuditService()
      .getAuditor(AuditConstants.DEFAULT_AUDITOR_NAME,
          AuditConstants.KNOX_SERVICE_NAME, AuditConstants.KNOX_COMPONENT_NAME);
  
  public Boolean doAudit(String username, Boolean auth){
    if (auth == null) {
      // continue
    } else if (auth) {
      AUDITOR.audit(Action.AUTHENTICATION, username, ResourceType.PRINCIPAL,
          ActionOutcome.SUCCESS);
    } else {
      AUDITOR.audit(Action.AUTHENTICATION, username, ResourceType.PRINCIPAL,
          ActionOutcome.FAILURE);
    }
    return auth;
  }

}
