package org.apache.hadoop.gateway.ssh.audit;

import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.locks.ReentrantLock;

public class TerminalAuditThread extends Thread {

  private final ArrayBlockingQueue<TerminalAuditWork> workQueue;
  private boolean stop;
  private final ReentrantLock stopLock = new ReentrantLock();
  private final TerminalActionAuditRecoder auditor;

  public TerminalAuditThread(ArrayBlockingQueue<TerminalAuditWork> workQueue,
      TerminalActionAuditRecoder auditor) {
    this.workQueue = workQueue;
    this.auditor = auditor;
    setDaemon(true);
  }

  @Override
  public void run() {
    boolean run = true;
    while (run) {
      TerminalAuditWork work;
      try {
        work = workQueue.take();
      } catch (InterruptedException e) {
        Thread.currentThread().interrupt();
        continue;
      }
      auditor.auditWork(work);

      stopLock.lock();
      try {
        run = !stop;
      } finally {
        stopLock.unlock();
      }
    }
  }

  public void close() {
    stopLock.lock();
    stop = true;
    stopLock.unlock();
  }
}