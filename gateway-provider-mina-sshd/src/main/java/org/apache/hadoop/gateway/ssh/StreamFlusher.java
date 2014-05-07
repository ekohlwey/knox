package org.apache.hadoop.gateway.ssh;

import java.io.IOException;
import java.io.OutputStream;
import java.util.TimerTask;

/**
 *
 */
public class StreamFlusher extends TimerTask {
  private final OutputStream outputStream;

  public StreamFlusher(OutputStream outputStream) {
    this.outputStream = outputStream;
  }

  @Override
  public void run() {
    try {
      outputStream.flush();
    } catch (IOException e) {
    }
  }
}
