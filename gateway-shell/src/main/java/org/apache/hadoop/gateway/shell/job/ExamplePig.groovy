/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.hadoop.gateway.shell.job

import org.apache.hadoop.gateway.shell.job.Job as job
import org.apache.hadoop.gateway.shell.hdfs.Hdfs as hdfs

import com.jayway.jsonpath.JsonPath
import org.apache.hadoop.gateway.shell.Hadoop

gateway = "https://localhost:8443/gateway/sample"
username = "mapred"
password = "mapred-password"
inputFile = "/Users/kevin.minder/Projects/gateway-0.2.0-SNAPSHOT/LICENSE"

script = """\
A = load '/tmp/test/input/FILE' using PigStorage(':');
B = foreach A generate \$0 as id;
dump B;
"""

hadoop = Hadoop.login( gateway, username, password )
hdfs.rm(hadoop).file( "/tmp/test" ).recursive().now()
hdfs.put(hadoop).file( inputFile ).to( "/tmp/test/input/FILE" ).now()
hdfs.put(hadoop).text( script ).to( "/tmp/test/script.pig" ).now()

jobId = job.submitPig(hadoop)
  .file( "/tmp/test/script.pig" ) \
  .arg( "-v" ) \
  .statusDir( "/tmp/test/output" ) \
  .now().jobId
println "Job=" + jobId

println job.queryQueue(hadoop).now().string

done = false;
while( !done ) {
  json = job.queryStatus(hadoop).jobId(jobId).now().string
  done = JsonPath.read( json, "\$.status.jobComplete" )
  sleep( 1000 )
  print "."
}
println "done"
