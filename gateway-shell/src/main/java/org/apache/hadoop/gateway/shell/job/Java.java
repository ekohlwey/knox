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
package org.apache.hadoop.gateway.shell.job;

import com.jayway.jsonpath.JsonPath;
import org.apache.hadoop.gateway.shell.AbstractRequest;
import org.apache.hadoop.gateway.shell.AbstractResponse;
import org.apache.hadoop.gateway.shell.Hadoop;
import org.apache.http.HttpResponse;
import org.apache.http.NameValuePair;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.utils.URIBuilder;
import org.apache.http.message.BasicNameValuePair;

import java.io.IOException;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.List;

class Java {
  
  static class Request extends AbstractRequest {

    String jar;
    String app;
    String input;
    String output;

    public Request( Hadoop hadoop ) {
      super( hadoop );
    }

    public Request jar( String jar ) {
      this.jar = jar;
      return this;
    }

    public Request app( String app ) {
      this.app = app;
      return this;
    }

    public Request input( String dir ) {
      input = dir;
      return this;
    }

    public Request output( String dir ) {
      output = dir;
      return this;
    }

    public Response now() throws IOException, URISyntaxException {
      URIBuilder uri = uri( Job.SERVICE_PATH, "/mapreduce/jar" );
      List<NameValuePair> params = new ArrayList<NameValuePair>();
      params.add( new BasicNameValuePair( "jar", jar ) );
      params.add( new BasicNameValuePair( "class", app ) );
      params.add( new BasicNameValuePair( "arg", input ) );
      params.add( new BasicNameValuePair( "arg", output ) );
      UrlEncodedFormEntity form = new UrlEncodedFormEntity( params );
      HttpPost request = new HttpPost( uri.build() );
      request.setEntity( form );
      return new Response( execute( request ) );
    }

  }

  static class Response extends AbstractResponse {

    public Response( HttpResponse response ) {
      super( response );
    }

    public String getJobId() throws IOException {
      return JsonPath.read( getString(), "$.id" );
    }

  }

}
