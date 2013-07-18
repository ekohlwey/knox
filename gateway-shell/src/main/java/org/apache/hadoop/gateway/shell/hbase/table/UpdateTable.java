/**
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements. See the NOTICE file distributed with this
 * work for additional information regarding copyright ownership. The ASF
 * licenses this file to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */
package org.apache.hadoop.gateway.shell.hbase.table;

import org.apache.hadoop.gateway.shell.AbstractRequest;
import org.apache.hadoop.gateway.shell.EmptyResponse;
import org.apache.hadoop.gateway.shell.Hadoop;
import org.apache.hadoop.gateway.shell.hbase.HBase;
import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.utils.URIBuilder;
import org.apache.http.entity.ContentType;
import org.apache.http.entity.StringEntity;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import java.io.StringWriter;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Callable;

public class UpdateTable {

  public static class Request extends AbstractRequest<Response> implements FamilyContainer<Request> {

    private static final String ELEMENT_TABLE_SCHEMA = "TableSchema";
    private static final String ELEMENT_COLUMN_SCHEMA = "ColumnSchema";
    private static final String ATTRIBUTE_NAME = "name";

    private String tableName;
    private List<Family<Request>> families = new ArrayList<Family<Request>>();

    public Request( Hadoop session, String tableName ) {
      super( session );
      this.tableName = tableName;
    }

    public Family<Request> family( String name ) {
      Family<Request> family = new Family<Request>( this, name );
      families.add( family );
      return family;
    }

    @Override
    public Request addFamily( Family<Request> family ) {
      families.add( family );
      return this;
    }

    protected Callable<Response> callable() {
      return new Callable<Response>() {
        @Override
        public Response call() throws Exception {
          DocumentBuilderFactory builderFactory = DocumentBuilderFactory.newInstance();
          DocumentBuilder builder = builderFactory.newDocumentBuilder();
          Document document = builder.newDocument();
          document.setXmlStandalone( true );

          Element root = document.createElement( ELEMENT_TABLE_SCHEMA );
          document.appendChild( root );

          for( Family<Request> family : families ) {
            Element columnSchema = document.createElement( ELEMENT_COLUMN_SCHEMA );
            columnSchema.setAttribute( ATTRIBUTE_NAME, family.name() );
            for( Attribute attribute : family.attributes() ) {
              columnSchema.setAttribute( attribute.getName(), attribute.getValue().toString() );
            }
            root.appendChild( columnSchema );
          }

          TransformerFactory transformerFactory = TransformerFactory.newInstance();
          Transformer transformer = transformerFactory.newTransformer();
          transformer.setOutputProperty( OutputKeys.STANDALONE, "yes" );

          StringWriter writer = new StringWriter();
          StreamResult result = new StreamResult( writer );
          DOMSource source = new DOMSource( document );
          transformer.transform( source, result );

          URIBuilder uri = uri( HBase.SERVICE_PATH, "/", tableName, "/schema" );
          HttpPost request = new HttpPost( uri.build() );
          HttpEntity entity = new StringEntity( writer.toString(), ContentType.create( "text/xml", "UTF-8" ) );
          request.setEntity( entity );

          return new Response( execute( request ) );
        }
      };
    }
  }

  public static class Response extends EmptyResponse {

    Response( HttpResponse response ) {
      super( response );
    }
  }
}
