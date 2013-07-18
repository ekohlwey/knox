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
package org.apache.hadoop.gateway.shell.hbase.table.row;

import org.apache.commons.codec.binary.Base64;
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

public class StoreRow {

  public static class Request extends AbstractRequest<Response> {

    private static final String ELEMENT_CELL_SET = "CellSet";
    private static final String ELEMENT_ROW = "Row";
    private static final String ELEMENT_CELL = "Cell";
    private static final String ATTRIBUTE_KEY = "key";
    private static final String ATTRIBUTE_COLUMN = "column";
    private static final String ATTRIBUTE_TIMESTAMP = "timestamp";

    private String rowId;
    private String tableName;
    private List<InsertableColumn> columns = new ArrayList<InsertableColumn>();

    public Request( Hadoop session, String rowId, String tableName ) {
      super( session );
      this.rowId = rowId;
      this.tableName = tableName;
    }

    public Request column( String family, String qualifier, Object value, Long time ) {
      columns.add( new InsertableColumn( family, qualifier, value, time ) );
      return this;
    }

    public Request column( String family, String qualifier, Object value ) {
      columns.add( new InsertableColumn( family, qualifier, value, null ) );
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

          Element root = document.createElement( ELEMENT_CELL_SET );
          document.appendChild( root );

          Element row = document.createElement( ELEMENT_ROW );
          row.setAttribute( ATTRIBUTE_KEY, Base64.encodeBase64String( rowId.getBytes( "UTF-8" ) ) );
          root.appendChild( row );

          for( InsertableColumn column : columns ) {
            Element cell = document.createElement( ELEMENT_CELL );
            cell.setAttribute( ATTRIBUTE_COLUMN, column.encodedName() );
            if( column.time() != null ) {
              cell.setAttribute( ATTRIBUTE_TIMESTAMP, column.time().toString() );
            }
            cell.setTextContent( column.encodedValue() );
            row.appendChild( cell );
          }

          TransformerFactory transformerFactory = TransformerFactory.newInstance();
          Transformer transformer = transformerFactory.newTransformer();
          transformer.setOutputProperty( OutputKeys.STANDALONE, "yes" );

          StringWriter writer = new StringWriter();
          StreamResult result = new StreamResult( writer );
          DOMSource source = new DOMSource( document );
          transformer.transform( source, result );

          URIBuilder uri = uri( HBase.SERVICE_PATH, "/", tableName, "/false-row-key" );
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
