/*
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS HEADER.
 *
 * Copyright (c) 2009 Sun Microsystems Inc. All Rights Reserved
 *
 * The contents of this file are subject to the terms
 * of the Common Development and Distribution License
 * (the License). You may not use this file except in
 * compliance with the License.
 *
 * You can obtain a copy of the License at
 * https://opensso.dev.java.net/public/CDDLv1.0.html or
 * opensso/legal/CDDLv1.0.txt
 * See the License for the specific language governing
 * permission and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL
 * Header Notice in each file and include the License file
 * at opensso/legal/CDDLv1.0.txt.
 * If applicable, add the following below the CDDL Header,
 * with the fields enclosed by brackets [] replaced by
 * your own identifying information:
 * "Portions Copyrighted [year] [name of copyright owner]"
 *
 */


package org.forgerock.openam.authentication.modules.duosecurity;

import com.iplanet.sso.SSOException;
import com.sun.identity.authentication.spi.AMLoginModule;
import com.sun.identity.idm.AMIdentity;
import com.sun.identity.idm.AMIdentityRepository;
import com.sun.identity.idm.IdRepoException;
import com.sun.identity.idm.IdSearchControl;
import com.sun.identity.idm.IdSearchResults;
import com.sun.identity.idm.IdType;
import com.sun.identity.shared.debug.Debug;
import org.apache.commons.lang.StringUtils;
import com.sun.identity.authentication.util.ISAuthConstants;
import com.sun.identity.authentication.spi.AuthLoginException;

import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.login.LoginException;
import java.security.Principal;
import java.util.Collections;
import java.util.Map;
import java.util.ResourceBundle;
import java.util.Set;
import org.json.JSONObject;

import org.forgerock.openam.authentication.modules.duosecurity.client.Http;

public class DuoSecurityModule extends AMLoginModule {

    private static final String AUTH_MODULE_NAME = "amAuthDuoSecurity";
    private static final Debug debug = Debug.getInstance(AUTH_MODULE_NAME);
    // orders defined in the callbacks file
    private final static int STATE_AUTH = 2;
    private String txid = "";
    private String status_detail = "";
    private String userName;
    private String secret_key = “your secret key here”;
    private String integration_key = “your integration key here”;
    private String api_server_host = “your api server host name”;

    /**
     * Constructs an instance of the DuoSecurityModule.
     */
    public DuoSecurityModule() {
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void init(Subject subject, Map sharedState, Map options) {

        userName = (String) sharedState.get(getUserKey());
        debug.message(“\n\n username -> "+userName);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public int process(Callback[] callbacks, int state) throws LoginException {
    	
    	debug.message("INSIDE process of DuoSecurityModule, state: "+state);
    			
    	if (debug.messageEnabled()) {
    		debug.message("DuoSecurity::process state: " + state);
        }
    	int nextState = STATE_AUTH;
         switch (state) {
	         case ISAuthConstants.LOGIN_START: 
	        	 try {
	        		 txid = invokeDuoSecurityAuthAPI(1);
	        		 nextState = STATE_AUTH;
	        	 } catch(Exception ex) {
	        		 debug.message("Exception submitting AuthAPI request to Duo!!");
                	 throw new AuthLoginException(ex);
	        	 }
                 break;
             case STATE_AUTH:
            	 try {
            		 debug.message("polling with txid: "+txid);
            		 String result = pollDuoPushAuthStatus(txid);
            		 if(result.equals("waiting")) {
            			 nextState = STATE_AUTH;
            		 } else if(result.equals("allow")) {
            			 nextState =  ISAuthConstants.LOGIN_SUCCEED;
            		 } else if(result.equals("deny")) {
            		 	 throw new AuthLoginException("Duo Push denied: "+status_detail);
            		 } else {
            			 debug.error(“not expecting this result: "+result);
            			 throw new AuthLoginException("Bad result from Duo Push: "+result);
            		 }
            	 } catch(Exception ex) {
            		 debug.error(“Exception polling for result!!");
                	 throw new AuthLoginException(ex);
            	 }
                 break;
             default:
                 throw new AuthLoginException("invalid state");
  
         }
         return nextState;
    }
    
    private String pollDuoPushAuthStatus(String txid) throws Exception {
    	String result = "waiting";
        String status = "";
        // SINGLE poll
        //while (result.equals("waiting")) { 
        Http request = new Http("GET",api_server_host,
                                "/auth/v2/auth_status");
        request.addParam("txid", txid);
        request.signRequest(integration_key, secret_key, 2);

        JSONObject response = (JSONObject)request.executeRequest();
        result = response.getString("result");
        status = response.getString("status");
        status_detail = response.getString("status_msg");

        debug.message(“Duo Push status: " +  status);
        //}
        return result;
    }
    
    private String invokeDuoSecurityAuthAPI(int async) throws AuthLoginException {
    	JSONObject response = null;
        String txid = null;
        // Make API call for phone verification
        try{
            Http request = new Http("POST",
                                    api_server_host,
                                    "/auth/v2/auth");
            request.addParam("username", userName);
            request.addParam("factor", "push");
            request.addParam("device", "auto");
            request.addParam("async", String.valueOf(async));
            request.signRequest(integration_key, secret_key, 2);

            response = (JSONObject) request.executeRequest();
            request = null;
            debug.message("\n"+response.toString());
            
            txid = response.getString("txid");
            
        }
        catch(Exception e) {
            debug.error("error making request");
            debug.error(e.toString());
            throw new AuthLoginException("error making request to Duo Security");
        }
        return txid;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Principal getPrincipal() {
        return new DuoSecurityModulePrincipal(userName);
    }

}
