/*
 * Copyright (c) 2011, NORDUnet A/S
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:
 *
 *  * Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
 *  * Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
 *  * Neither the name of the NORDUnet nor the names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
package net.bc.crowd.sso;

import com.atlassian.crowd.embedded.api.Directory;
import com.atlassian.crowd.embedded.api.User;
import com.atlassian.crowd.exception.*;
import com.atlassian.crowd.integration.Constants;
import com.atlassian.crowd.integration.http.HttpAuthenticator;
import com.atlassian.crowd.integration.soap.springsecurity.CrowdSSOAuthenticationToken;
import com.atlassian.crowd.manager.application.ApplicationAccessDeniedException;
import com.atlassian.crowd.manager.authentication.TokenAuthenticationManager;
import com.atlassian.crowd.manager.directory.DirectoryManager;
import com.atlassian.crowd.model.authentication.UserAuthenticationContext;
import com.atlassian.crowd.model.authentication.ValidationFactor;
import com.atlassian.crowd.model.user.UserTemplate;
import com.atlassian.crowd.service.client.ClientProperties;
import netscape.ldap.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;





/**
 * Servlet for setting the SSO cookie and redirecting to the wanted destination
 * @author juha
 */
public class SSOCookieServlet extends HttpServlet {

    private static final Logger log = LoggerFactory.getLogger(SSOCookieServlet.class);
    private DirectoryManager directoryManager;
    private TokenAuthenticationManager tokenAuthenticationManager;
    private HttpAuthenticator httpAuthenticator;
    private ClientProperties clientProperties;
    public static final String REDIRECT_ATTRIBUTE = "ssocookie.redirect";
    private static Configuration config;


    static {
        config = ConfigurationLoader.loadConfiguration(null);
    }


    public SSOCookieServlet(DirectoryManager directoryManager, TokenAuthenticationManager tokenAuthenticationManager, HttpAuthenticator httpAuthenticator, ClientProperties clientProperties) {
         this.directoryManager = directoryManager;
         this.tokenAuthenticationManager = tokenAuthenticationManager;
         this.httpAuthenticator = httpAuthenticator;
         this.clientProperties = clientProperties;
     }

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse res) throws ServletException, IOException {
        UserAuthenticationContext authCtx = new UserAuthenticationContext();

        // Check to see if the properties file needs reloading
        if (config.checkReloadConfig()) {
           log.info("Properties file has changed. Reloading config");
           config = ConfigurationLoader.loadConfiguration(config.getConfigFile());
        }

        // This block copied over from ShibbolethSSOFilter to make it unnecessary
        //
        boolean authed = false;

        // This Servlet must be protected with a Shibboleth Session, handled by Apache
        // The REMOTE_USER header is set by Apache if a Shib session was successfully established
        String username = req.getHeader("REMOTE_USER");

        // First, clear the username in the Session context, for security
        req.getSession().setAttribute("ssocookie.username", "");

        if (username != null && !username.equals("")) {
            // First check LDAP to see if the eppn exists on an existing user;

            LDAPConnection ldap = new LDAPConnection();
            LDAPSearchConstraints ldapSearchConstraints = ldap.getSearchConstraints();
            ldapSearchConstraints.setMaxResults( 1 );
            String myFilter="(" + config.getLdapShibAttribute() + "=" + username + ")";
            String[] myAttrs = { config.getLdapUserAttribute() };

            LDAPSearchResults myResults;

            log.debug("Searching LDAP for " + myFilter);

            try {
                log.trace("Connecting to LDAP at host " + config.getLdapHost() );
                ldap.connect(config.getLdapHost(), Integer.parseInt(config.getLdapPort()));
                log.trace("Binding to LDAP as user " + config.getLdapBindUser());
                ldap.authenticate(3, config.getLdapBindUser(), config.getLdapBindPassword());

                myResults = ldap.search( config.getLdapBase(), LDAPv2.SCOPE_SUB, myFilter, myAttrs, false, ldapSearchConstraints );
                if (myResults.getCount() > 0) {
                    LDAPEntry myEntry = myResults.next();
                    String cn = (String) myEntry.getAttribute(config.getLdapUserAttribute()).getStringValues().nextElement();
                    authed = true;
                    log.info("Shib eppn " + username + " found in LDAP as user " + cn);
                    username = cn;
                    // Store the Crowd username in the session context for the SSOCookie Servlet to retrieve
                    req.getSession().setAttribute("ssocookie.username", username);
                }

            } catch (LDAPException e) {
              if (e.getLDAPResultCode() == LDAPException.INVALID_CREDENTIALS) {
                  log.error("Error authenticating to or searching LDAP: " + e.getMessage());
              } else {
                  log.error("LDAP Error:", e);
              }
            } finally {
                try {
                    ldap.disconnect();
                } catch (Exception e) {
                      log.error("Error dropping LDAP Connection: ",e);
                  }
            }

            if (!authed) {
                try {
                    if (!findUser(username)) {

                        // We're about to redirect user away from their target page. Remember their target
                        // page for when they're done. Store the target URL in the session context
                        String originalRequestUrl = req.getParameter("redirectTo");
                        String referer = req.getHeader("referer");
                        String gotoUrl;

                        if (originalRequestUrl != null && originalRequestUrl.length() > 0) {
                          gotoUrl = res.encodeRedirectURL(originalRequestUrl);
                        } else {
                          gotoUrl = res.encodeRedirectURL(referer);
                        }

                        req.getSession().setAttribute(REDIRECT_ATTRIBUTE, gotoUrl);

                        // TODO: claimAccount URL should come from .properties file
                        String claimAccountUrl = res.encodeRedirectURL("/crowd/plugins/servlet/claimAccount");
                        try {
                          res.sendRedirect(claimAccountUrl);
                          log.info("New user: Redirecting to " + claimAccountUrl);
                        } catch (IOException ex) {
                          log.error("Error trying to redirect to claimAccount servlet!", ex);
                        }
                        return;
                    }
                } catch (Exception e) {
                  // Not sure in which case this can come up while the system is
                  // working correctly so we'll just ignore this
                }
            }
        }

          // End of block copied from ShibbolethSSOFilter

        if (!authed) { username = null; }

        // Figure out where the user's trying to get to. If it's not passed in, check the session
        // and if it's not there, use the referrer as a last resort
        String originalRequestUrl = req.getParameter("redirectTo");
        if (originalRequestUrl == null) {
            originalRequestUrl = (String) req.getSession().getAttribute(REDIRECT_ATTRIBUTE);
        }

        if (username == null || username.length() == 0) {
            log.error("No username found in Session. Did Shib session fail?");
            errorPage(res, "USER parameter is blank. Possible causes (in order of likelihood): <ul><li>Your Identity Provider did not give our site access to your identity. The 'eppn', or eduPersonPrincipalName, attribute is required to gain access to this site..</li><li>You aren't accessing this site over HTTPS (Shibboleth will not pass secure information over HTTP</li><li>Some other error that we couldn't predict occurred</li></ul>");
            return;
        }

        log.debug("SSOCookieServlet: processing GET");

        // FIgure out what URL the user's headed to and generate an SSO token accordingly

        String referer = req.getHeader("referer");
        String gotoUrl;

        if (originalRequestUrl != null && originalRequestUrl.length() > 0) {
            gotoUrl = res.encodeRedirectURL(originalRequestUrl);
        } else {
            gotoUrl = res.encodeRedirectURL(referer);
        }

        // Choose a sensible default app name in case we can't determine the right one
        String appName = Configuration.DEFAULT_APPLICATION;

        log.debug("Searching apps for URL " + gotoUrl);
        // Search the list of Crowd applications for this URL
        for (Object key : config.applications.keySet()) {
            String url = config.applications.get(key);
            if (gotoUrl.contains(url)) {
                appName = (String) key;
                log.debug("Found match with " + appName);
                break;
            }
        }

        // Make sure the user exists and has access to the target application


        authCtx.setName(username);
        authCtx.setApplication(appName);

        ValidationFactor[] validationFactors = httpAuthenticator.getValidationFactors(req);
        authCtx.setValidationFactors(validationFactors);
        CrowdSSOAuthenticationToken crowdAuthRequest = null;
        try {
            crowdAuthRequest = new CrowdSSOAuthenticationToken(tokenAuthenticationManager.authenticateUserWithoutValidatingPassword(authCtx).getRandomHash());
            log.info("Setting CrowdSSO Token for application " + appName);
        } catch (InvalidAuthenticationException e) {
            log.error(e.getMessage());
            errorPage(res, e.getMessage());
            return;
        } catch (ApplicationAccessDeniedException e) {
            log.error(username + " is denied access to " + appName);
            log.error(e.getMessage());
            accessDeniedPage(res);
            return;
        } catch (InactiveAccountException e) {
            log.error("Account is inactive: " + e.getMessage());
            errorPage(res, e.getMessage());
            return;
        } catch (ObjectNotFoundException e) {
            log.error("Object not found: " + e.getMessage());
            accessDeniedPage(res);
            return;
        } catch (OperationFailedException e) {
            log.error(e.getMessage());
            errorPage(res, e.getMessage());
        }

        // fix for Confluence where the response filter is sometimes null.
        if (res != null && crowdAuthRequest != null && crowdAuthRequest.getCredentials() != null) {
            log.debug("Creating cookie");
            // create the cookie sent to the client
            Cookie tokenCookie = buildCookie(crowdAuthRequest.getCredentials().toString());

            log.debug("Cookie: " + tokenCookie.getDomain() + " - " + tokenCookie.getName() + " " + tokenCookie.getValue());

            res.addCookie(tokenCookie);
        } else {
            accessDeniedPage(res);
            return;
        }

	    log.info("Redirecting to " + gotoUrl);
        res.sendRedirect(gotoUrl);
    }

    /**
     * Creates the cookie and sets attributes such as path, domain, and "secure" flag.
     * @param token The SSO token to be included in the cookie
     * @return Cookie Generated cookie to return to the browser
     */
    private Cookie buildCookie(String token) {
        Cookie tokenCookie = new Cookie(getCookieTokenKey(), token);

        // path
        tokenCookie.setPath(Constants.COOKIE_PATH);

        if (config.getCookieDomain() != null) {
            tokenCookie.setDomain(config.getCookieDomain());
        }

        // TODO: Add .properties attribute to allow setting "Secure" to TRUE
        // "Secure" flag
        tokenCookie.setSecure(Boolean.FALSE);

        return tokenCookie;
    }

    // TODO A real error page
    private void errorPage(HttpServletResponse res, String error) throws IOException {
        if (error != null) {
            res.getWriter().write("ERROR: " + error);
        } else {
            res.getWriter().write("Undefined error");
        }
    }

    // TODO: Should this use errorPage for a "common look and feel" error page?
    private void accessDeniedPage(HttpServletResponse res) throws IOException {
        res.sendError(HttpServletResponse.SC_UNAUTHORIZED, "You do not have access to the application");
    }

    public String getCookieTokenKey() {
        return clientProperties.getCookieTokenKey();
    }

    // Determine whether a user exists in the configured Directory
     private boolean findUser(String username) throws Exception {
         Directory targetDirectory;
         UserTemplate newUserTemplate;
         String directory = config.getDirectoryName();
         User result;

         try {
             targetDirectory = directoryManager.findDirectoryByName(directory);
         } catch (DirectoryNotFoundException e) {
             log.error("Can't search for user. Couldn't find Directory " + directory);
             // For our purposes, we're not going to add a user unless we have a directory to add them to
             throw e;
         }

         if (targetDirectory == null) {
             throw new DirectoryNotFoundException("Searching for Configured Directory returns null");
         }

         try {
             result = directoryManager.findUserByName(targetDirectory.getId(), username);
         } catch (UserNotFoundException e) {
             return false;
         }
         return (result != null);
     }

}
