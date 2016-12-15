/*
 * Copyright (c) 2011, BCNET Networking Society
 * This work is based on code originally developed by NORDUnet. Their copyright appears below
 *
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
import com.atlassian.crowd.embedded.api.PasswordCredential;
import com.atlassian.crowd.embedded.api.User;
import com.atlassian.crowd.exception.*;
import com.atlassian.crowd.manager.application.AliasManager;
import com.atlassian.crowd.manager.application.ApplicationManager;
import com.atlassian.crowd.manager.application.ApplicationService;
import com.atlassian.crowd.manager.authentication.TokenAuthenticationManager;
import com.atlassian.crowd.manager.directory.DirectoryManager;
import com.atlassian.crowd.manager.directory.DirectoryPermissionException;
import com.atlassian.crowd.model.user.UserTemplate;
import com.atlassian.crowd.service.client.ClientProperties;
import com.atlassian.plugin.webresource.WebResourceManager;
import netscape.ldap.LDAPAttribute;
import netscape.ldap.LDAPConnection;
import netscape.ldap.LDAPException;
import netscape.ldap.LDAPModification;
import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.apache.velocity.Template;
import org.apache.velocity.VelocityContext;
import org.apache.velocity.app.VelocityEngine;
import org.bouncycastle.util.encoders.Base64;

import javax.mail.Message;
import javax.mail.Session;
import javax.mail.Transport;
import javax.mail.internet.MimeMessage;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;

/**
 * This is now the workhorse for the shib module
 * Servlet for claiming old accounts.
 * We get here from either SSOCookieServlet or ShibbolethSSOFilter
 *  when a never-before-seen Shib eppn logs in.
 * To "claim" an existing account, we add the Shibboleth
 * eppn as an attribute to the Crowd account's LDAP entry
 * If the user chooses not to claim an account, we must create a new one and add one or more
 * default groups to that account to give them a basic level of access
 *
 * @author Juha-Matti Leppälä <juha@eduix.fi>
 * @version $Id$
 *
 * @author Steve Hillman <hillman@bc.net>
 */
public class ClaimAccountServlet extends HttpServlet {

    private static final Logger log = Logger.getLogger(ClaimAccountServlet.class);
    private DirectoryManager directoryManager;
    private AliasManager aliasManager;
    private ApplicationManager applicationManager;
    private ApplicationService applicationService;
    private TokenAuthenticationManager tokenAuthenticationManager;
    private ClientProperties clientProperties;
    private WebResourceManager webResourceManager;
    private static Configuration config;
    private static SecureRandom prng;
    private static MessageDigest sha;


    static {
        config = ConfigurationLoader.loadConfiguration(null);

        try {
            prng = SecureRandom.getInstance("SHA1PRNG");
            sha = MessageDigest.getInstance("SHA-1");
        } catch (NoSuchAlgorithmException e) {
            log.error(e);
        }
    }

    public ClaimAccountServlet(DirectoryManager directoryManager, AliasManager aliasManager, ApplicationManager applicationManager, ApplicationService applicationService, TokenAuthenticationManager tokenAuthenticationManager, ClientProperties clientProperties, WebResourceManager webResourceManager) {
        this.directoryManager = directoryManager;
        this.aliasManager = aliasManager;
        this.applicationManager = applicationManager;
        this.applicationService = applicationService;
        this.tokenAuthenticationManager = tokenAuthenticationManager;
        this.clientProperties = clientProperties;
        this.webResourceManager = webResourceManager;
    }


    // If we have a Shib username, draw the ClaimAccount form, otherwise just write out an error
    // We don't make use of aliases at BCNET so just use the shib username in the Form
    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {        
        String username = req.getHeader("REMOTE_USER");
        ShibUser shibUser = new ShibUser();
        shibUser.setEppn(username);
        resp.setContentType("text/html");

        // Check to see if the properties file needs reloading
        if (config.checkReloadConfig()) {
            log.info("Properties file has changed. Reloading config");
            config = ConfigurationLoader.loadConfiguration(config.getConfigFile());
        }

        String action = req.getParameter("action");

        // Test for AJAX action call
        if (action != null && action.equals("checkUser")) {
            String user = req.getParameter("newUsername");

            resp.setContentType("text/json");

            PrintWriter writer = resp.getWriter();

            log.info("Processing checkUser AJAX call for value " + user);

            try {
                if (findUser(user)) {
                    writer.write("\"That username is in use\"");
                } else {
                    writer.write("\"true\"");
                }

            } catch (Exception e) {
                writer.write("\"true\"");
            }
            return;
        }

        log.info("Returning ClaimAccount Form for Shib User " + username);

        writeAccountClaimFormNew(req, resp, shibUser, null);
    }


    // Process the ClaimAccount form
    //  if 'reclaim' was selected, try binding to Crowd LDAP using supplied id/pw
    //    if successful, add eppn to LDAP entry
    //    if not successful, redraw form
    //  if 'reclaim' not selected, create new Crowd user and add to default groups
    //    use code from ShibbolethSSOfilter to create acct
    //
    // Note, it's only necessary to use LDAP directly because Crowd doesn't support adding
    // custom attributes to LDAP, which we need to do to add in the eppn. Since we need
    // the LDAP connection anyway, may as well use it for the auth step too (because
    // NORDUNET already wrote that part

    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        List<String> errors = new ArrayList<String>();
        ShibUser shibUser = new ShibUser();
        resp.setContentType("text/html");


         // Check to see if the properties file needs reloading
        if (config.checkReloadConfig()) {
            log.debug("Properties file has changed. Reloading config");
            config = ConfigurationLoader.loadConfiguration(config.getConfigFile());
        }


        shibUser.setEppn(req.getHeader("REMOTE_USER"));
        log.info("Processing ClaimAccount Form for Shib User " + shibUser.getEppn());

        boolean reclaim = Boolean.parseBoolean(req.getParameter("reclaim"));
        String account = req.getParameter("username").toLowerCase();
        String password = req.getParameter("password");

        shibUser.setFirstname(req.getParameter("firstname"));
        shibUser.setLastname(req.getParameter("lastname"));
        shibUser.setEmail(req.getParameter("email"));
        shibUser.setUsername(account);
        shibUser.setPassword(password);

        if (shibUser.getFirstname() == null) { shibUser.setFirstname(""); }
        if (shibUser.getLastname() == null) { shibUser.setLastname(""); }
        if (shibUser.getEmail() == null) { shibUser.setEmail(""); }
        if (shibUser.getPassword() == null) { shibUser.setPassword(""); }
        if (shibUser.getUsername() == null) { shibUser.setUsername(""); }


        log.debug("Reclaim = "  + req.getParameter("reclaim"));
        log.debug("username = " + account);
        log.debug("First Name = " + shibUser.getFirstname());
        log.debug("Last Name = " + shibUser.getLastname());
        log.debug("Email = " + shibUser.getEmail());

	    boolean authed = false;
        String defaultGroup = config.getDefaultGroup();

	    if (reclaim)
	    {
            log.debug("Processing account reclaim request");
            if (StringUtils.isBlank(account) || StringUtils.isBlank(password)) {
                errors.add("Username or password was invalid");
                writeAccountClaimFormNew(req, resp, shibUser, errors);
                return;
            }

            LDAPConnection ldap = new LDAPConnection();
            try {
                ldap.connect(config.getLdapHost(), Integer.parseInt(config.getLdapPort()));
                ldap.authenticate(3, usernameToUID(account), password);
	            authed = true;
                log.debug("LDAP authentication succesful as " + usernameToUID(account));
            } catch (LDAPException e) {
                if (e.getLDAPResultCode() == LDAPException.INVALID_CREDENTIALS) {
                    log.error("Error authenticating " + usernameToUID(account) + " to LDAP: " + e.getMessage());
                    errors.add("Username or password was invalid");
                } else {
                    errors.add("Error communicating with LDAP. Contact administration");
                    log.error(e);
                }
                writeAccountClaimFormNew(req, resp, shibUser, errors);
                return;
            } finally {
	            if (!authed) {
            	    try {
                	    ldap.disconnect();
            	    } catch (Exception e) {
                        log.error(e);
            	    }
	            }
            }
	        // Authentication was successful. Add the eppn to ldap
	        // Note, we don't check for a pre-existing eppn attribute. If you use a single-value LDAP attribute and it
            // is already present, this will throw an Exception. If you use a multi-value attribute, multiple Shibboleth
            // identities can be affiliated with a single Crowd account (arguably a good thing)
	        try {
	            LDAPModification ldapChange = new LDAPModification(LDAPModification.ADD, new LDAPAttribute(config.getLdapShibAttribute(),shibUser.getEppn()));
	            ldap.modify(usernameToUID(account), ldapChange );
                shibUser.setExists(true);
                log.info("Added eppn to account " + usernameToUID(account));
                sendEmail(req, shibUser,account,false);
	        } catch (LDAPException e) {
	            errors.add("Error adding Shibboleth identity to LDAP. Error was logged. Contact administration");
                log.error("Error adding Shib eppn to LDAP: ",e);
            }
            writeAccountClaimFormNew(req, resp, shibUser, errors);

	    } // reclaim
	    else {
	        // Not trying to reclaim -- create a new account in Crowd,
	        // then bind to LDAP and add the eppn

            log.debug("Processing new account request for " + shibUser.getEppn());
            if (shibUser.getFirstname().equals("") || shibUser.getLastname().equals("") || shibUser.getEmail().equals("") || shibUser.getUsername().equals("")) {
                errors.add("You must supply a first name, last name, and email address to create a new account");
                writeAccountClaimFormNew(req, resp, shibUser, errors);
                return;
            }

            try {
                if (createUser(shibUser, defaultGroup)) {
                    // User was created successfully - connect to LDAP and add the eppn
                    log.info("Created Crowd account for " + account);
                    LDAPConnection ldap = new LDAPConnection();
                    try {
                          ldap.connect(config.getLdapHost(), Integer.parseInt(config.getLdapPort()));
                          ldap.authenticate(3, usernameToUID(account), shibUser.getPassword());
                          authed = true;
                    } catch (LDAPException e) {
                          if (e.getLDAPResultCode() == LDAPException.INVALID_CREDENTIALS) {
                              log.error("Error authenticating to LDAP after creating Crowd account:: " + e.getMessage());
                          }
                          errors.add("Error communicating with LDAP. Contact administration");
                          log.error(e);
                          writeAccountClaimFormNew(req, resp, shibUser, errors);
                          return;
                    } finally {
                          if (!authed) {
                              try {
                                  ldap.disconnect();
                              } catch (Exception e) {
                                  log.error(e);
                              }
                          }
                    }
                    // authentication was successful. Add the eppn to ldap
                    try {
                        LDAPModification ldapChange = new LDAPModification(LDAPModification.ADD, new LDAPAttribute(config.getLdapShibAttribute(),shibUser.getEppn()));
                        ldap.modify(usernameToUID(account), ldapChange );
                        shibUser.setExists(true);
                        log.info("Added eppn " + shibUser.getEppn() + " to account " + usernameToUID(account));
                        sendEmail(req, shibUser,account,true);

                    } catch (LDAPException e) {
                          errors.add("Error communicating with LDAP. Error was logged. Contact administration");
                          log.error(e);
                    }

                    writeAccountClaimFormNew(req, resp, shibUser, errors);
                } // createUser
                else {
                    errors.add("Error creating new Crowd account. Contact site administrator");
                    writeAccountClaimFormNew(req, resp, shibUser, errors);
                    // Couldn't create the user. Notify them that they're screwed
                }
            } catch (UserAlreadyExistsException ex) {
                errors.add("That username already exists. If it's your account, please enter your password and choose 'Claim Account'. Otherwise, choose a different username");
                log.info("Attempted to create Crowd account which already exists: " + account);
                writeAccountClaimFormNew(req, resp, shibUser, errors);
            }

        }
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

    private boolean createUser(ShibUser newUser, String groups) throws UserAlreadyExistsException {

        Directory targetDirectory;
        UserTemplate newUserTemplate;
        String directory = config.getDirectoryName();

        try {
            targetDirectory = directoryManager.findDirectoryByName(directory);
        } catch (DirectoryNotFoundException e) {
            log.error("Not adding user. Couldn't find Directory " + directory);
            // For our purposes, we're not going to add a user unless we have a directory to add them to
            return false;
        }

         if (targetDirectory != null) {
             log.debug("Creating user in DirectoryId " + targetDirectory.getId());
             newUserTemplate = new UserTemplate(newUser.getUsername(), targetDirectory.getId());
             newUserTemplate.setFirstName(newUser.getFirstname());
             newUserTemplate.setLastName(newUser.getLastname());
             newUserTemplate.setEmailAddress(newUser.getEmail());
        }
        else {
            log.error("Not adding user. Directory is null?? " + directory);
            // For our purposes, we're not going to add a user unless we have a directory to add them to
            return false;
        }

        // Generate a random password  if the user didn't specify one

        if (newUser.getPassword().equals("")) {
            newUser.setPassword(randomPassword());
        }

        PasswordCredential credentials = new PasswordCredential(newUser.getPassword(), false);

        try {
            directoryManager.addUser(targetDirectory.getId(), newUserTemplate, credentials);
         } catch (InvalidCredentialException ex) {
            log.error("Invalid Credentials. Insufficient access to add users to this directory");
            log.error(ex);
            return false;
         } catch (InvalidUserException ex) {
            log.error("Invalid User Exception");
            log.error(ex);
            return false;
         } catch (OperationFailedException ex) {
            log.error("Operation Failed. Could not create user " + newUser.getUsername());
            log.error(ex);
            return false;
         } catch (DirectoryNotFoundException ex) {
            log.error("Directory Not Found: " + directory);
            log.error(ex);
            return false;
         } catch (UserAlreadyExistsException ex) {
            log.error("User '" + newUser.getUsername() + "' already exists!");
            log.error(ex);
            throw ex;
         } catch (Exception e) {
            log.error("Unknown error");
            log.error(e);
            return false;
        }

        // Add the user to default group(s) as long as a default group was specified
        if (groups != null && !groups.equals("")) {
            for(String groupName: groups.split(","))  {
                   try {
                       directoryManager.addUserToGroup(targetDirectory.getId(), newUser.getUsername(), groupName);
                       log.info("Added user " + newUser.getUsername() + " to Crowd group " + groupName);
                   } catch (GroupNotFoundException e) {
                       log.error("Error: No such group: " + groupName);
                       log.error(e);
                       return false;
                   } catch (UserNotFoundException e) {
                       log.error("WTF? I just created this user, yet Crowd says User not found!");
                       log.error(e);
                       return false;
                   } catch (DirectoryPermissionException e) {
                       log.error("Insufficient privileges to change directory");
                       log.error(e);
                   } catch (CrowdException e) {
                       log.error("An error occurred adding user '" + newUser.getUsername() + "'");
                       log.error(e);
                       return false;
                   }
            }
         }
        return true;
    }


     private String randomPassword() {

         //generate a random number
         String randomNum = Integer.toString(prng.nextInt());

         //get its digest
         byte[] result = sha.digest(randomNum.getBytes());
         // The byte[] returned by MessageDigest does not have a nice
         // textual representation so we Base64 encode it before returning it
         return new String(Base64.encode(result));
     }

    private String usernameToUID(String username) {
        return config.getLdapUserAttribute() + "=" + username + "," + config.getLdapBase();
    }



    private void writeAccountClaimFormNew(HttpServletRequest req, HttpServletResponse resp, ShibUser user,  List errors)  throws ServletException, IOException

    {
        PrintWriter writer = resp.getWriter();
        try {
            VelocityEngine ve = new VelocityEngine();
            ve.init();

            VelocityContext context = new VelocityContext();
            context.put("eppn", user.getEppn());
            context.put("username", user.getUsername());
            context.put("firstname", user.getFirstname());
            context.put("lastname", user.getLastname());
            context.put("email", user.getEmail());
            context.put("errors", errors);
            context.put("exists", new Boolean (user.isExists()) );
            context.put("gotoURL", "ssocookie?redirectTo=" + req.getSession().getAttribute(SSOCookieServlet.REDIRECT_ATTRIBUTE));

            /*
            *   get the Template
            */
            Template webForm = ve.getTemplate(config.getClaimAccountTemplateFile() );

            /*
             *  now render the template into a Writer, here
             *  a StringWriter
             */

            webForm.merge(context, writer);

        } catch (Exception e) {
            log.error(e);
            writer.write("<HTML><BODY>An error occurred rendering the page: " + e + "</BODY></HTML>");
        }


    }

    private void sendEmail(HttpServletRequest request, ShibUser shibUser, String account, boolean isNew) {
        String subject;
        StringBuffer body = new StringBuffer();

        if (config.getProps().getProperty(Configuration.MAILHOST) != null && config.getProps().getProperty(Configuration.MAILFROM) != null
              && config.getProps().getProperty(Configuration.MAILTO) != null) {
            try {
                // required params are defined. We can send mail
                log.info("Sending 'new user' message to: " + config.getMailto());
                Session session = Session.getDefaultInstance(config.getProps());
                MimeMessage message = new MimeMessage(session);
                message.addRecipients(Message.RecipientType.TO, config.getMailto());
                if (isNew) {
                    subject = "Created new Crowd user " + account + " from Shibboleth";
                } else {
                    subject = "Added Shib identity to Crowd user " + account;
                }
                message.setSubject(subject);

                body.append("Details:\n");
                body.append("Crowd account: " + account);
                body.append("\nShibboleth EPPN: " + shibUser.getEppn());
                body.append("\nNew Account: " + isNew);
                if (isNew) {
                    body.append("\nEmail Address Given: ");
                    body.append(shibUser.getEppn());
                    body.append("\nFirst Name Given: ");
                    body.append(shibUser.getFirstname());
                    body.append("\nLast Name Given: ");
                    body.append(shibUser.getLastname());
                }
                body.append("\n\n\nFull dump of Shibboleth data passed to BCNET:\n");
                Enumeration headerNames = request.getHeaderNames();
                while (headerNames.hasMoreElements()) {
                    String h = (String) headerNames.nextElement();
                    body.append(h + " - " + request.getHeader(h) + "\n");
                }
                message.setText(body.toString());
                Transport.send(message);
            } catch (Exception e) {
                e.printStackTrace();
            }
        } else {
            log.info("One of mail.host, mail.from or mail.to are not defined in Properties file. Skipping sending email notification");
        }

    }
}
