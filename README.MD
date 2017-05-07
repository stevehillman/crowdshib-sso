This plugin is based very heavily on work done by Nordu.net to add Shibboleth support to their Atlassian apps
Their license file is included accordingly.

## Prerequisites:
 - Atlassian Crowd
 - Confluence, Jira, or some other app you want to allow Shib login to
 - an LDAP directory that Crowd stores its users in. This plugin will not work with an Internal Crowd Directory
 - A way to enforce Shibboleth session. Recommended: Apache web server and Shibboleth SP with Crowd reverse-proxied behind it

## To install this plugin:
 - Copy the generated jar file to the %crowd-home%/plugins directory and restart Crowd
 - Copy the ShibbolethServlet.properties file to top level of your %crowd-home/ directory
 - Modify the ShibbolethServlet.properties file accordingly
 - copy the claimaccount.vm file from ./src/main/resources to your %crowd-app% root directory. Modify for your site as needed
 - copy the .js and .css files from ./src/main/resources to your %crowd-app%/crowd-webapp/console directory. Modify for your site

## TODO:
 - make the plugin load the .vm, .js, and .css files from the %crowd-home%/ directory

## Usage:

In order to use this plugin, you need to be able to enforce a Shibboleth session for a given URL. This plugin doesn't handle
that part of the workflow - it just expects the REMOTE_USER environment variable to be populated with the Shib EPPN once
a session has been established.

The easiest way to accomplish this is by running the Shibboleth SP and Apache, and place Crowd behind Apache using a reverse
proxy configuration. With that setup, apply the following patch to <crowd-app-dir>/crowd-wepapp/WEB-INF/classes/applicationContext-CrowdSecurity.xml
```
*** applicationContext-CrowdSecurity.xml.orig	2017-05-07 12:26:34.406632163 -0700
--- applicationContext-CrowdSecurity.xml	2017-05-07 12:26:44.166633623 -0700
***************
*** 30,35 ****
--- 30,40 ----
          <security:http-basic />
      </security:http>
  
+     <!-- Security Exception for the ClaimAccount Servlet - it mustn't be protected with Crowd auth
+ >          as no Crowd user exists at this point -->
+     <security:http pattern="/plugins/servlet/claimAccount" security="none"/>
+     <security:http pattern="/plugins/servlet/ssocookie" security="none"/>
+ 
      <security:http auto-config="false"
            authentication-manager-ref="authenticationManager"
            entry-point-ref="crowdAuthenticationProcessingFilterEntryPoint"
```

Then modify your Apache config to enforce a session for the above two plugins. For example:

```# Force Shib on for all URLs but don't *require* an active session - just preserve it if it's there
# This allows our apps to initiate Shib login by calling the login URL and have the shib session
# be preserved from then on
<Location />
  AuthType shibboleth
  Require shibboleth
</Location>
#
# Special case - for the ssocookie plugin, force a Shib session as it won't force one itself but
# expects the REMOTE_USER attribute to be set
<Location /crowd/plugins/servlet/>
  AuthType shibboleth
  ShibRequestSetting requireSession 1
  ShibUseHeaders On
  Require valid-user
</Location>
```
