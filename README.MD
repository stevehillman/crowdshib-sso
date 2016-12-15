This plugin is based very heavily on work done by Nordu.net to add Shibboleth support to their Atlassian apps
Their license file is included accordingly.

Prerequisites:
 - Atlassian Crowd
 - Confluence, Jira, or some other app you want to allow Shib login to
 - an LDAP directory that Crowd stores its users in. This plugin will not work with an Internal Crowd Directory

To install this plugin:
 - Copy the generated jar file to the %crowd-home%/plugins directory and restart Crowd
 - Copy the ShibbolethServlet.properties file to top level of your %crowd-home/ directory
 - Modify the ShibbolethServlet.properties file accordingly
 - copy the claimaccount.vm file from ./src/main/resources to your %crowd-app% root directory. Modify for your site as needed
 - copy the .js and .css files from ./src/main/resources to your %crowd-app%/crowd-webapp/console directory. Modify for your site

TODO:
 - make the plugin load the .vm, .js, and .css files from the %crowd-home%/ directory
