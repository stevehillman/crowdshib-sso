package net.bc.crowd.sso;

import java.io.File;
import java.util.HashMap;
import java.util.Properties;

/**
 * Created by IntelliJ IDEA.
 * User: hillman
 * Date: 7/25/11
 * Time: 10:02 PM
 */
public class Configuration {

    public static final String LDAP_HOST = "ldap.host";
    public static final String LDAP_PORT = "ldap.port";
    public static final String LDAP_BIND_USER = "ldap.bind.user";
    public static final String LDAP_BIND_PASSWORD = "ldap.bind.password";
    public static final String DEFAULT_GROUP = "default.group";
    public static final String DIRECTORY = "directory";
    public static final String LDAP_SHIB_ATTRIBUTE = "ldap.shib.attribute";
    public static final String LDAP_BASE = "ldap.base";
    public static final String LDAP_USER_ATTRIBUTE = "ldap.user.attribute";
    public static final String COOKIE_DOMAIN = "cookie.domain";
    public static final String RELOAD_CONFIG = "reload.config";
    public static final String RELOAD_CONFIG_INTERVAL = "reload.config.interval";
    public static final String CLAIM_ACCOUNT_TEMPLATE = "claimaccount.template.file";
    public static final String MAILTO = "mail.to";
    public static final String MAILFROM = "mail.from"; // don't change: javax.mail API expects this property name
    public static final String MAILHOST = "mail.host"; // don't change: javax.mail API expects this property name


    public static final String DEFAULT_APPLICATION = "confluence";
    public static final String APPLICATION = "application";
    public static final String APPLICATION_URL = "url";

    public HashMap<String, String> applications;

    private String ldapHost = "localhost";
    private String ldapPort = "389";
    private String ldapBindUser;
    private String ldapBindPassword;
    private String ldapBase;
    private String ldapUserAttribute = "cn";
    private String directoryName;
    private String defaultGroup;
    private String ldapShibAttribute = "eduPersonPrincipalName";
    private String cookieDomain;
    private boolean reloadConfig;
    private long reloadConfigInterval;
    private String configFile;
    private long configFileLastModified;
    private long configFileLastChecked;
    private String claimAccountTemplateFile = "claimaccount.vm";
    private Properties props;
    private String mailto;


    public String getClaimAccountTemplateFile() {
        return claimAccountTemplateFile;
    }

    public void setClaimAccountTemplateFile(String claimAccountTemplateFile) {
        this.claimAccountTemplateFile = claimAccountTemplateFile;
    }


    public String getCookieDomain() {
        return cookieDomain;
    }

    public void setCookieDomain(String cookieDomain) {
        this.cookieDomain = cookieDomain;
    }

    public String getLdapShibAttribute() {
        return ldapShibAttribute;
    }

    public void setLdapShibAttribute(String ldapShibAttribute) {
        this.ldapShibAttribute = ldapShibAttribute;
    }

    public Configuration() {
        applications = new HashMap<String, String>();
    }

    public String getLdapHost() {
	return ldapHost;
    }

    public void setLdapHost(String ldapHost) {
	this.ldapHost = ldapHost;
    }

    public String getLdapPort() {
	return ldapPort;
    }

    public void setLdapPort(String ldapPort) {
	this.ldapPort = ldapPort;
    }

    public String getLdapBindUser() {
           return ldapBindUser;
     }

     public void setLdapBindUser(String ldapBindUser) {
           this.ldapBindUser = ldapBindUser;
     }

     public String getLdapBindPassword() {
           return ldapBindPassword;
     }

     public void setLdapBindPassword(String ldapBindPassword) {
           this.ldapBindPassword = ldapBindPassword;
     }

     public String getLdapBase() {
        return ldapBase;
     }

     public void setLdapBase(String ldapBase) {
        this.ldapBase = ldapBase;
     }

     public String getLdapUserAttribute() {
        return ldapUserAttribute;
     }

     public void setLdapUserAttribute(String ldapUserAttribute) {
        this.ldapUserAttribute = ldapUserAttribute;
     }

    public String getDirectoryName() {
	return directoryName;
    }

    public void setDirectoryName(String directoryName) {
	this.directoryName = directoryName;
    }

    public String getDefaultGroup() {
	return defaultGroup;
    }

    public void setDefaultGroup(String defaultGroup) {
	this.defaultGroup = defaultGroup;
    }

    public boolean isReloadConfig() {
        return reloadConfig;
    }

    public void setReloadConfig(boolean reloadConfig) {
        this.reloadConfig = reloadConfig;
    }

    public long getReloadConfigInterval() {
        return reloadConfigInterval;
    }

    public void setReloadConfigInterval(long reloadConfigInterval) {
        this.reloadConfigInterval = reloadConfigInterval;
    }

    public long getConfigFileLastChecked() {
        return configFileLastChecked;
    }

    public void setConfigFileLastChecked(long configFileLastChecked) {
        this.configFileLastChecked = configFileLastChecked;
    }

    public long getConfigFileLastModified() {
        return configFileLastModified;
    }

    public void setConfigFileLastModified(long configFileLastModified) {
        this.configFileLastModified = configFileLastModified;
    }

    public String getConfigFile() {
        return configFile;
    }

    public void setConfigFile(String configFile) {
        this.configFile = configFile;
    }

     public boolean checkReloadConfig() {

        if (reloadConfig && configFile != null) {
            if (System.currentTimeMillis() < configFileLastChecked + reloadConfigInterval) {
                return false;
            }

            long configFileLastModified = new File(configFile).lastModified();

            if (configFileLastModified != this.configFileLastModified) {
                return true;
            } else {
                setConfigFileLastChecked(System.currentTimeMillis());
                return false;
            }
        }
        return false;
    }

    public String getMailto() {
        return mailto;
    }

    public void setMailto(String mailto) {
        this.mailto = mailto;
    }

    public Properties getProps() {
        return props;
    }

    public void setProps(Properties props) {
        this.props = props;
    }
}
