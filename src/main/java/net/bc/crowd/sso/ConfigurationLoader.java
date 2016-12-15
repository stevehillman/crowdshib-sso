package net.bc.crowd.sso;

/**
 * Created by IntelliJ IDEA.
 * Copyright 2011 BCNET Networking Society
 * User: hillman@bc.net
 * Date: 7/25/11
 * Time: 9:58 PM
 */

import com.atlassian.config.util.BootstrapUtils;
import org.apache.log4j.Logger;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.util.HashMap;
import java.util.Properties;

/**
 * Class for loading filter configuration
 *
 * @author Juha-Matti Leppälä <juha@eduix.fi>
 * @version $Id$
 */
public class ConfigurationLoader {

    private static final Logger log = Logger.getLogger(ConfigurationLoader.class);
    private static final String configFile = "ShibbolethServlet.properties";

    public static Configuration loadConfiguration(String file) {

        String crowdDataDir = BootstrapUtils.getBootstrapManager().getConfiguredApplicationHome();
        Configuration config = new Configuration();
        HashMap<String, String> apps = config.applications;

        if (file == null)  {
            file = configFile;
        }

        String propsFile = crowdDataDir + System.getProperty("file.separator") + file;

        try {
            InputStream propsIn;
                log.debug("Attempting to load config file from " + propsFile);
                propsIn = new FileInputStream(propsFile);

            if(propsIn == null) {
                throw new RuntimeException("Error loading Properties. Configuration file not found");
            }
            Properties props = new Properties();

            props.load(propsIn);

            config.setProps(props);

	        if (props.getProperty(Configuration.LDAP_HOST) != null) {
		        config.setLdapHost(props.getProperty(Configuration.LDAP_HOST));
	        }

	        if (props.getProperty(Configuration.LDAP_PORT) != null) {
		        config.setLdapPort(props.getProperty(Configuration.LDAP_PORT));
	        }

            if (props.getProperty(Configuration.LDAP_BIND_USER) != null) {
                 config.setLdapBindUser(props.getProperty(Configuration.LDAP_BIND_USER));
             }

              if (props.getProperty(Configuration.LDAP_BIND_PASSWORD) != null) {
                 config.setLdapBindPassword(props.getProperty(Configuration.LDAP_BIND_PASSWORD));
             }

            if (props.getProperty(Configuration.LDAP_USER_ATTRIBUTE) != null) {
                config.setLdapUserAttribute(props.getProperty(Configuration.LDAP_USER_ATTRIBUTE));
            }

            config.setLdapBase(props.getProperty(Configuration.LDAP_BASE));

            config.setCookieDomain(props.getProperty(Configuration.COOKIE_DOMAIN));

	        config.setDefaultGroup(props.getProperty(Configuration.DEFAULT_GROUP));
	        config.setDirectoryName(props.getProperty(Configuration.DIRECTORY));

            if (props.getProperty(Configuration.LDAP_SHIB_ATTRIBUTE) != null) {
                config.setLdapShibAttribute(props.getProperty(Configuration.LDAP_SHIB_ATTRIBUTE));
            }

            if (props.getProperty(Configuration.CLAIM_ACCOUNT_TEMPLATE) != null) {
                config.setClaimAccountTemplateFile(props.getProperty(Configuration.CLAIM_ACCOUNT_TEMPLATE));
            }

            config.setMailto(props.getProperty(Configuration.MAILTO));

            config.setReloadConfig(Boolean.parseBoolean(props.getProperty(Configuration.RELOAD_CONFIG)));
            String reloadInterval = props.getProperty(Configuration.RELOAD_CONFIG_INTERVAL);
            if (reloadInterval != null) {
                try {
                    config.setReloadConfigInterval(Long.parseLong(reloadInterval) * 1000);
                } catch (NumberFormatException e) {
                    config.setReloadConfigInterval(3600 * 1000);
                }
            }
            config.setConfigFileLastChecked(System.currentTimeMillis());

            if (file == null) {
                URL confFileURL = ConfigurationLoader.class.getResource(configFile);
                if (confFileURL != null && confFileURL.getProtocol().equals("file")) {
                    String confFile = confFileURL.getFile();
                    config.setConfigFile(confFile);
                }
            }
            else
            {
                config.setConfigFile(file);
            }
            if (config.getConfigFile() != null) {
                long configFileLastModified = new File(config.getConfigFile()).lastModified();
                config.setConfigFileLastModified(configFileLastModified);
            }


            // Process application URLs
             for (Object key : props.keySet()) {
                String keyString = (String) key;
                if (keyString.contains(".")) {
                    String[] parts = keyString.split("\\.", 0);
                    if (parts.length == 3 && Configuration.APPLICATION.equals(parts[0]) && Configuration.APPLICATION_URL.equals(parts[1])) {
                        String appName  = parts[2];
                        String val = props.getProperty(keyString);
                        apps.put(appName, val);
                        log.debug("Loading app Name = " + appName + ". URL = " + val);
                    }
                }
            }
        } catch (IOException ex) {
            log.error("Error loading properties file", ex);
        }
        return config;
    }
}

