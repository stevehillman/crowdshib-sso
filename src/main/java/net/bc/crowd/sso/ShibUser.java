package net.bc.crowd.sso;

/**
 * Created by IntelliJ IDEA.
 * Copyright 2011 BCNET Networking Society
 * User: hillman@bc.net
 * Date: 8/27/11
 * Time: 11:55 AM
 */
public class ShibUser {

    private String eppn = "";
    private String username = "";
    private String firstname = "";
    private String lastname = "";
    private String password = "";
    private String email = "";
    private boolean exists;

    public ShibUser() {
    }

    public String getEppn() {
        return eppn;
    }

    public void setEppn(String eppn) {
        this.eppn = eppn;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getFirstname() {
        return firstname;
    }

    public void setFirstname(String firstname) {
        this.firstname = firstname;
    }

    public String getLastname() {
        return lastname;
    }

    public void setLastname(String lastname) {
        this.lastname = lastname;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }


    public boolean isExists() {
        return exists;
    }

    public void setExists(boolean exists) {
        this.exists = exists;
    }
}
