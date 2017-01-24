/*
 * Copyright (C) 2016 Fraunhofer Institut IOSB, Fraunhoferstr. 1, D 76131
 * Karlsruhe, Germany.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
package de.fraunhofer.iosb.ilt.sensorthingsserver.mqtt.moquette;

import java.nio.charset.Charset;
import java.util.Calendar;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.login.LoginException;

import org.keycloak.adapters.jaas.AbstractKeycloakLoginModule;
import org.keycloak.adapters.jaas.BearerTokenLoginModule;
import org.keycloak.adapters.jaas.DirectAccessGrantsLoginModule;
import org.slf4j.LoggerFactory;

import io.moquette.server.config.IConfig;
import io.moquette.spi.security.IAuthenticator;
import io.moquette.spi.security.IAuthorizator;

/**
 *
 * @author scf
 */
public class AuthOpenIDConnect implements IAuthenticator, IAuthorizator {

    /**
     * The logger for this class.
     */
    private static final org.slf4j.Logger LOGGER = LoggerFactory.getLogger(AuthOpenIDConnect.class);
    private static final Charset UTF8 = Charset.forName("UTF-8");
    private static String sensorThingsClientID;
    private final int cutoffHours = 24;

    private class Client {

        public final String userName;
        public String token;
        public Calendar lastSeen;
        public Subject subject;

        public Client(String userName) {
            this.userName = userName;
        }

    }
    /**
     * The map of clients with their tokens. We need those to determine the
     * authorisation. But how long do we keep those? TODO: Needs a cleanup
     * routine to avoid memory leak.
     */
    private static final Map<String, Client> clientMap = new HashMap<>();
    private static final Map<String, Object> sharedState = new HashMap<>();
    private static final Map<String, Object> options = new HashMap<>();

    public AuthOpenIDConnect(IConfig conf) {
        options.put("keycloak-config-file", conf.getProperty(MoquetteMqttServer.TAG_KEYCLOAK_CONFIG_FILE));
    }

    private void clientMapCleanup() {
        try {
            Calendar cutoff = Calendar.getInstance();
            cutoff.add(Calendar.HOUR, -cutoffHours);
            LOGGER.debug("Cleaning up client map... Current size: {}.", clientMap.size());
            Iterator<Map.Entry<String, Client>> i;
            for (i = clientMap.entrySet().iterator(); i.hasNext();) {
                Map.Entry<String, Client> entry = i.next();
                if (entry.getValue().lastSeen.before(cutoff)) {
                    i.remove();
                }
            }
            LOGGER.debug("Done cleaning up client map. Current size: {}.", clientMap.size());
        } catch (Exception e) {
            LOGGER.warn("Exception while cleaning up client map.", e);
        }
    }

    @Override
    public boolean checkValid(final String clientId, final String username, final byte[] password) {
        if (clientId != null && clientId.equals(sensorThingsClientID)) {
            return true;
        }

        AbstractKeycloakLoginModule loginModule;
        if (password.length > 50) {
            loginModule = new BearerTokenLoginModule();
        } else {
            loginModule = new DirectAccessGrantsLoginModule();
        }

        clientMapCleanup();

        return checkLogin(loginModule, username, password, clientId);
    }

    private boolean checkLogin(AbstractKeycloakLoginModule loginModule, final String username, final byte[] password, final String clientId) {
        try {
            Subject subject = new Subject();
            loginModule.initialize(subject, (Callback[] callbacks) -> {
                ((NameCallback) callbacks[0]).setName(username);
                ((PasswordCallback) callbacks[1]).setPassword(new String(password, UTF8).toCharArray());
            }, sharedState, options);
            boolean login = loginModule.login();
            if (login) {
                loginModule.commit();
                Client client = new Client(username);
                client.lastSeen = Calendar.getInstance();
                client.subject = subject;
                clientMap.put(clientId, client);
            }
            return login;
        } catch (LoginException ex) {
            LOGGER.error("Login failed with exception:", ex.getMessage());
            return false;
        }
    }

    @Override
    public boolean canWrite(String topic, String user, String clientId) {
        if (clientId != null && clientId.equals(sensorThingsClientID)) {
            return true;
        }
        Client client = clientMap.get(clientId);
        if (client == null) {
            return false;
        }
        boolean canInsert = client.subject.getPrincipals().stream().anyMatch(p -> p.getName().equalsIgnoreCase("create"));
        return canInsert;
    }

    @Override
    public boolean canRead(String topic, String user, String clientId) {
        if (clientId != null && clientId.equals(sensorThingsClientID)) {
            return true;
        }
        Client client = clientMap.get(clientId);
        if (client == null) {
            return false;
        }
        boolean canInsert = client.subject.getPrincipals().stream().anyMatch(p -> p.getName().equalsIgnoreCase("read"));
        return canInsert;
    }

    public static void setSensorThingsClientID(String SensorThingsClientID) {
        AuthOpenIDConnect.sensorThingsClientID = SensorThingsClientID;
    }

}
