package de.fraunhofer.iosb.ilt.sensorthingsserver.mqtt.moquette;

import io.moquette.spi.security.IAuthenticator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class Authenticator implements IAuthenticator {
    private static final Logger LOGGER = LoggerFactory.getLogger(Authenticator.class);

    public boolean checkValid(String clientId, String username, byte[] password) {
        LOGGER.warn("Tried USERNAME: " + username);
        return true;
    }
}
