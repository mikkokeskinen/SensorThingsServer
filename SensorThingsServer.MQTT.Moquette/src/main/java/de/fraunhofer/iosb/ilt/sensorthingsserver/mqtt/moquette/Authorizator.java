package de.fraunhofer.iosb.ilt.sensorthingsserver.mqtt.moquette;

import io.moquette.spi.security.IAuthorizator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * @author andrea
 */
public class Authorizator implements IAuthorizator {
    private static final Logger LOG = LoggerFactory.getLogger(Authorizator.class);

    public boolean canWrite(String topic, String user, String client) {
        LOG.info("canWrite topic: " + topic + " user: " + user + " client: " + client);
        return true;
    }

    public boolean canRead(String topic, String user, String client) {
        LOG.info("canRead topic: " + topic + " user: " + user + " client: " + client);
        return true;
    }
}
