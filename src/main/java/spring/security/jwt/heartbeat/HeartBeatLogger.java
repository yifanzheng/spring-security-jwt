package spring.security.jwt.heartbeat;

/**
 * HeartBeatLogger
 */
public interface HeartBeatLogger {

    void error(String message);

    void error(String message, Throwable e);

    void info(String message);
}
