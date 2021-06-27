package spring.security.jwt.util;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.InetAddress;
import java.net.NetworkInterface;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;
import java.util.Objects;

/**
 * ip 工具类
 *
 * @author star
 **/
public class IpUtils {

    public static final Logger log = LoggerFactory.getLogger(IpUtils.class);

    private IpUtils() {

    }

    /**
     * 获得服务器的IP地址
     */
    public static String getLocalIP() {
        String ipStr = "";
        InetAddress inetAddress = null;
        try {
            boolean isFindIp = false;
            Enumeration<NetworkInterface> netInterfaces = NetworkInterface
                    .getNetworkInterfaces();
            while (netInterfaces.hasMoreElements()) {
                if (isFindIp) {
                    break;
                }
                NetworkInterface ni = netInterfaces
                        .nextElement();
                Enumeration<InetAddress> inetAddressList = ni.getInetAddresses();
                while (inetAddressList.hasMoreElements()) {
                    inetAddress = inetAddressList.nextElement();
                    if (!inetAddress.isLoopbackAddress()
                            && inetAddress.getHostAddress().matches(
                            "(\\d{1,3}\\.){3}\\d{1,3}")) {
                        isFindIp = true;
                        break;
                    }
                }
            }
        } catch (Exception e) {
            log.error("Get ip address fialed, message: {}", e.getMessage());
        }
        if (Objects.nonNull(inetAddress)) {
            ipStr = inetAddress.getHostAddress();
        }
        return ipStr;
    }

    /**
     * 获得服务器的IP地址(多网卡)
     */
    public static List<String> getLocalIPS() {
        InetAddress ip = null;
        List<String> ipList = new ArrayList<String>();
        try {
            Enumeration<NetworkInterface> netInterfaces = NetworkInterface
                    .getNetworkInterfaces();
            while (netInterfaces.hasMoreElements()) {
                NetworkInterface ni = netInterfaces
                        .nextElement();
                Enumeration<InetAddress> ips = ni.getInetAddresses();
                while (ips.hasMoreElements()) {
                    ip = ips.nextElement();
                    if (!ip.isLoopbackAddress()
                            && ip.getHostAddress().matches(
                            "(\\d{1,3}\\.){3}\\d{1,3}")) {
                        ipList.add(ip.getHostAddress());
                    }
                }
            }
        } catch (Exception e) {
            log.error("Get ip address fialed, message: {}", e.getMessage());
        }
        return ipList;
    }

}