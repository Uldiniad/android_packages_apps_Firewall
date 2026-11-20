/*
 * SPDX-FileCopyrightText: The LineageOS Project
 * SPDX-License-Identifier: Apache-2.0
 */

package org.lineageos.firewall.hostside.app;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import android.Manifest;
import android.content.pm.webapp.WebAppInstallRequest;
import android.content.pm.webapp.WebAppManager;
import android.net.ConnectivityManager;
import android.net.ProxyInfo;
import android.net.Uri;
import android.net.wifi.WifiConfiguration;
import android.net.wifi.WifiManager;

import com.android.compatibility.common.util.PollingCheck;
import com.android.compatibility.common.util.SystemUtil;

import org.junit.Test;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Proxy;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;

/** Asks system services to fetch for this app; the host checks the firewall refused them. */
public class DelegatedTraffic {
    @Test
    public void requestWebAppInstall() throws Exception {
        WebAppManager manager = Firewall.context().getSystemService(WebAppManager.class);
        assertTrue("WebApp is unavailable", manager != null && manager.isAvailable());
        CompletableFuture<Integer> result = new CompletableFuture<>();
        manager.install(new WebAppInstallRequest.Builder("Firewall test",
                "https://example.com/manifest.json").build(), Runnable::run,
                (packageName, code) -> result.complete(code));
        assertEquals(WebAppInstallRequest.RESULT_NETWORK_ERROR,
                (int) result.get(30, TimeUnit.SECONDS));
    }

    /**
     * Requests through Android's local PAC proxy, set on the Wi-Fi network as a user would, with
     * a PAC file that sends everything direct.
     */
    @Test
    public void requestThroughAPacProxy() throws Exception {
        WifiManager wifi = Firewall.context().getSystemService(WifiManager.class);
        try (ServerSocket server = new ServerSocket(0, 50, InetAddress.getByName("127.0.0.1"))) {
            new Thread(() -> servePac(server)).start();
            WifiConfiguration config = SystemUtil.runWithShellPermissionIdentity(() -> {
                int id = wifi.getConnectionInfo().getNetworkId();
                return wifi.getPrivilegedConfiguredNetworks().stream()
                        .filter(c -> c.networkId == id).findFirst().orElseThrow();
            }, Manifest.permission.NETWORK_SETTINGS, Manifest.permission.READ_WIFI_CREDENTIAL);
            ProxyInfo before = config.getHttpProxy();
            setProxy(wifi, config, ProxyInfo.buildPacProxy(
                    Uri.parse("http://127.0.0.1:" + server.getLocalPort() + "/proxy.pac")));
            try {
                ConnectivityManager cm = Firewall.context().getSystemService(
                        ConnectivityManager.class);
                // Java's own selector runs the PAC file in the app, so this request goes through
                // Android's local proxy the way WebView and native code do, once it's started.
                PollingCheck.waitFor(30_000, () -> cm.getDefaultProxy() != null
                        && cm.getDefaultProxy().getPort() > 0, "No PAC proxy");
                ProxyInfo local = cm.getDefaultProxy();
                // HTTPS, as apps may not send cleartext; the proxy gets a CONNECT for it.
                HttpURLConnection connection = (HttpURLConnection) new URL("https://192.0.2.1/")
                        .openConnection(new Proxy(Proxy.Type.HTTP,
                                new InetSocketAddress(local.getHost(), local.getPort())));
                connection.setConnectTimeout(10_000);
                connection.setReadTimeout(10_000);
                try {
                    connection.getResponseCode();
                } catch (IOException e) {
                    // The proxy can't reach it; the host checks the firewall refused it.
                }
            } finally {
                setProxy(wifi, config, before);
            }
        }
    }

    /** Saves the network's proxy as Settings does, which also applies it to the connection. */
    private static void setProxy(WifiManager wifi, WifiConfiguration config, ProxyInfo proxy) {
        config.setHttpProxy(proxy);
        CompletableFuture<Boolean> saved = new CompletableFuture<>();
        // Wi-Fi checks the permission again on its own thread, so it's held until the reply.
        SystemUtil.runWithShellPermissionIdentity(() -> {
            wifi.save(config, new WifiManager.ActionListener() {
                @Override
                public void onSuccess() {
                    saved.complete(true);
                }

                @Override
                public void onFailure(int reason) {
                    saved.complete(false);
                }
            });
            assertTrue("Wi-Fi didn't save the proxy", saved.get(10, TimeUnit.SECONDS));
        }, Manifest.permission.NETWORK_SETTINGS);
    }

    /** Serves a PAC file that sends everything direct, to each request until closed. */
    private static void servePac(ServerSocket server) {
        String pac = "function FindProxyForURL(url, host) { return \"DIRECT\"; }";
        String response = "HTTP/1.0 200 OK\r\nContent-Type: application/x-ns-proxy-autoconfig"
                + "\r\nContent-Length: " + pac.length() + "\r\n\r\n" + pac;
        while (!server.isClosed()) {
            try (Socket client = server.accept()) {
                BufferedReader in = new BufferedReader(
                        new InputStreamReader(client.getInputStream(), StandardCharsets.UTF_8));
                for (String line = in.readLine(); line != null && !line.isEmpty();
                        line = in.readLine()) {
                    // Skips the request, as any request gets the file.
                }
                client.getOutputStream().write(response.getBytes(StandardCharsets.UTF_8));
            } catch (IOException e) {
                // Closed at the end of the test, or a client went away.
            }
        }
    }
}
