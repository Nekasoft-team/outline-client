// Copyright 2018 The Outline Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package org.outline;

import static android.Manifest.permission.POST_NOTIFICATIONS;

import android.app.Activity;
import android.content.ActivityNotFoundException;
import android.content.BroadcastReceiver;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.ServiceConnection;
import android.content.SharedPreferences;
import android.net.VpnService;
import android.os.Build;
import android.os.IBinder;
import android.os.Handler;
import android.os.Looper;
import android.widget.Toast;
import androidx.activity.result.ActivityResultLauncher;
import androidx.activity.result.contract.ActivityResultContracts;
import androidx.core.app.ActivityCompat;
import androidx.core.content.ContextCompat;
import androidx.core.content.PermissionChecker;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.Locale;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.Objects;
import org.apache.cordova.CallbackContext;
import org.apache.cordova.CordovaPlugin;
import org.apache.cordova.PluginResult;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import org.outline.log.OutlineLogger;
import org.outline.log.SentryErrorReporter;
// import org.outline.vpn.VpnServiceStarter;
// import org.outline.vpn.VpnTunnelService;
import org.outline.vpn.xray.AppConfigs;
import org.outline.vpn.xray.V2rayController;
import org.outline.vpn.xray.V2rayVPNService;

// import static org.outline.vpn.VpnTunnelService.ErrorCode;
// import static org.outline.vpn.VpnTunnelService.MessageData;
// import static org.outline.vpn.VpnTunnelService.TunnelStatus;

public class OutlinePlugin extends CordovaPlugin {
  private static final Logger LOG = Logger.getLogger(OutlinePlugin.class.getName());
  private SharedPreferences sharedPreferences;
  private BroadcastReceiver v2rayBroadCastReceiver;

  // Actions supported by this plugin.
  public enum Action {
    START("simpleStart"),
    STOP("stop"),
    ON_STATUS_CHANGE("onStatusChange"),
    IS_RUNNING("isRunning"),
    IS_REACHABLE("isServerReachable"),
    INIT_ERROR_REPORTING("initializeErrorReporting"),
    REPORT_EVENTS("reportEvents"),
    QUIT("quitApplication");

    private final static Map<String, Action> actions = new HashMap<>();
    static {
      for (Action action : Action.values()) {
        actions.put(action.value, action);
      }
    }

    // Returns whether |value| is a defined action.
    public static boolean hasValue(final String value) {
      return actions.containsKey(value);
    }

    public final String value;
    Action(final String value) {
      this.value = value;
    }

    // Returns whether |action| is the underlying value of this instance.
    public boolean is(final String action) {
      return this.value.equals(action);
    }
  }

  // Encapsulates parameters to start the VPN asynchronously after requesting user permission.
  // private static class StartVpnRequest {
  //   public final JSONArray args;
  //   public final CallbackContext callback;
  //   public StartVpnRequest(JSONArray args, CallbackContext callback) {
  //     this.args = args;
  //     this.callback = callback;
  //   }
  // }

  private static final int REQUEST_CODE_PREPARE_VPN = 100;

  // AIDL interface for VpnTunnelService, which is bound for the lifetime of this class.
  // The VpnTunnelService runs in a sub process and is thread-safe.
  // A race condition may occur when calling methods on this instance if the service unbinds.
  // We catch any exceptions, which should generally be transient and recoverable, and report them
  // to the WebView.
  // private VpnTunnelService vpnTunnelService = new VpnTunnelService();
  private String errorReportingApiKey;
  // private StartVpnRequest startVpnRequest;
  // Tunnel status change callback by tunnel ID.
  // private final Map<String, CallbackContext> tunnelStatusListeners = new ConcurrentHashMap<>();

  // Connection to the VPN service.
  // private final ServiceConnection vpnServiceConnection = new ServiceConnection() {
  //   @Override
  //   public void onServiceConnected(ComponentName className, IBinder binder) {
  //     // vpnTunnelService = IVpnTunnelService.Stub.asInterface(binder);
  //     LOG.info("VPN service connected");
  //   }

  //   @Override
  //   public void onServiceDisconnected(ComponentName className) {
  //     LOG.warning("VPN service disconnected");
  //     // Rebind the service so the VPN automatically reconnects if the service process crashed.
  //     Context context = getBaseContext();
  //     Intent rebind = new Intent(context, V2rayVPNService.class);
  //     // rebind.putExtra(VpnServiceStarter.AUTOSTART_EXTRA, true);
  //     // Send the error reporting API key so the potential crash is reported.
  //     rebind.putExtra("errorReportingApiKey", errorReportingApiKey);
  //     context.bindService(rebind, vpnServiceConnection, Context.BIND_AUTO_CREATE);
  //   }
  // };

  @Override
  protected void pluginInitialize() {
    V2rayController.init(getBaseContext(), 0, "Outline");

            v2rayBroadCastReceiver = new BroadcastReceiver() {
            @Override
            public void onReceive(Context context, Intent intent) {
                // connection_time.setText("connection time : " + Objects.requireNonNull(intent.getExtras()).getString("DURATION"));
                // System.out.println("connection time : " + Objects.requireNonNull(intent.getExtras()).getString("DURATION"));
                // connection_speed.setText("connection speed : " + intent.getExtras().getString("UPLOAD_SPEED") + " | " + intent.getExtras().getString("DOWNLOAD_SPEED"));
                // System.out.println("connection speed : " + intent.getExtras().getString("UPLOAD_SPEED") + " | " + intent.getExtras().getString("DOWNLOAD_SPEED"));
                // connection_traffic.setText("connection traffic : " + intent.getExtras().getString("UPLOAD_TRAFFIC") + " | " + intent.getExtras().getString("DOWNLOAD_TRAFFIC"));
                // System.out.println("connection traffic : " + intent.getExtras().getString("UPLOAD_TRAFFIC") + " | " + intent.getExtras().getString("DOWNLOAD_TRAFFIC"));
                switch (Objects.requireNonNull(intent.getExtras().getSerializable("STATE")).toString()) {
                    case "V2RAY_CONNECTED":
                        // connection.setText("CONNECTED");
                        // System.out.println("CONNECTED");
                        break;
                    case "V2RAY_DISCONNECTED":
                        // connection.setText("DISCONNECTED");
                        // System.out.println("DISCONNECTED");
                        break;
                    case "V2RAY_CONNECTING":
                        // connection.setText("CONNECTING");
                        // System.out.println("CONNECTING");
                        break;
                    default:
                        break;
                }
            }
        };
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            cordova.getActivity().registerReceiver(v2rayBroadCastReceiver, new IntentFilter("V2RAY_CONNECTION_INFO"), getBaseContext().RECEIVER_EXPORTED);
        } else {
            cordova.getActivity().registerReceiver(v2rayBroadCastReceiver, new IntentFilter("V2RAY_CONNECTION_INFO"));
        }
    // OutlineLogger.registerLogHandler(SentryErrorReporter.BREADCRUMB_LOG_HANDLER);
    // Context context = getBaseContext();
    // IntentFilter broadcastFilter = new IntentFilter();
    // broadcastFilter.addAction(VpnTunnelService.STATUS_BROADCAST_KEY);
    // broadcastFilter.addCategory(context.getPackageName());
    // context.registerReceiver(vpnTunnelBroadcastReceiver, broadcastFilter);

    // context.bindService(new Intent(context, VpnTunnelService.class), vpnServiceConnection,
    //     Context.BIND_AUTO_CREATE);
  }

  @Override
  public void onDestroy() {
    System.out.println("onDestroy");
    // Context context = getBaseContext();
    // context.unregisterReceiver(vpnTunnelBroadcastReceiver);
    // context.unbindService(vpnServiceConnection);
  }

  @Override
  public boolean execute(String action, JSONArray args, CallbackContext callbackContext)
      throws JSONException {
    if (!Action.hasValue(action)) {
      return false;
    }
    if (Action.QUIT.is(action)) {
      this.cordova.getActivity().finish();
      return true;
    }

    LOG.fine(String.format(Locale.ROOT, "Received action: %s", action));

    if (Action.ON_STATUS_CHANGE.is(action)) {
      // Store the callback so we can execute it asynchronously.
      // final String tunnelId = args.getString(0);
      // tunnelStatusListeners.put(tunnelId, callbackContext);
      return true;
    }

    if (Action.START.is(action)) {
      // Prepare the VPN before spawning a new thread. Fall through if it's already prepared.
      try {
        if (!prepareVpnService()) {
          // startVpnRequest = new StartVpnRequest(args, callbackContext);
          return true;
        }
      } catch (ActivityNotFoundException e) {
        callbackContext.error(1);
        return true;
      }
    }

    executeAsync(action, args, callbackContext);
    return true;
  }

  // Executes an action asynchronously through the Cordova thread pool.
  private void executeAsync(
      final String action, final JSONArray args, final CallbackContext callback) {
    cordova.getThreadPool().execute(() -> {
      try {
        // Tunnel instance actions: tunnel ID is always the first argument.
        if (Action.START.is(action)) {

          sharedPreferences = getBaseContext().getSharedPreferences("conf", getBaseContext().MODE_PRIVATE);
                                          // check application have permission to create tunnel
            if (V2rayController.IsPreparedForConnection(getBaseContext())) {
                // save config to shared preference
                // sharedPreferences.edit().putString("v2ray_config", getXrayConfig().toString()).apply();
                if (V2rayController.getConnectionState() == AppConfigs.V2RAY_STATES.V2RAY_DISCONNECTED) {
                    // in StartV2ray function we can set remark to show that on notification.
                    // StartV2ray function steel need json config of v2ray. Unfortunately, it does not accept URI or base64 type at the moment.
                    V2rayController.StartV2ray(getBaseContext(), "Default", getXrayConfig().toString(), null);
                    //getConnectedV2rayServerDelay function need a text view for now
                    // String connected_server_delay = "-";
                    // Activity activity = this.cordova.getActivity();
                    cordova.getActivity().runOnUiThread(() -> V2rayController.getConnectedV2rayServerDelay(cordova.getContext()));

                    // new Handler().postDelayed(() -> V2rayController.getConnectedV2rayServerDelay(getBaseContext()), 1000);
                } else {
                    V2rayController.StopV2ray(getBaseContext());
                }
            } else {
                // Prepare application permission (vpnService And POST_NOTIFICATION)
                prepareForConnection();
            }
          
          // final String tunnelId = args.getString(0);
          // final JSONObject config = args.getJSONObject(1);
          // int errorCode = startVpnTunnel(tunnelId, config);
          sendErrorCode(callback, 0);
        } else if (Action.STOP.is(action)) {
          // final String tunnelId = args.getString(0);
          // LOG.info(String.format(Locale.ROOT, "Stopping VPN tunnel %s", tunnelId));
          // ErrorCode errorCode = vpnTunnelService.stopTunnel(tunnelId);
          // sendErrorCode(callback, errorCode.value);
        } else if (Action.IS_RUNNING.is(action)) {
          // final String tunnelId = args.getString(0);
          // boolean isActive = isTunnelActive(tunnelId);
          // callback.sendPluginResult(new PluginResult(PluginResult.Status.OK, isActive));

          // Static actions
        } else if (Action.IS_REACHABLE.is(action)) {
          // boolean isReachable =
              // this.vpnTunnelService.isServerReachable(args.getString(0), args.getInt(1));
          // callback.sendPluginResult(new PluginResult(PluginResult.Status.OK, isReachable));
        } else if (Action.INIT_ERROR_REPORTING.is(action)) {
          // errorReportingApiKey = args.getString(0);
          // Treat failures to initialize error reporting as unexpected by propagating exceptions.
          SentryErrorReporter.init(getBaseContext(), errorReportingApiKey);
          // vpnTunnelService.initErrorReporting(errorReportingApiKey);
          callback.success();
        } else if (Action.REPORT_EVENTS.is(action)) {
          // final String uuid = args.getString(0);
          // SentryErrorReporter.send(uuid);
          callback.success();
        } else {
          throw new IllegalArgumentException(
              String.format(Locale.ROOT, "Unexpected action %s", action));
        }
      } catch (Exception e) {
        LOG.log(Level.SEVERE,
            String.format(Locale.ROOT, "Unexpected error while executing action: %s", action), e);
        callback.error(1);
      }
    });
  }

  private ActivityResultLauncher<Intent> activityResultLauncher;

  private void prepareForConnection() {
        // Initialize the ActivityResultLauncher if not already initialized
    if (activityResultLauncher == null) {
        activityResultLauncher = this.cordova.getActivity().registerForActivityResult(
            new ActivityResultContracts.StartActivityForResult(), result -> {
                if (result.getResultCode() == Activity.RESULT_OK) {
                    Toast.makeText(getBaseContext(), "Permission granted, please click again on the connection button", Toast.LENGTH_SHORT).show();
                } else {
                    Toast.makeText(getBaseContext(), "Permission not granted.", Toast.LENGTH_LONG).show();
                }
            }
        );
    }
        Intent vpnServicePrepareIntent = VpnService.prepare(getBaseContext());
        if (vpnServicePrepareIntent != null) {
            activityResultLauncher.launch(vpnServicePrepareIntent);
            return;
        }

        if (Build.VERSION.SDK_INT >= 33) {
            if (ContextCompat.checkSelfPermission(getBaseContext(), POST_NOTIFICATIONS) != PermissionChecker.PERMISSION_GRANTED) {
                ActivityCompat.requestPermissions(this.cordova.getActivity(), new String[]{POST_NOTIFICATIONS}, 101);
            }
        }
    }

    public static JsonObject getXrayConfig() {
    return createJsonConfig();
  }

  private static JsonObject createJsonConfig() {
    // Создание JSON объекта
        JsonObject jsonConfig = new JsonObject();

        // Добавление "log" объекта
        JsonObject log = new JsonObject();
        log.addProperty("loglevel", "debug");
        log.addProperty("dnsLog", true);
        jsonConfig.add("log", log);

        // Добавление "inbounds" массива
        JsonArray inbounds = new JsonArray();

        // Добавление "socksInbound" объекта в "inbounds"
        JsonObject socksInbound = new JsonObject();
        socksInbound.addProperty("port", 1080);
        socksInbound.addProperty("listen", "127.0.0.1");
        socksInbound.addProperty("protocol", "socks");

        // Добавление "settings" объекта в "socksInbound" с вложенными свойствами
        JsonObject socksSettings = new JsonObject();
        socksSettings.addProperty("udp", true);

        socksInbound.add("settings", socksSettings);

        inbounds.add(socksInbound);

        jsonConfig.add("inbounds", inbounds);

        // Добавление "outbounds" массива
        JsonArray outbounds = new JsonArray();

        // Добавление "vless" объекта в "outbounds"
        JsonObject vlessOutbound = new JsonObject();
        vlessOutbound.addProperty("protocol", "vless");

        // Добавление "settings" объекта в "vless" с вложенными свойствами
        JsonObject vlessSettings = new JsonObject();

        // Добавление "vnext" массива в "vlessSettings"
        JsonArray vnext = new JsonArray();
        JsonObject vnextServer = new JsonObject();
        vnextServer.addProperty("address", "135.181.44.107");
        vnextServer.addProperty("port", 10088);

        // Добавление "users" массива в "vnextServer"
        JsonArray users = new JsonArray();
        JsonObject user = new JsonObject();
        user.addProperty("encryption", "none");
        user.addProperty("id", "b831381d-6324-4d53-ad4f-8cda48b30822");
        users.add(user);

        vnextServer.add("users", users);
        vnext.add(vnextServer);

        vlessSettings.add("vnext", vnext);
        vlessOutbound.add("settings", vlessSettings);

        // Добавление "streamSettings" объекта в "vlessOutbound"
        JsonObject streamSettings = new JsonObject();
        streamSettings.addProperty("network", "tcp");
        streamSettings.addProperty("security", "tls");

        // Добавление "tlsSettings" объекта в "streamSettings" с вложенными свойствами
        JsonObject tlsSettings = new JsonObject();
        tlsSettings.addProperty("serverName", "test2.xray.vpn.paperpaper.io");
        tlsSettings.addProperty("allowInsecure", false);
        tlsSettings.addProperty("fingerprint", "chrome");

        // Добавление "alpn" массива в "tlsSettings"
        JsonArray alpn = new JsonArray();
        alpn.add("h2");
        alpn.add("http/1.1");
        tlsSettings.add("alpn", alpn);

        tlsSettings.addProperty("disableSessionResumption", true);

        JsonArray certificates = new JsonArray();
        JsonObject certificate = new JsonObject();

        certificate.addProperty("usage", "verify");

JsonArray certificateCode = new JsonArray();
        certificateCode.add("-----BEGIN CERTIFICATE-----");
        certificateCode.add("MIIEBzCCAu+gAwIBAgIUVRAlD8yPA/u+ZChsSjTOY5ozflQwDQYJKoZIhvcNAQEL");
        certificateCode.add("BQAwgZIxCzAJBgNVBAYTAlJTMRUwEwYDVQQIDAxHcmFkIEJlb2dyYWQxETAPBgNV");
        certificateCode.add("BAoMCFBhcGVyVlBOMREwDwYDVQQLDAhTZWN1cml0eTEdMBsGA1UEAwwUQWxleGFu");
        certificateCode.add("ZGVyIEtvdGVsbmlrb3YxJzAlBgkqhkiG9w0BCQEWGGtvdGVsbmlrb3ZAcGFwZXJw");
        certificateCode.add("YXBlci5pbzAeFw0yMzA5MjEwOTEyNTRaFw0yNjA5MjAwOTEyNTRaMIGSMQswCQYD");
        certificateCode.add("VQQGEwJSUzEVMBMGA1UECAwMR3JhZCBCZW9ncmFkMREwDwYDVQQKDAhQYXBlclZQ");
        certificateCode.add("TjERMA8GA1UECwwIU2VjdXJpdHkxHTAbBgNVBAMMFEFsZXhhbmRlciBLb3RlbG5p");
        certificateCode.add("a292MScwJQYJKoZIhvcNAQkBFhhrb3RlbG5pa292QHBhcGVycGFwZXIuaW8wggEi");
        certificateCode.add("MA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC3Foj0xsewQx6y+NCh1rQpkEGM");
        certificateCode.add("Y+sAouNd+/aXQt9ajZS65FTF50fceL1qrhPb0uH0uXaTGffAwL0TBJK7UasJKwrD");
        certificateCode.add("CnPEZJ/X50pm1r6edVSBrJvwvxSnhIaBRZU8GOJTamXneJFn3yOQkm0SQys6z8nn");
        certificateCode.add("Oc+S/4gQ8WJkmC9u3er/etQWqR3QKnyWjogVTg9oe2BGhEPjMk3uKgUY1fwNsIDV");
        certificateCode.add("fmY17ql2WrECLCT3TIrN6QV0dw+rqYNAZ/X+s4YIqTq3NGt4dj/48ZhbJR/PIRj2");
        certificateCode.add("ym2yKGd+LObKHC47pF9eT0dApeiJNVNirj+QGdBaWpt2llmYwlvfgpdI4zu/AgMB");
        certificateCode.add("AAGjUzBRMB0GA1UdDgQWBBT23BYJfz5+urI5KmWyc/T+OZTEPTAfBgNVHSMEGDAW");
        certificateCode.add("gBT23BYJfz5+urI5KmWyc/T+OZTEPTAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3");
        certificateCode.add("DQEBCwUAA4IBAQAiYGCWPg7oH6xTBTI6WPAQiOtTMIPJfG+N0ks5DyLWMQ3y8+aH");
        certificateCode.add("4gG27J8K03XOHej7RS3CrkU5RPCnbtqbZYiqkF2GkWuewpluQiUG8pZSDnkHspFT");
        certificateCode.add("2fkrRuF9rN7zTppT96e6hwQjCCi8iZZyePIfv3ZCKEDjUHFWwuDcJtVLNE3sgFT7");
        certificateCode.add("RMJWHGhV9utOeTb8oxQBdN7s8eym4pvqDTk2v8RWReLqWapIpBejpYFc6C6Dbvjf");
        certificateCode.add("jF+fZMVchhZJ+RRroHI10UsdiGZwLzeabjg5kfue+3l898e/f08bx9O5vj9PoaNH");
        certificateCode.add("0GBUl0VewvXr22q4snNfsn6DXxr1v1BBB8Yp");
        certificateCode.add("-----END CERTIFICATE-----");

        certificate.add("certificate", certificateCode);

        certificates.add(certificate);

        tlsSettings.add("certificates", certificates);

        streamSettings.add("tlsSettings", tlsSettings);

        vlessOutbound.add("streamSettings", streamSettings);

        outbounds.add(vlessOutbound);

        JsonObject freedomOutbound = new JsonObject();

        freedomOutbound.addProperty("protocol", "freedom");
        freedomOutbound.addProperty("tag", "direct");

        outbounds.add(freedomOutbound);

        jsonConfig.add("outbounds", outbounds);

        // Добавление "routing" объекта
        JsonObject routing = new JsonObject();
        routing.addProperty("domainStrategy", "IPIfNonMatch");

        JsonArray rules = new JsonArray();

        JsonObject rule = new JsonObject();
        rule.addProperty("type", "field");
        rule.addProperty("outboundTag", "direct");

        JsonArray ip = new JsonArray();
        ip.add("geoip:private");
        rule.add("ip", ip);

        rules.add(rule);

        routing.add("rules", rules);

        jsonConfig.add("routing", routing);

        // Преобразование объекта в JSON строку
        // String jsonString = jsonConfig.toString();

        return jsonConfig;
  }

  // Requests user permission to connect the VPN. Returns true if permission was previously granted,
  // and false if the OS prompt will be displayed.
  private boolean prepareVpnService() throws ActivityNotFoundException {
    LOG.fine("Preparing VPN.");
    Intent prepareVpnIntent = VpnService.prepare(getBaseContext());
    if (prepareVpnIntent == null) {
      return true;
    }
    LOG.info("Prepare VPN with activity");
    cordova.startActivityForResult(this, prepareVpnIntent, REQUEST_CODE_PREPARE_VPN);
    return false;
  }

  @Override
  public void onActivityResult(int request, int result, Intent data) {
    if (request != REQUEST_CODE_PREPARE_VPN) {
      LOG.warning("Received non-requested activity result.");
      return;
    }
    if (result != Activity.RESULT_OK) {
      LOG.warning("Failed to prepare VPN.");
      // sendErrorCode(startVpnRequest.callback, 2);
      return;
    }
    // executeAsync(Action.START.value, startVpnRequest.args, startVpnRequest.callback);
    // startVpnRequest = null;
  }

  // private int startVpnTunnel(final String tunnelId, final JSONObject config) throws Exception {
  //   LOG.info(String.format(Locale.ROOT, "Starting VPN tunnel %s", tunnelId));
  //   final TunnelConfig tunnelConfig;
  //   // try {
  //   //   tunnelConfig = VpnTunnelService.makeTunnelConfig(tunnelId, config);
  //   // } catch (Exception e) {
  //   //   LOG.log(Level.SEVERE, "Failed to retrieve the tunnel proxy config.", e);
  //   //   return ErrorCode.ILLEGAL_SERVER_CONFIGURATION.value;
  //   // }
  //   Context context = getBaseContext();
  //   return vpnTunnelService.startTunnel(tunnelConfig, context).value;
  // }

  // Returns whether the VPN service is running a particular tunnel instance.
  // private boolean isTunnelActive(final String tunnelId) {
  //   try {
  //     return vpnTunnelService.isTunnelActive(tunnelId);
  //   } catch (Exception e) {
  //     LOG.log(Level.SEVERE,
  //         String.format(Locale.ROOT, "Failed to determine if tunnel is active: %s", tunnelId), e);
  //   }
  //   return false;
  // }

  // Broadcasts

  private VpnTunnelBroadcastReceiver vpnTunnelBroadcastReceiver =
      new VpnTunnelBroadcastReceiver(OutlinePlugin.this);

  // Receiver to forward VPN service broadcasts to the WebView when the tunnel status changes.
  private static class VpnTunnelBroadcastReceiver extends BroadcastReceiver {
    private final OutlinePlugin outlinePlugin;

    public VpnTunnelBroadcastReceiver(OutlinePlugin outlinePlugin) {
      this.outlinePlugin = outlinePlugin;
    }

    @Override
    public void onReceive(Context context, Intent intent) {
      System.out.println("onReceive");
      // final String tunnelId = intent.getStringExtra("tunnelId");
      // if (tunnelId == null) {
      //   LOG.warning("Tunnel status broadcast missing tunnel ID");
      //   return;
      // }
      // CallbackContext callback = outlinePlugin.tunnelStatusListeners.get(tunnelId);
      // if (callback == null) {
      //   LOG.warning(String.format(
      //       Locale.ROOT, "Failed to retrieve status listener for tunnel ID %s", tunnelId));
      //   return;
      // }
      // int status = intent.getIntExtra("payload", -1);
      // LOG.fine(String.format(Locale.ROOT, "VPN connectivity changed: %s, %d", tunnelId, status));

      // PluginResult result = new PluginResult(PluginResult.Status.OK, status);
      // // Keep the tunnel status callback so it can be called multiple times.
      // result.setKeepCallback(true);
      // callback.sendPluginResult(result);
    }
  };

  // Helpers

  private Context getBaseContext() {
    return this.cordova.getActivity().getApplicationContext();
  }

  private void sendErrorCode(final CallbackContext callback, int errorCode) {
    if (errorCode == 0) {
      callback.success();
    } else {
      callback.error(errorCode);
    }
  }
}
