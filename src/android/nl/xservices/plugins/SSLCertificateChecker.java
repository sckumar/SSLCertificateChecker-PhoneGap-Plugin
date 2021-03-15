package nl.xservices.plugins;

import org.apache.cordova.CallbackContext;
import org.apache.cordova.CordovaPlugin;
import org.json.JSONArray;
import org.json.JSONException;

import javax.net.ssl.HttpsURLConnection;
import java.io.IOException;
import java.net.URL;
import java.net.MalformedURLException;
import java.net.SocketTimeoutException;
import java.util.LinkedList;
import java.util.List;
import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.TrustManager;

public class SSLCertificateChecker extends CordovaPlugin {

  private static final String ACTION_CHECK_EVENT = "check";
  private static char[] HEX_CHARS = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'};

  @Override
  public boolean execute(final String action, final JSONArray args, final CallbackContext callbackContext) throws JSONException {
    if (ACTION_CHECK_EVENT.equals(action)) {
      cordova.getThreadPool().execute(new Runnable() {
        public void run() {
          try {
            List<String> fingerprints = new LinkedList<>();
            String getUrlStr = args.getString(0);
            JSONArray fingerprintsJson = args.getJSONArray(2);
            for (int i = 0; i < fingerprintsJson.length(); i++) {
              fingerprints.add(fingerprintsJson.getString(i));
            }
            try {
              URL getUrl = new URL(getUrlStr);
              getUrl.getHost();
              try {
                HttpsURLConnection conn = (HttpsURLConnection) getUrl.openConnection();
                try {
                  conn.setUseCaches(false);
                  TrustManager[] tm = {new HashTrust(fingerprints)};
                  SSLContext connContext = SSLContext.getInstance("TLS");
                  connContext.init(null, tm, null);
                  conn.setSSLSocketFactory(connContext.getSocketFactory());
                  conn.setHostnameVerifier(new HostnameVerifier() {
                    public boolean verify(String connectedHostname, SSLSession sslSession) {
                      return true;
                    }
                  });
                  try {
                    conn.setConnectTimeout(5000);
                    conn.connect();
                    callbackContext.success("CONNECTION_SECURE");
                  } catch (SocketTimeoutException e3) {
                    callbackContext.error("TIMEOUT");
                  } catch (IOException e4) {
                    if (e4.getMessage().indexOf("INVALID_CERT") > -1) {
                      callbackContext.error("CONNECTION_NOT_SECURE");
                    } else {
                      callbackContext.error("CANT_CONNECT");
                    }
                  }
                } catch (Exception e5) {
                  callbackContext.error("CANT_CONNECT");
                }
              } catch (IOException e6) {
                callbackContext.error("CANT_CONNECT");
              }
            } catch (MalformedURLException e7) {
              callbackContext.error("INVALID_URL");
            }
          } catch (JSONException e8) {
            callbackContext.error("INVALID_PARAMS");
          }
        }
      });
      return true;
    } else {
      callbackContext.error("sslCertificateChecker." + action + " is not a supported function. Did you mean '" + ACTION_CHECK_EVENT + "'?");
      return false;
    }
  }
}
