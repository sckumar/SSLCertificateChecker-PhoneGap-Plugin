package nl.xservices.plugins;

import android.util.Log;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.List;
import javax.net.ssl.X509TrustManager;

public final class HashTrust implements X509TrustManager {
  private static char[] HEX_CHARS = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'};
  private List<String> _expectedFingerprints;

  public HashTrust(List<String> fingerprints) {
    if (fingerprints == null || fingerprints.size() == 0) {
      throw new IllegalArgumentException("Excepted fingerprints list cannot be null");
    }
    for (int i = 0; i < fingerprints.size(); i++) {
      fingerprints.set(i, removeSpaces(fingerprints.get(i)));
    }
    this._expectedFingerprints = fingerprints;
  }

  @Override // javax.net.ssl.X509TrustManager
  public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
    if (chain == null) {
      throw new IllegalArgumentException("Cert chain cannot be null");
    } else if (chain.length <= 0) {
      throw new IllegalArgumentException("Cert chain cannot be empty");
    } else {
      boolean isValid = false;
      for (int iCert = 0; iCert < chain.length; iCert++) {
        X509Certificate serverCert = chain[iCert];
        try {
          MessageDigest md = MessageDigest.getInstance("SHA256");
          md.update(serverCert.getEncoded());
          String foundFingerprint = dumpHex(md.digest());
          int i = 0;
          while (true) {
            if (i >= this._expectedFingerprints.size()) {
              break;
            } else if (foundFingerprint.equalsIgnoreCase(this._expectedFingerprints.get(i))) {
              isValid = true;
              break;
            } else {
              i++;
            }
          }
          if (isValid) {
            break;
          }
        } catch (NoSuchAlgorithmException e) {
          throw new CertificateException("Missing SHA1 support! Killing the connection");
        } catch (CertificateEncodingException e2) {
          throw new CertificateException("Bad certificate encoding");
        }
      }
      if (!isValid) {
        throw new CertificateException("INVALID_CERT");
      }
    }
  }

  @Override // javax.net.ssl.X509TrustManager
  public void checkClientTrusted(X509Certificate[] chain, String authType) {
  }

  public X509Certificate[] getAcceptedIssuers() {
    return null;
  }

  private static String dumpHex(byte[] data) {
    int n = data.length;
    StringBuilder sb = new StringBuilder(n * 2);
    for (int i = 0; i < n; i++) {
      sb.append(HEX_CHARS[(data[i] >> 4) & 15]);
      sb.append(HEX_CHARS[data[i] & 15]);
    }
    return sb.toString();
  }

  private static String removeSpaces(String s) {
    return s.replace(" ", "");
  }
}
