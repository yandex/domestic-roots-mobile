package ru.domesticroots.webview;

import android.annotation.SuppressLint;
import android.content.Context;
import android.os.AsyncTask;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import com.appmattus.certificatetransparency.CTLogger;
import com.appmattus.certificatetransparency.CTTrustManagerBuilder;
import com.appmattus.certificatetransparency.VerificationResult;
import com.appmattus.certificatetransparency.cache.AndroidDiskCache;
import com.appmattus.certificatetransparency.cache.DiskCachePolicy;
import com.appmattus.certificatetransparency.loglist.LogListService;
import org.jetbrains.annotations.NotNull;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.X509TrustManager;
import java.io.IOException;
import java.net.URL;
import java.net.URLConnection;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Date;

class DownloadCertsAndCheckTask extends AsyncTask<Void, Void, Boolean> {
    @SuppressLint("StaticFieldLeak") // We are using only application context here
    @NonNull
    private final Context context;
    @NonNull
    private final String url;
    @NonNull
    private final byte[][] certificates;
    @NonNull
    private final CTLogDataSource ctLogDataSource;
    @NonNull
    private final CertificateCheckCache certificateCheckCache;
    @NonNull
    private final WebViewSslErrorHandler.Callback callback;
    @NonNull
    private final Logger logger;

    @SuppressWarnings("deprecation")
    DownloadCertsAndCheckTask(@NonNull Context context,
                              @NonNull String url,
                              @NonNull byte[][] certificates,
                              @NonNull CTLogDataSource ctLogDataSource,
                              @NonNull CertificateCheckCache certificateCheckCache,
                              @NonNull WebViewSslErrorHandler.Callback callback,
                              @NonNull Logger logger) {
        this.context = context.getApplicationContext();
        this.url = url;
        this.certificates = certificates;
        this.ctLogDataSource = ctLogDataSource;
        this.certificateCheckCache = certificateCheckCache;
        this.callback = callback;
        this.logger = logger;
    }

    @Override
    protected Boolean doInBackground(Void... voids) {
        Certificate[] chain = connectAndGetServerCertificates(url);
        if (chain == null || chain.length == 0) {
            return false;
        }
        X509Certificate[] x509Chain = Utils.getX509Chain(chain);
        if (x509Chain.length != chain.length) {
            logger.e(String.format("Illegal certificate transformation. " +
                    "Was %s, but found %s", chain.length, x509Chain.length));
            return false;
        }

        X509TrustManager trustManager = Utils.getTrustManagerWithCertificates(certificates, logger);
        if (trustManager == null) {
            logger.e("Empty TrustManager");
            return false;
        }

        CTTrustManagerBuilder ctTrustManagerBuilder = new CTTrustManagerBuilder(trustManager)
                .setFailOnError(true)
                .setLogger(new CTLoggerImpl(logger))
                .setLogListService(new LogListServiceAdapter(ctLogDataSource));

        if (ctLogDataSource.getCachePolicy() != null) {
            ctTrustManagerBuilder.setDiskCache(
                    new AndroidDiskCache(context, new LogCachePolicyAdapter(ctLogDataSource.getCachePolicy())));
        }
        
        trustManager = ctTrustManagerBuilder.build();

        try {
            trustManager.checkServerTrusted(x509Chain, "RSA");

            certificateCheckCache.addSuccessful(url);
            return true;
        } catch (CertificateException e) {
            logger.e("Failed to verify certificate chain", e);
            certificateCheckCache.addFailed(url);
        }

        return false;
    }

    @Override
    protected void onPostExecute(Boolean result) {
        if (result) {
            callback.onProceeded();
        } else {
            callback.onCanceled();
        }
    }

    @Nullable
    private Certificate[] connectAndGetServerCertificates(@NonNull String url) {
        HttpsURLConnection connection = openConnection(url);
        if (connection == null) {
            return null;
        }
        connection.setSSLSocketFactory(Utils.getTrustAllSocketFactory());
        try {
            connection.connect();
            return connection.getServerCertificates();
        } catch (IOException e) {
            logger.e("Failed to establish connection");
            return null;
        } finally {
            connection.disconnect();
        }
    }

    @Nullable
    private HttpsURLConnection openConnection(@NonNull String url) {
        URLConnection connection;
        try {
            connection = new URL(url).openConnection();
        } catch (IOException e) {
            logger.e("Failed to open connection", e);
            return null;
        }
        if (!(connection instanceof HttpsURLConnection)) {
            logger.e("Expected HTTPS connection, but found " + connection);
            return null;
        }
        return (HttpsURLConnection) connection;
    }

    private static class CTLoggerImpl implements CTLogger {
        @NonNull
        private final Logger logger;

        private CTLoggerImpl(@NonNull Logger logger) {
            this.logger = logger;
        }

        @Override
        public void log(@NonNull String host, @NonNull VerificationResult result) {
            logger.d(host + " " + result);
        }
    }

    private static class LogListServiceAdapter implements LogListService {
        @NonNull
        private final CTLogDataSource ctLogDataSource;

        private LogListServiceAdapter(@NonNull CTLogDataSource ctLogDataSource) {
            this.ctLogDataSource = ctLogDataSource;
        }

        @NotNull
        @Override
        public byte[] getLogList() {
            return ctLogDataSource.getRawLog();
        }

        @Nullable
        @Override
        public byte[] getLogListSignature() {
            return null;
        }
    }

    private static class LogCachePolicyAdapter implements DiskCachePolicy {
        @NonNull
        private final CTLogCachePolicy ctLogCachePolicy;

        private LogCachePolicyAdapter(@NonNull CTLogCachePolicy ctLogCachePolicy) {
            this.ctLogCachePolicy = ctLogCachePolicy;
        }

        @Override
        public boolean isExpired(@NotNull Date lastWriteDate, @NotNull Date currentDate) {
            return ctLogCachePolicy.isExpired(lastWriteDate, currentDate);
        }
    }

}
