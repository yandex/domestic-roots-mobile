package ru.domesticroots.webview;

import androidx.annotation.NonNull;
import com.appmattus.certificatetransparency.loglist.LogListDataSourceFactory;
import com.appmattus.certificatetransparency.loglist.LogListService;
import com.appmattus.certificatetransparency.loglist.LogListUrlProvider;
import org.jetbrains.annotations.Nullable;

public class CTLogNetworkSource implements CTLogDataSource {
    private final String url;

    public CTLogNetworkSource(String url) {
        this.url = url;
    }

    @NonNull
    @Override
    public byte[] getRawLog() {
        LogListService logListService = LogListDataSourceFactory.createLogListService(new UrlProvider(url));
        return logListService.getLogList();
    }

    @Nullable
    @Override
    public CTLogCachePolicy getCachePolicy() {
        return new DefaultCTLogCachePolicy();
    }

    private static class UrlProvider implements LogListUrlProvider {
        private final String url;

        private UrlProvider(String url) {
            this.url = url;
        }

        @Override
        public String getLogListUrl() {
            return url;
        }

        @Nullable
        @Override
        public String getLogListSignatureUrl() {
            return null;
        }
    }
}
