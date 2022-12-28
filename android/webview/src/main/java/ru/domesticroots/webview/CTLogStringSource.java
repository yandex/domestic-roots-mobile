package ru.domesticroots.webview;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import java.nio.charset.Charset;

public class CTLogStringSource implements CTLogDataSource {
    private final String logString;

    public CTLogStringSource(String logString) {
        this.logString = logString;
    }

    @NonNull
    @Override
    public byte[] getRawLog() {
        return logString.getBytes(Charset.defaultCharset());
    }

    @Nullable
    @Override
    public CTLogCachePolicy getCachePolicy() {
        return null;
    }
}
