package ru.domesticroots.webview;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.annotation.WorkerThread;

public interface CTLogDataSource {

    @NonNull
    @WorkerThread
    byte[] getRawLog();

    @Nullable
    @WorkerThread
    CTLogCachePolicy getCachePolicy();
}
