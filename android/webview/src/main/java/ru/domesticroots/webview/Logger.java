package ru.domesticroots.webview;

import android.util.Log;
import androidx.annotation.NonNull;

public interface Logger {

    void d(@NonNull String message);

    void e(@NonNull String message);

    void e(@NonNull String message, @NonNull Throwable throwable);

    Logger EMPTY = new Logger() {
        @Override
        public void d(@NonNull String message) {}

        @Override
        public void e(@NonNull String message) {}

        @Override
        public void e(@NonNull String message, @NonNull Throwable throwable) {}
    };

    Logger ANDROID_LOG = new Logger() {
        private static final String TAG = "DomesticRoots";

        @Override
        public void d(@NonNull String message) {
            Log.d(TAG, message);
        }

        @Override
        public void e(@NonNull String message) {
            Log.e(TAG, message);
        }

        @Override
        public void e(@NonNull String message, @NonNull Throwable throwable) {
            Log.e(TAG, message, throwable);
        }
    };
}
