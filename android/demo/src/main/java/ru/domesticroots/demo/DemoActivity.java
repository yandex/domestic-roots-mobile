package ru.domesticroots.demo;

import android.net.http.SslError;
import android.os.Bundle;
import android.view.KeyEvent;
import android.view.inputmethod.EditorInfo;
import android.webkit.SslErrorHandler;
import android.webkit.WebView;
import android.webkit.WebViewClient;
import androidx.annotation.Nullable;
import androidx.appcompat.app.AppCompatActivity;
import ru.domesticroots.demo.databinding.ActivityDemoBinding;
import ru.domesticroots.nuc.NucCTLogNetworkSource;
import ru.domesticroots.nuc.NucCertificateProvider;
import ru.domesticroots.webview.Logger;
import ru.domesticroots.webview.WebViewSslErrorHandler;

public class DemoActivity extends AppCompatActivity {

    private ActivityDemoBinding binding;

    @Override
    protected void onCreate(@Nullable Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        binding = ActivityDemoBinding.inflate(getLayoutInflater());
        setContentView(binding.getRoot());

        loadUrlFromEditText();

        binding.editUrl.setOnEditorActionListener((v, actionId, event) -> {
            if (actionId == EditorInfo.IME_ACTION_GO || event.getKeyCode() == KeyEvent.KEYCODE_ENTER) {
                loadUrlFromEditText();
                binding.editUrl.clearFocus();
                return true;
            } else {
                return false;
            }
        });

        binding.buttonGo.setOnClickListener(v -> {
            loadUrlFromEditText();
        });

        WebViewSslErrorHandler sslErrorHandler = WebViewSslErrorHandler.create(
                getApplicationContext(),
                new NucCertificateProvider(this),
                new NucCTLogNetworkSource(),
                Logger.ANDROID_LOG
        );;
        binding.webView.setWebViewClient(new WebViewClient() {
            @Override
            public void onReceivedSslError(WebView view, SslErrorHandler handler, SslError error) {
                if (!sslErrorHandler.handleSslError(error, new WebViewSslErrorHandler.Callback() {
                    @Override
                    public void onProceeded() {
                        handler.proceed();
                    }

                    @Override
                    public void onCanceled() {
                        handler.cancel();
                    }
                })) {
                    handler.cancel();
                }
            }
        });
        binding.webView.getSettings().setDomStorageEnabled(true);
        binding.webView.getSettings().setJavaScriptEnabled(true);
    }

    private void loadUrlFromEditText() {
        binding.webView.loadUrl(binding.editUrl.getText().toString());
    }

}
