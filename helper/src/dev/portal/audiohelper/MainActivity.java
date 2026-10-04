package dev.portal.audiohelper;

import android.app.Activity;
import android.os.Bundle;
import android.widget.TextView;

public final class MainActivity extends Activity {
    @Override protected void onCreate(Bundle state) {
        super.onCreate(state);
        TextView text = new TextView(this);
        text.setText("Portal audio watchdog is running.\nAEC and NS are held off.");
        text.setTextSize(22);
        text.setPadding(32, 32, 32, 32);
        setContentView(text);
        AudioKeeperService.start(this);
    }
}
