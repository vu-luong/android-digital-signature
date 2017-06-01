package vu.com.digitalsignature;

import android.content.Intent;
import android.net.Uri;
import android.os.Bundle;
import android.support.v7.app.AppCompatActivity;
import android.util.Log;
import android.view.View;
import android.widget.Toast;

import java.io.File;

/**
 * Created by AnhVu on 5/17/17.
 * This activity will be called when the signing process completed.
 */

public class DoneActivity extends AppCompatActivity {

    /**
     * uri of the signed pdf file
     */
    private Uri mSignedFileUri;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_sign_done);

        mSignedFileUri = Uri.fromFile(new File(getIntent().getStringExtra("uri")));

        /** perform `view signed pdf file` action */
        findViewById(R.id.button_view).setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                if (mSignedFileUri != null) {
                    Intent intent = new Intent(Intent.ACTION_VIEW);
                    intent.setData(mSignedFileUri);
                    startActivity(intent);
                } else {
                    Toast.makeText(getApplicationContext(), "No PDF File!", Toast.LENGTH_SHORT).show();
                    return;
                }
            }
        });

        /** perform `share signed pdf file` action */
        findViewById(R.id.button_share).setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                Intent shareIntent = new Intent(Intent.ACTION_SEND);
                shareIntent.setType("pdf/*");
                shareIntent.putExtra(Intent.EXTRA_STREAM, mSignedFileUri);
                startActivity(Intent.createChooser(shareIntent, "Share Document"));
            }
        });
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
    }
}
