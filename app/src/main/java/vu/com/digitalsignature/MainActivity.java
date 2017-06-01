package vu.com.digitalsignature;

import android.annotation.TargetApi;
import android.app.Activity;
import android.app.ProgressDialog;
import android.content.Intent;
import android.database.Cursor;
import android.graphics.Bitmap;
import android.net.Uri;
import android.os.AsyncTask;
import android.os.Build;
import android.os.Bundle;
import android.os.Environment;
import android.os.Handler;
import android.os.Looper;
import android.provider.OpenableColumns;
import android.security.KeyChain;
import android.security.KeyChainAliasCallback;
import android.security.KeyChainException;
import android.support.v7.app.AppCompatActivity;
import android.util.Log;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.ImageView;
import android.widget.TextView;
import android.widget.Toast;

import com.itextpdf.text.DocumentException;
import com.itextpdf.text.Image;
import com.itextpdf.text.Rectangle;
import com.itextpdf.text.pdf.PdfReader;
import com.itextpdf.text.pdf.PdfSignatureAppearance;
import com.itextpdf.text.pdf.PdfStamper;
import com.itextpdf.text.pdf.security.BouncyCastleDigest;
import com.itextpdf.text.pdf.security.DigestAlgorithms;
import com.itextpdf.text.pdf.security.ExternalDigest;
import com.itextpdf.text.pdf.security.ExternalSignature;
import com.itextpdf.text.pdf.security.MakeSignature.CryptoStandard;
import com.simplify.ink.InkView;

import org.spongycastle.jce.provider.BouncyCastleProvider;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.Certificate;


public class MainActivity extends AppCompatActivity {

    private static final int OPEN_REQUEST_CODE = 123;

    /** Panel for physic signature. */
    private InkView ink;

    /** TextView that display file name. */
    private TextView mFileNameTextView;

    /** Uri returned after browsing file PDF*/
    private Uri mFileUri;

    /**  Button to view PDF file */
    private ImageView mViewPDFImageView;

    /**  Reason of signature */
    private EditText mReasonEditText;

    /** Location of sigature */
    private EditText mLocationEditText;

    /** progress dialog that pop up while signing */
    private ProgressDialog mProgressDialog;

    /** Button to sign PDF file */
    private Button mSignButton;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        initView();


        final Activity a = this;

        /** Button to clean ink panel */
        findViewById(R.id.iv_clean).setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                ink.clear();
            }
        });

        /** perform `view pdf` action */
        mViewPDFImageView.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                if (mFileUri != null) {
                    Intent intent = new Intent(Intent.ACTION_VIEW);
                    intent.setData(mFileUri);
                    startActivity(intent);
                } else {
                    Toast.makeText(getApplicationContext(), "No PDF File!", Toast.LENGTH_SHORT).show();
                    return;
                }
            }
        });


        /** perform `browse file` action */
        findViewById(R.id.iv_browse_file).setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                Intent intent = new Intent(Intent.ACTION_GET_CONTENT);
                intent.setType("application/pdf");
                intent.addCategory(Intent.CATEGORY_OPENABLE);
                startActivityForResult(intent, OPEN_REQUEST_CODE);
            }
        });

        /** perform `sign pdf` action */
        mSignButton.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                if (mFileUri == null) {
                    Toast.makeText(getApplicationContext(), "Please choose a pdf file!", Toast.LENGTH_SHORT).show();
                    return;
                }
                saveImage();
                KeyChain.choosePrivateKeyAlias(a,
                        new KeyChainAliasCallback() {
                            public void alias(String alias) {
                                // Credential alias selected.  Remember the alias selection for future use.
                                if (alias != null) {
                                    Handler h = new Handler(Looper.getMainLooper());
                                    h.post(new Runnable() {
                                        public void run() {
                                            showProgressDialog();
                                        }
                                    });
                                    sign(alias, mReasonEditText.getText().toString(), mLocationEditText.getText().toString());
                                }
                            }
                        }, null, null, null, -1, null);
            }
        });
    }

    private void initView() {
        ink = (InkView) findViewById(R.id.ink);
        mSignButton = (Button) findViewById(R.id.button_sign);
        mFileNameTextView = (TextView) findViewById(R.id.tv_file_name);
        mViewPDFImageView = (ImageView) findViewById(R.id.iv_view);
        mReasonEditText = (EditText) findViewById(R.id.et_reason);
        mLocationEditText = (EditText) findViewById(R.id.et_location);
        mProgressDialog = new ProgressDialog(this);
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        switch (requestCode) {
            case OPEN_REQUEST_CODE:
                if (resultCode == Activity.RESULT_OK) {
                    mFileUri = data.getData();

                    mFileNameTextView.setText(getFileName(mFileUri));
                } else {
                    Toast.makeText(this, "File action canceled", Toast.LENGTH_SHORT).show();
                }
                break;
            default:
                super.onActivityResult(requestCode, resultCode, data);
                break;
        }
    }

    /**
     * Get actual file name from uri
     * @param uri
     * @return actual file name
     */
    public String getFileName(Uri uri) {
        String result = null;
        if (uri.getScheme().equals("content")) {
            Cursor cursor = getContentResolver().query(uri, null, null, null, null);
            try {
                if (cursor != null && cursor.moveToFirst()) {
                    result = cursor.getString(cursor.getColumnIndex(OpenableColumns.DISPLAY_NAME));
                }
            } finally {
                cursor.close();
            }
        }
        if (result == null) {
            result = uri.getPath();
            int cut = result.lastIndexOf('/');
            if (cut != -1) {
                result = result.substring(cut + 1);
            }
        }
        return result;
    }

    /**
     * save ink signature to internal storage
     */
    private void saveImage() {
        FileOutputStream out = null;
        try {
            out = new FileOutputStream(Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS) + "/image.png");
            ink.getBitmap().compress(Bitmap.CompressFormat.PNG, 100, out); // bmp is your Bitmap instance
            // PNG is a lossless format, the compression factor (100) is ignored
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            try {
                if (out != null) {
                    out.close();
                }
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }

    /**
     * Sign PDF.
     * @param alias to get privateKey
     * @param reason
     * @param location
     */
    private void sign(final String alias, final String reason, final String location) {

        new AsyncTask<Void, Void, Void>() {
            @Override
            protected void onPostExecute(Void aVoid) {
                super.onPostExecute(aVoid);
                mProgressDialog.dismiss();
                Intent i = new Intent(getApplicationContext(), DoneActivity.class);

                String f = Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS) + "/sign_" + getFileName(mFileUri);

                i.putExtra("uri", f);
                startActivity(i);
//                Log.d("MAIN: ", "XONOAXNOANSOFIAOSIDJ");
            }

            @TargetApi(Build.VERSION_CODES.M)
            @Override
            protected Void doInBackground(Void... params) {
                PrivateKey privateKey = null;
                try {

                    privateKey = KeyChain.getPrivateKey(getApplicationContext(), alias);


                    KeyFactory keyFactory =
                            KeyFactory.getInstance(privateKey.getAlgorithm(), "AndroidKeyStore");


                    Certificate[] chain = KeyChain.getCertificateChain(getApplicationContext(), alias);

                    BouncyCastleProvider provider = new BouncyCastleProvider();
                    Security.addProvider(provider);

                    ExternalSignature pks = new CustomPrivateKeySignature(privateKey, DigestAlgorithms.SHA256, provider.getName());

                    File tmp = File.createTempFile("eid", ".pdf", getCacheDir());
                    File file = new File(Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS), "sign_" + getFileName(mFileUri));
                    FileOutputStream fos = new FileOutputStream(file);

                    sign(mFileUri, fos, chain, pks, DigestAlgorithms.SHA256, provider.getName(), CryptoStandard.CADES, reason, location);

                } catch (KeyChainException e) {
                    e.printStackTrace();
                } catch (InterruptedException e) {
                    e.printStackTrace();
                } catch (FileNotFoundException e) {
                    e.printStackTrace();
                } catch (IOException e) {
                    e.printStackTrace();
                } catch (GeneralSecurityException e) {
                    e.printStackTrace();
                } catch (DocumentException e) {
                    e.printStackTrace();
                }

                return null;
            }
        }.execute();
    }


    public void sign(Uri uri, FileOutputStream os,
                     Certificate[] chain,
                     ExternalSignature pk, String digestAlgorithm, String provider,
                     CryptoStandard subfilter,
                     String reason, String location)
            throws GeneralSecurityException, IOException, DocumentException {
        // Creating the reader and the stamper
        PdfReader reader = new PdfReader(getContentResolver().openInputStream(uri));
        PdfStamper stamper = PdfStamper.createSignature(reader, os, '\0');
        // Creating the appearance
        PdfSignatureAppearance appearance = stamper.getSignatureAppearance();
        appearance.setReason(reason);
        appearance.setLocation(location);
        appearance.setVisibleSignature(new Rectangle(36, 748, 144, 780), 1, "sig");
        appearance.setImage(Image.getInstance(Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS) + "/image.png"));

        appearance.setImageScale(-1);
        // Creating the signature
        ExternalDigest digest = new BouncyCastleDigest();
        CustomMakeSignature.signDetached(appearance, digest, pk, chain, null, null, null, 0, subfilter);
    }

    private void showProgressDialog() {
        mProgressDialog.setIndeterminate(true);
        mProgressDialog.setTitle("Đang ký văn bản");
        mProgressDialog.setCancelable(false);
        mProgressDialog.setMessage("Vui lòng đợi trong giây lát");
        mProgressDialog.show();
    }
}
