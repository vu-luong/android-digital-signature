package vu.com.digitalsignature;

import android.annotation.TargetApi;
import android.os.AsyncTask;
import android.os.Build;
import android.os.Bundle;
import android.os.Environment;
import android.security.KeyChain;
import android.security.KeyChainAliasCallback;
import android.security.KeyChainException;
import android.security.keystore.KeyProperties;
import android.support.v7.app.AppCompatActivity;
import android.util.Log;

import com.itextpdf.text.DocumentException;
import com.itextpdf.text.Rectangle;
import com.itextpdf.text.pdf.PdfReader;
import com.itextpdf.text.pdf.PdfSignatureAppearance;
import com.itextpdf.text.pdf.PdfStamper;
import com.itextpdf.text.pdf.security.BouncyCastleDigest;
import com.itextpdf.text.pdf.security.DigestAlgorithms;
import com.itextpdf.text.pdf.security.ExternalDigest;
import com.itextpdf.text.pdf.security.ExternalSignature;
import com.itextpdf.text.pdf.security.MakeSignature;
import com.itextpdf.text.pdf.security.MakeSignature.CryptoStandard;
import com.itextpdf.text.pdf.security.PrivateKeySignature;

import org.spongycastle.jce.provider.BouncyCastleProvider;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.Security;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;


public class MainActivity extends AppCompatActivity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);



        KeyChain.choosePrivateKeyAlias(this,
                new KeyChainAliasCallback() {

                    public void alias(String alias) {
                        // Credential alias selected.  Remember the alias selection for future use.
                        if (alias != null) {
                            sign(alias);
                        }
                    }
                },
                null, // List of acceptable key types. null for any
                null,                        // issuer, null for any
                null,      // host name of server requesting the cert, null if unavailable
                -1,                         // port of server requesting the cert, -1 if unavailable
                null);                       // alias to preselect, null if unavailable

    }

    private void sign(final String alias) {
        new AsyncTask<Void, Void, Void>() {
            @TargetApi(Build.VERSION_CODES.JELLY_BEAN_MR2)
            @Override
            protected Void doInBackground(Void... params) {
//                RSAPrivateKey
                PrivateKey privateKey = null;
                try {

                    privateKey =  KeyChain.getPrivateKey(getApplicationContext(), alias);
                    Log.d("MAIN: ", privateKey.getClass().getName());


                    final Signature signature = Signature.getInstance("SHA256withRSA");
                    signature.initSign(privateKey);
                    Log.d("MAIN: ", privateKey.toString());

                    ExternalSignature pks = new ExternalSignature() {
                        @Override
                        public String getHashAlgorithm() {
                            return "SHA256";
                        }

                        @Override
                        public String getEncryptionAlgorithm() {
                            return "RSA";
                        }

                        @Override
                        public byte[] sign(byte[] bytes) throws GeneralSecurityException {
                            MessageDigest messageDigest = MessageDigest.getInstance(getHashAlgorithm());
                            byte hash[] = messageDigest.digest(bytes);

                            try {
                                signature.update(bytes);
                                return signature.sign();
                            } catch (Exception e) {
                                throw new GeneralSecurityException(e);
                            }
                        }
                    };

                    Certificate[] chain = KeyChain.getCertificateChain(getApplicationContext(), alias);

//                    X509Certificate[] chain = KeyChain.getCertificateChain(getApplicationContext(), alias);

                    BouncyCastleProvider provider = new BouncyCastleProvider();
                    Security.addProvider(provider);

                    File tmp = File.createTempFile("eid", ".pdf", getCacheDir());
                    File file = new File(Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS), "sign_test.pdf");
                    FileOutputStream fos = new FileOutputStream(file);

                    String src = Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS).toString() + "/nhom1.pdf";

//                    sign(src, fos, chain, privateKey, DigestAlgorithms.SHA256, provider.getName(), CryptoStandard.CMS, "Test 1", "Ghent");
//                    sign(src, fos, chain, privateKey, DigestAlgorithms.SHA512, provider.getName(), CryptoStandard.CMS, "Test 2", "Ghent");
                    sign(src, fos, chain, pks, DigestAlgorithms.SHA256, provider.getName(), CryptoStandard.CADES, "Test 3", "Ghent");
//                    sign(src, fos, chain, privateKey, DigestAlgorithms.RIPEMD160, provider.getName(), CryptoStandard.CADES, "Test 4", "Ghent");

//                    MakeSignature.signDetached();

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




    public void sign(String src, FileOutputStream os,
                     Certificate[] chain,
                     ExternalSignature pk, String digestAlgorithm, String provider,
                     CryptoStandard subfilter,
                     String reason, String location)
            throws GeneralSecurityException, IOException, DocumentException {
        // Creating the reader and the stamper
        PdfReader reader = new PdfReader(src);
//        FileOutputStream os = new FileOutputStream(dest);
        PdfStamper stamper = PdfStamper.createSignature(reader, os, '\0');
        // Creating the appearance
        PdfSignatureAppearance appearance = stamper.getSignatureAppearance();
        appearance.setReason(reason);
        appearance.setLocation(location);
        appearance.setVisibleSignature(new Rectangle(36, 748, 144, 780), 1, "sig");
//        appearance.setImage(Image.getInstance(IMG));
        appearance.setImageScale(-1);
        // Creating the signature
        ExternalDigest digest = new BouncyCastleDigest();
//        ExternalSignature signature = new PrivateKeySignature(pk, digestAlgorithm, provider);
        MakeSignature.signDetached(appearance, digest, pk, chain, null, null, null, 0, subfilter);
    }
}
