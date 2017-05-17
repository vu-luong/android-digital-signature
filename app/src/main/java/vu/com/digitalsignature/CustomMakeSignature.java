package vu.com.digitalsignature;

import com.itextpdf.text.DocumentException;
import com.itextpdf.text.pdf.PdfDate;
import com.itextpdf.text.pdf.PdfDeveloperExtension;
import com.itextpdf.text.pdf.PdfDictionary;
import com.itextpdf.text.pdf.PdfName;
import com.itextpdf.text.pdf.PdfSignature;
import com.itextpdf.text.pdf.PdfSignatureAppearance;
import com.itextpdf.text.pdf.PdfString;
import com.itextpdf.text.pdf.security.CrlClient;
import com.itextpdf.text.pdf.security.DigestAlgorithms;
import com.itextpdf.text.pdf.security.ExternalDigest;
import com.itextpdf.text.pdf.security.ExternalSignature;
import com.itextpdf.text.pdf.security.MakeSignature;
import com.itextpdf.text.pdf.security.OcspClient;
import com.itextpdf.text.pdf.security.PdfPKCS7;
import com.itextpdf.text.pdf.security.TSAClient;

import org.spongycastle.asn1.esf.SignaturePolicyIdentifier;

import java.io.IOException;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.HashMap;
import java.util.Iterator;

/**
 * Created by AnhVu on 5/10/17.
 */

public class CustomMakeSignature extends MakeSignature {

    public static void signDetached(PdfSignatureAppearance sap, ExternalDigest externalDigest, ExternalSignature externalSignature, Certificate[] chain, Collection<CrlClient> crlList, OcspClient ocspClient, TSAClient tsaClient, int estimatedSize, MakeSignature.CryptoStandard sigtype) throws IOException, DocumentException, GeneralSecurityException {
        signDetached(sap, externalDigest, externalSignature, chain, crlList, ocspClient, tsaClient, estimatedSize, sigtype, (SignaturePolicyIdentifier)null);
    }

    public static void signDetached(PdfSignatureAppearance sap, ExternalDigest externalDigest, ExternalSignature externalSignature, Certificate[] chain, Collection<CrlClient> crlList, OcspClient ocspClient, TSAClient tsaClient, int estimatedSize, MakeSignature.CryptoStandard sigtype, SignaturePolicyIdentifier signaturePolicy) throws IOException, DocumentException, GeneralSecurityException {
        Collection crlBytes = null;

        for(int i = 0; crlBytes == null && i < chain.length; crlBytes = processCrl(chain[i++], crlList)) {
            ;
        }

        if(estimatedSize == 0) {
            estimatedSize = 8192;
            byte[] exc;
            if(crlBytes != null) {
                for(Iterator dic = crlBytes.iterator(); dic.hasNext(); estimatedSize += exc.length + 10) {
                    exc = (byte[])dic.next();
                }
            }

            if(ocspClient != null) {
                estimatedSize += 4192;
            }

            if(tsaClient != null) {
                estimatedSize += 4192;
            }
        }

        sap.setCertificate(chain[0]);
        if(sigtype == MakeSignature.CryptoStandard.CADES) {
            sap.addDeveloperExtension(PdfDeveloperExtension.ESIC_1_7_EXTENSIONLEVEL2);
        }

        PdfSignature var24 = new PdfSignature(PdfName.ADOBE_PPKLITE, sigtype == MakeSignature.CryptoStandard.CADES?PdfName.ETSI_CADES_DETACHED:PdfName.ADBE_PKCS7_DETACHED);
        var24.setReason(sap.getReason());
        var24.setLocation(sap.getLocation());
        var24.setSignatureCreator(sap.getSignatureCreator());
        var24.setContact(sap.getContact());
        var24.setDate(new PdfDate(sap.getSignDate()));
        sap.setCryptoDictionary(var24);
        HashMap var25 = new HashMap();
        var25.put(PdfName.CONTENTS, new Integer(estimatedSize * 2 + 2));
        sap.preClose(var25);
        String hashAlgorithm = externalSignature.getHashAlgorithm();
        PdfPKCS7 sgn = new PdfPKCS7((PrivateKey)null, chain, hashAlgorithm, (String)null, externalDigest, false);
        if(signaturePolicy != null) {
            sgn.setSignaturePolicy(signaturePolicy);
        }

        InputStream data = sap.getRangeStream();
        byte[] hash = DigestAlgorithms.digest(data, externalDigest.getMessageDigest(hashAlgorithm));
        byte[] ocsp = null;
        if(chain.length >= 2 && ocspClient != null) {
            ocsp = ocspClient.getEncoded((X509Certificate)chain[0], (X509Certificate)chain[1], (String)null);
        }

        byte[] sh = sgn.getAuthenticatedAttributeBytes(hash, ocsp, crlBytes, sigtype);
        byte[] extSignature = externalSignature.sign(sh);
        sgn.setExternalDigest(extSignature, (byte[])null, externalSignature.getEncryptionAlgorithm());
        byte[] encodedSig = sgn.getEncodedPKCS7(hash, tsaClient, ocsp, crlBytes, sigtype);
        if(estimatedSize < encodedSig.length) {
            throw new IOException("Not enough space");
        } else {
            byte[] paddedSig = new byte[estimatedSize];
            System.arraycopy(encodedSig, 0, paddedSig, 0, encodedSig.length);
            PdfDictionary dic2 = new PdfDictionary();
            dic2.put(PdfName.CONTENTS, (new PdfString(paddedSig)).setHexWriting(true));
            sap.close(dic2);
        }
    }
}
