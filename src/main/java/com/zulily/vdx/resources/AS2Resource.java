package com.zulily.vdx.resources;

import com.zulily.vdx.dao.PrivateKeyDAO;
import com.zulily.vdx.dao.PublicKeyDAO;
import com.zulily.vdx.model.PrivateKeyModel;
import com.zulily.vdx.model.PublicKeyModel;
import io.dropwizard.hibernate.UnitOfWork;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.KeyTransRecipientInformation;
import org.bouncycastle.cms.RecipientInformation;
import org.bouncycastle.cms.RecipientInformationStore;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.cms.SignerInformationVerifier;
import org.bouncycastle.cms.bc.BcRSAKeyTransEnvelopedRecipient;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.cms.jcajce.ZlibExpanderProvider;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.mail.smime.SMIMECompressed;
import org.bouncycastle.mail.smime.SMIMEEnveloped;
import org.bouncycastle.mail.smime.SMIMEException;
import org.bouncycastle.mail.smime.SMIMESigned;
import org.bouncycastle.mail.smime.SMIMESignedParser;
import org.bouncycastle.mail.smime.SMIMEUtil;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.activation.DataHandler;
import javax.activation.DataSource;
import javax.mail.MessagingException;
import javax.mail.internet.MimeBodyPart;
import javax.mail.internet.MimeMultipart;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.WebApplicationException;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.Response;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.StringReader;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Collection;
import java.util.List;

/**
 * Created by ssun on 12/30/16.
 * This is trying to simplify OpenAS2 which has too many unnecessary OOP stuff.
 * This is more service oriented and will use database instead of file system.
 */
@Path("/")
public class AS2Resource {
    private static Logger log = LoggerFactory.getLogger(AS2Resource.class);
    private PrivateKeyDAO privateKeyDAO;
    private PublicKeyDAO publicKeyDAO;

    public AS2Resource(final PrivateKeyDAO privateKeyDAO, final PublicKeyDAO publicKeyDAO) {
        this.privateKeyDAO = privateKeyDAO;
        this.publicKeyDAO = publicKeyDAO;
    }

    @POST
    @UnitOfWork
    public Response postAS2(@Context HttpHeaders headers, byte[] postedBytes){
        MultivaluedMap<String, String> headersMap = headers.getRequestHeaders();
        if (headersMap == null) {
            String errorMessage = "We got no headers at all. Something is very wrong.";
            log.error(errorMessage);
            throw new WebApplicationException(errorMessage, 400);
        }
        log.info("There are {} headers in this request.", headersMap.size());
        //for(String key : headersMap.keySet()) {
        //    log.info("Key: {} Value: {}", key, headersMap.get(key));
        //}

        List<String> contentTypes = headersMap.get("Content-Type");
        if (contentTypes==null || contentTypes.size() == 0) {
            String errorMessage = "No Content-Type in headers. Something is very wrong.";
            log.error(errorMessage);
            throw new WebApplicationException(errorMessage, 400);
        }
        if (contentTypes.size() > 1) {
            String errorMessage = String.format("We have %d entries in header for Content-Type. We do not know which one to use.", contentTypes.size());
            log.error(errorMessage);
            throw new WebApplicationException(errorMessage, 400);
        }

        String contentTypeStr = contentTypes.get(0);
        log.info("From the header, we have Content-Type: {}", contentTypeStr);
        if (!contentTypeStr.contains("application/pkcs7-mime")) {
            String errorMessage = "Did not find application/pkcs7-mime in content type. Message does not seems to be encrypted. We do not support non-encrypted messages.";
            log.error(errorMessage);
            throw new WebApplicationException(errorMessage, 400);
        }
        if (!contentTypeStr.contains("smime-type=enveloped-data")) {
            String errorMessage = "Did not find smime-type=enveloped-data in content type. Message does not seems to be encrypted. We do not support non-encrypted messages.";
            log.error(errorMessage);
            throw new WebApplicationException(errorMessage, 400);
        }
        log.info("Message is encrypted according to Content-Type on the header.");

        List<String> as2Tos = headersMap.get("AS2-To");
        if (as2Tos == null || as2Tos.size() == 0) {
            String errorMessage = "No AS2-To in headers. Can't decide which private key to load for decryption.";
            log.error(errorMessage);
            throw new WebApplicationException(errorMessage, 400);
        }
        if (as2Tos.size() > 1) {
            String errorMessage = String.format("We have %d entries in header for Content-Type. We do not know which one to use.", as2Tos.size());
            log.error(errorMessage);
            throw new WebApplicationException(errorMessage, 400);
        }

        String as2To = as2Tos.get(0);
        log.info("Message sent to {} according to the header. Loading the corresponding private key to decrypt.", as2To);

        List<PrivateKeyModel> privateKeyModels = this.privateKeyDAO.findAS2Id(as2To);
        if (privateKeyModels == null || privateKeyModels.size()==0) {
            String errorMessage = String.format("Failed to find private key from database for as2Id: %s . Is the party setup properly?", as2To);
            log.error(errorMessage);
            throw new WebApplicationException(errorMessage, 400);
        }
        if (privateKeyModels.size() > 1) {
            // TODO: Support it
            String errorMessage = String.format("Found %d private key from database for as2Id: %s . We do not support multiple private key right now. We may in the future.", privateKeyModels.size(), as2To);
            log.error(errorMessage);
            throw new WebApplicationException(errorMessage, 400);
        }
        PrivateKeyModel privateKeyModel = privateKeyModels.get(0);
        String privateKeyStr = privateKeyModel.privateKey;
        log.info("Got 1 and only 1 private key from db.");
        //log.info(privateKeyStr);

        // http://stackoverflow.com/questions/11410770/load-rsa-public-key-from-file
        StringReader privateKeyReader = new StringReader(privateKeyStr);
        log.info("Created a StringReader for the private key.");
        PemReader pemReader = new PemReader(privateKeyReader);
        log.info("Created PemReader using the StringReader.");
        PemObject pemObject;
        try {
            log.info("Reading PemObject using PemReader.");
            pemObject = pemReader.readPemObject();
            log.info("Read successful.");
        } catch (IOException e) {
            String errorMessage = "Encountered IOException when try to read PemObject using PemReader.";
            log.error(errorMessage, e);
            throw new WebApplicationException(errorMessage, 500);
        }

        byte[] content = pemObject.getContent();
        log.info("Got the byte content for PemObject.");
        PKCS8EncodedKeySpec privKeySpec = new PKCS8EncodedKeySpec(content);
        log.info("Created PKCS8EncodedKeySpec using the byte content.");

        KeyFactory factory;
        try {
            log.info("Creating RSA KeyFactory using BC as provider.");
            factory = KeyFactory.getInstance("RSA", "BC");
            log.info("Created KeyFactory.");
        } catch (NoSuchAlgorithmException e) {
            String errorMessage = "Encountered NoSuchAlgorithmException when try to create an empty RSA KeyFactory using BC as provider.";
            log.error(errorMessage, e);
            throw new WebApplicationException(errorMessage, 500);
        } catch (NoSuchProviderException e) {
            String errorMessage = "Encountered NoSuchProviderException when create an empty RSA KeyFactory using BC as provider.";
            log.error(errorMessage, e);
            throw new WebApplicationException(errorMessage, 500);
        }

        PrivateKey privateKey;
        try {
            log.info("Generating the PrivateKey from PKCS8EncodedKeySpec using the KeyFactory.");
            privateKey = factory.generatePrivate(privKeySpec);
            log.info("Generated successfully.");
        } catch (InvalidKeySpecException e) {
            String errorMessage = "Encountered InvalidKeySpecException when generating the PrivateKey from PKCS8EncodedKeySpec using the KeyFactory.";
            log.error(errorMessage, e);
            throw new WebApplicationException(errorMessage, 500);
        }

        DataSource source = new ByteArrayDataSource(postedBytes, contentTypeStr, null);
        log.info("Created a DataSource with the posted bytes. Used the content type string. But I think it is useless.");
        DataHandler handler = new DataHandler(source);
        log.info("Created a DataHandler using the DataSource.");
        MimeBodyPart part = new MimeBodyPart();
        log.info("Created a MimeBodyPart.");

        try {
            log.info("Setting the handler on the MimeBodyPart.");
            part.setDataHandler(handler);
            log.info("Set the handler on the MimeBodyPart successfully.");
        } catch (MessagingException e) {
            String errorMessage = "Encountered MessagingException when try to set the handler on the MimeBodyPart.";
            log.error(errorMessage, e);
            throw new WebApplicationException(errorMessage, 500);
        }

        // Set "Content-Type" and "Content-Transfer-Encoding" to what is received in the HTTP header
        // since it may not be set in the received mime body part
        try {
            log.info("Setting the header Content-Type on the MimeBodyPart to {}.", contentTypeStr);
            part.setHeader("Content-Type", contentTypeStr);
            log.info("Set successfully.");
        } catch (MessagingException e) {
            String errorMessage = "Encountered MessagingException when try to set the header Content-Type on the MimeBodyPart.";
            log.error(errorMessage, e);
            throw new WebApplicationException(errorMessage, 500);
        }

        // Set the transfer encoding
        // http://stackoverflow.com/questions/25710599/content-transfer-encoding-7bit-or-8-bit
        List<String> ctes = headersMap.get("Content-Transfer-Encoding");
        String cte = "binary";
        if (ctes == null || ctes.size() == 0) {
            log.info("No Content-Transfer-Encoding set in the headers, use default encoding: binary");
        }
        else {
            int ctesSize = ctes.size();
            if (ctesSize > 1) {
                String errorMessage = String.format("We have %d entries in header for Content-Transfer-Encoding. We do not know which one to use.", ctes.size());
                log.error(errorMessage);
                throw new WebApplicationException(errorMessage, 400);
            }
            cte = ctes.get(0);
            log.info("Using Content-Transfer-Encoding: {}", cte);
        }
        try {
            log.info("Setting the header Content-Transfer-Encoding on the MimeBodyPart to: {}.", cte);
            part.setHeader("Content-Transfer-Encoding", cte);
            log.info("Set successfully.");
        } catch (MessagingException e) {
            String errorMessage = "Encountered MessagingException when try to set the header Content-Transfer-Encoding on the MimeBodyPart.";
            log.error(errorMessage, e);
            throw new WebApplicationException(errorMessage, 500);
        }

        SMIMEEnveloped envelope;
        try {
            log.info("Creating a new SMIMEEnveloped using the MimeBodyPart.");
            envelope = new SMIMEEnveloped(part);
            log.info("Created successfully.");
        } catch (MessagingException e) {
            String errorMessage = "We caught an MessagingException when create SMIMEEnveloped with the MimeBodyPart. Something is very wrong.";
            log.error(errorMessage, e);
            throw new WebApplicationException(errorMessage, 500);
        } catch (CMSException e) {
            String errorMessage = "We caught an CMSException when create SMIMEEnveloped with the MimeBodyPart. Something is very wrong.";
            log.error(errorMessage, e);
            throw new WebApplicationException(errorMessage, 500);
        }

        RecipientInformationStore recipientInfoStore = envelope.getRecipientInfos();
        if (recipientInfoStore == null) {
            String errorMessage = "We failed to get RecipientInformationStore from SMIMEEnveloped. Something is very wrong.";
            log.error(errorMessage);
            throw new WebApplicationException(errorMessage, 500);
        }
        log.info("Got RecipientInformationStore from the SMIMEEnveloped.");
        Collection<RecipientInformation> recipients = recipientInfoStore.getRecipients();
        if (recipients == null || recipients.size() == 0) {
            String errorMessage = "We got no recipients from the RecipientInformationStore. We cannot decrypt.";
            log.error(errorMessage);
            throw new WebApplicationException(errorMessage, 400);
        }

        if (recipients.size() > 1) {
            String errorMessage = String.format("We got %d recipients from the RecipientInformationStore. " +
                                                "It seems that you are sending this to multiple parties. " +
                                                "It may be OK, but we do not want to support it. " +
                                                "Contact us if you really really need it.", recipients.size());
            log.error(errorMessage);
            throw new WebApplicationException(errorMessage, 500);
        }

        // TODO: To truly support receipient, the loop need to compare certificate with what we loaded using the as2To
        for (RecipientInformation recipientInfo : recipients)
        {
            if (!(recipientInfo instanceof KeyTransRecipientInformation)) {
                String errorMessage = "The only RecipientInfo is not a KeyTransRecipientInformation. We cannot decrypt.";
                log.error(errorMessage);
                throw new WebApplicationException(errorMessage, 400);
            }

            byte[] privateKeyEncoded = privateKey.getEncoded();
            log.info("Converted private key to encoded byte array.");
            PrivateKeyInfo privateKeyInfo = PrivateKeyInfo.getInstance(privateKeyEncoded);
            log.info("Built a PrivateKeyInfo using the encoded byte array.");
            AsymmetricKeyParameter asymmetricKeyParameter;
            try {
                log.info("Creating a AsymmetricKeyParameter from the privateKeyInfo.");
                asymmetricKeyParameter = PrivateKeyFactory.createKey(privateKeyInfo);
                log.info("Created successfully.");
            } catch (IOException e) {
                String errorMessage = "Encountered IOException when try to create AsymmetricKeyParameter from the privateKeyInfo.";
                log.error(errorMessage, e);
                throw new WebApplicationException(errorMessage, 500);
            }

            BcRSAKeyTransEnvelopedRecipient envelopedRecipient = new BcRSAKeyTransEnvelopedRecipient(asymmetricKeyParameter);
            log.info("Created a BcRSAKeyTransEnvelopedRecipient with the AsymmetricKeyParameter");
            byte[] decryptedData;
            try {
                log.info("Decrypting the content using BcRSAKeyTransEnvelopedRecipient.");
                decryptedData = recipientInfo.getContent(envelopedRecipient);
                log.info("Decrypted successfully.");
                //log.info(new String(decryptedData));
            } catch (CMSException e) {
                String errorMessage = "Encountered CMSException when try to decrypt the content using BcRSAKeyTransEnvelopedRecipient.";
                log.error(errorMessage, e);
                throw new WebApplicationException(errorMessage, 400);
            }

            MimeBodyPart decryptedPart;
            try {
                log.info("Create a MimeBodyPart with the decrypted data.");
                decryptedPart = SMIMEUtil.toMimeBodyPart(decryptedData);
                log.info("Created a MimeBodyPart successfully.");
            } catch (SMIMEException e) {
                String decryptedDataStr = new String(decryptedData);
                String errorMessage = "Encountered SMIMEException when try to create a MimeBodyPart with the decrypted data. The decrypted data looks like this: " + decryptedDataStr;
                log.error(errorMessage, e);
                throw new WebApplicationException(errorMessage, 400);
            }

            String decryptedContentTypeStr;
            try {
                log.info("Try to get the content type string from the decrypted MimeBodyPart.");
                decryptedContentTypeStr = decryptedPart.getContentType();
                log.info("Successfully got the content type string: {}", decryptedContentTypeStr);
            } catch (MessagingException e) {
                String decryptedDataStr = new String(decryptedData);
                String errorMessage = "Encountered MessagingException when try to get Content-Type from the decrypted MimeBodyPart. The decrypted data looks like this: " + decryptedDataStr;
                log.error(errorMessage, e);
                throw new WebApplicationException(errorMessage, 400);
            }

            // https://tools.ietf.org/html/rfc5402
            // According to RFC5402, compression can be after signing but then no compression before signing.
            // Or you can compress before signing but then no compression allowed after signing.
            boolean compressedAfterSigning = false;
            if (decryptedContentTypeStr.contains("application/pkcs7-mime") && decryptedContentTypeStr.contains("smime-type=compressed-data")) {
                log.info("The message is compressed after the signature. It is OK according to RFC5402. But they cannot compress before and after the signature. So now we expect the message to be NOT compressed before the signature.");
                compressedAfterSigning = true;
                // TODO: support this
                String errorMessage = String.format("The decrypted Content-Type string is: \"%finalMessage\". It contains application/pkcs7-mime and smime-type=compressed-data. Meaning it is compressed after the signature. We currently do not support this.", decryptedContentTypeStr);
                log.error(errorMessage);
                throw new WebApplicationException(errorMessage, 400);
            }
            else {
                log.info("The message is not compressed after the signature. It is still possible for it to be compressed before the signature.");
            }

            if (!decryptedContentTypeStr.contains("multipart/signed")) {
                String errorMessage = String.format("The decrypted Content-Type string is: \"%finalMessage\". It does not contains multipart/signed, meaning the message is not signed. We do not support this.", decryptedContentTypeStr);
                log.error(errorMessage);
                throw new WebApplicationException(errorMessage, 400);
            }

            log.info("Message is signed. Need to look up the sender.");
            List<String> as2Froms = headersMap.get("AS2-From");
            if (as2Froms == null || as2Froms.size() == 0) {
                String errorMessage = "No AS2-From in headers. Can't decide which private key to load for decryption.";
                log.error(errorMessage);
                throw new WebApplicationException(errorMessage, 400);
            }
            if (as2Froms.size() > 1) {
                String errorMessage = String.format("We have %d entries in header for Content-Type. We do not know which one to use.", as2Froms.size());
                log.error(errorMessage);
                throw new WebApplicationException(errorMessage, 400);
            }

            String as2From = as2Froms.get(0);
            log.info("Message sent from {} . Loading the corresponding public key to verify signature.", as2From);

            List<PublicKeyModel> publicKeyModels = this.publicKeyDAO.findAS2Id(as2From);
            if (publicKeyModels == null || publicKeyModels.size()==0) {
                String errorMessage = String.format("Failed to find public key from database for as2Id: %finalMessage . Is the party setup properly?", as2To);
                log.error(errorMessage);
                throw new WebApplicationException(errorMessage, 400);
            }
            if (publicKeyModels.size() > 1) {
                // TODO: Support it
                String errorMessage = String.format("Found %d public key from database for as2Id: %finalMessage . We do not support multiple public key right now. We may in the future.", publicKeyModels.size(), as2To);
                log.error(errorMessage);
                throw new WebApplicationException(errorMessage, 400);
            }
            PublicKeyModel publicKeyModel = publicKeyModels.get(0);
            String publicKeyStr = publicKeyModel.publicKey;
            log.info("Got 1 and only 1 public key from db.");
            //log.info(publicKeyStr);

            InputStream publicKeyStream = new ByteArrayInputStream(publicKeyStr.getBytes(StandardCharsets.UTF_8));

            CertificateFactory certificateFactory;
            try {
                log.info("Creating X.509 CertificateFactory.");
                certificateFactory = CertificateFactory.getInstance("X.509");
                log.info("Created successfully.");
            } catch (CertificateException e) {
                String errorMessage = "Encountered CertificateException when try to create X.509 CertificateFactory.";
                log.error(errorMessage, e);
                throw new WebApplicationException(errorMessage, 500);
            }

            X509Certificate dropas2aCert;
            try {
                log.info("Creating X509Certificate using the factory from the input stream.");
                dropas2aCert = (X509Certificate) certificateFactory.generateCertificate(publicKeyStream);
                log.info("Created successfully.");
            } catch (CertificateException e) {
                String errorMessage = "Encountered CertificateException when try to create X.509 Certificate using the factory from the input stream.";
                log.error(errorMessage, e);
                throw new WebApplicationException(errorMessage, 500);
            }

            JcaSimpleSignerInfoVerifierBuilder jcaSimpleSignerInfoVerifierBuilder = new JcaSimpleSignerInfoVerifierBuilder();
            log.info("Created a JcaSimpleSignerInfoVerifierBuilder.");
            jcaSimpleSignerInfoVerifierBuilder.setProvider("BC");
            log.info("Set BC as the provider for JcaSimpleSignerInfoVerifierBuilder.");
            SignerInformationVerifier signerInfoVerifier;
            try {
                log.info("Building a SignerInformationVerifier from the builder.");
                signerInfoVerifier = jcaSimpleSignerInfoVerifierBuilder.build(dropas2aCert);
                log.info("Build successful.");
            } catch (OperatorCreationException e) {
                String errorMessage = "Encountered OperatorCreationException when try buil a SignerInformationVerifier from the builder.";
                log.error(errorMessage, e);
                throw new WebApplicationException(errorMessage, 500);
            }


            Object decryptedPartContentObj;
            try {
                log.info("Try get the content of the decrypted MIMEBodyPart.");
                decryptedPartContentObj = decryptedPart.getContent();
                log.info("Got the content successfully.");
            } catch (IOException e) {
                String errorMessage = "Encountered IOException when try to get content of the decrypted MimeBodyPart.";
                log.error(errorMessage, e);
                throw new WebApplicationException(errorMessage, 500);
            } catch (MessagingException e) {
                String errorMessage = "Encountered MessagingException when try to get content of the decrypted MimeBodyPart.";
                log.error(errorMessage, e);
                throw new WebApplicationException(errorMessage, 500);
            }

            MimeMultipart decryptedMultipart = (MimeMultipart) decryptedPartContentObj;
            log.info("Created MimeMultipart from the decrypted MIMEBodyPart content object.");
            SMIMESigned signedPart;
            try {
                log.info("Creating an SMIMESigned instance from the MimeMultipart.");
                signedPart = new SMIMESigned(decryptedMultipart);
                log.info("Created successfully.");
            } catch (MessagingException e) {
                String errorMessage = "Encountered MessagingException when try to create an SMIMESigned instance from the MimeMultipart.";
                log.error(errorMessage, e);
                throw new WebApplicationException(errorMessage, 500);
            } catch (CMSException e) {
                String errorMessage = "Encountered CMSException when try to create an SMIMESigned instance from the MimeMultipart.";
                log.error(errorMessage, e);
                throw new WebApplicationException(errorMessage, 500);
            }

            JcaDigestCalculatorProviderBuilder jcaDigestCalculatorProviderBuilder = new JcaDigestCalculatorProviderBuilder();
            log.info("Created a JcaDigestCalculatorProviderBuilder.");
            jcaDigestCalculatorProviderBuilder.setProvider("BC");
            log.info("Set the provider to BC for the JcaDigestCalculatorProviderBuilder.");
            DigestCalculatorProvider digestCalculatorProvider;
            try {
                log.info("Building a DigestCalculatorProvider.");
                digestCalculatorProvider = jcaDigestCalculatorProviderBuilder.build();
                log.info("Built successfully.");
            } catch (OperatorCreationException e) {
                String errorMessage = "Encountered OperatorCreationException when try to build a DigestCalculatorProvider.";
                log.error(errorMessage, e);
                throw new WebApplicationException(errorMessage, 500);
            }

            MimeBodyPart signedPartContent = signedPart.getContent();
            log.info("Get the body part of the signed part of the decrypted multipart.");
            String contentTransferEncoding;
            try {
                log.info("Get the encoding of the singed part content.");
                contentTransferEncoding = signedPartContent.getEncoding();
            } catch (MessagingException e) {
                String errorMessage = "Encountered MessagingException when try to get the encoding of the singed part content.";
                log.error(errorMessage, e);
                throw new WebApplicationException(errorMessage, 500);
            }
            if (contentTransferEncoding == null || contentTransferEncoding.length() < 1) {
                log.info("Content-Transfer-Encoding was not set. Use default value: binary");
                contentTransferEncoding = "binary";
            }

            SMIMESignedParser smimeSignedParser;
            try {
                log.info("Creating a SMIMESignedParser using the digestCalculatorProvider, digestCalculatorProvider and contentTransferEncoding.");
                smimeSignedParser = new SMIMESignedParser(digestCalculatorProvider, decryptedMultipart, contentTransferEncoding);
                log.info("Create successful.");
            } catch (MessagingException e) {
                String errorMessage = "Encountered MessagingException when try to create SMIMESignedParser.";
                log.error(errorMessage, e);
                throw new WebApplicationException(errorMessage, 500);
            } catch (CMSException e) {
                String errorMessage = "Encountered CMSException when try to create SMIMESignedParser.";
                log.error(errorMessage, e);
                throw new WebApplicationException(errorMessage, 500);
            }

            SignerInformationStore sis;
            try {
                log.info("Creating SignerInformationStore from SMIMESignedParser");
                sis = smimeSignedParser.getSignerInfos();
                log.info("Created SMIMESignedParser");
            } catch (CMSException e) {
                String errorMessage = "Encountered CMSException when try to create SignerInformationStore.";
                log.error(errorMessage, e);
                throw new WebApplicationException(errorMessage, 500);
            }

            Collection<SignerInformation> signers = sis.getSigners();
            if (signers == null || signers.size()==0) {
                String errorMessage = "Found no signers from the SignerInformationStore.";
                log.error(errorMessage);
                throw new WebApplicationException(errorMessage, 500);
            }

            log.info("Found {} signers from the SignerInformationStore.", signers.size());
            boolean signedByAS2From = false;
            for(SignerInformation signer : signers) {
                AttributeTable attrTbl = signer.getSignedAttributes();
                log.info("Signer Attributes: " + (attrTbl==null?"NULL":attrTbl.toHashtable()));
                try {
                    signedByAS2From = signer.verify(signerInfoVerifier);
                } catch (CMSException e) {
                    String errorMessage = "Encountered CMSException when try to create verify signature.";
                    log.error(errorMessage, e);
                    throw new WebApplicationException(errorMessage, 500);
                }
                if (signedByAS2From) {
                    break;
                }
            }
            if (!signedByAS2From) {
                String errorMessage = "The message does not seems to be signed properly by the sender.";
                log.error(errorMessage);
                throw new WebApplicationException(errorMessage, 400);
            }
            log.info("We successfully verified that the message is signed properly by AS2-From: {}.", as2From);

            SMIMECompressed compressed = null;
            try {
                compressed = new SMIMECompressed(signedPartContent);
            } catch (MessagingException e) {
                // TODO: Support it!
                String errorMessage = "Encountered MessagingException when try to create SMIMECompressed. If the message is not compressed, we currently do not support it.";
                log.error(errorMessage, e);
                throw new WebApplicationException(errorMessage, 500);
            } catch (CMSException e) {
                String errorMessage = "Encountered CMSException when try to create SMIMECompressed. If the message is not compressed, we currently do not support it.";
                log.error(errorMessage, e);
                throw new WebApplicationException(errorMessage, 500);
            }

            ZlibExpanderProvider zlibExpanderProvider = new ZlibExpanderProvider();
            byte[] decompressedContent;
            try {
                decompressedContent = compressed.getContent(zlibExpanderProvider);
                log.info("Decompressed successfully.");
                //log.info(new String(decompressedContent));
            } catch (CMSException e) {
                String errorMessage = "Encountered CMSException when try to decompress.";
                log.error(errorMessage, e);
                throw new WebApplicationException(errorMessage, 500);
            }

            MimeBodyPart decompressedPart;
            try {
                decompressedPart = SMIMEUtil.toMimeBodyPart(decompressedContent);
                log.info("Created MimeBodyPart using the decompressed bytes.");
            } catch (SMIMEException e) {
                String errorMessage = "Encountered SMIMEException when try to create a MimeBodyPart from the decompressedContnet byte array.";
                log.error(errorMessage, e);
                throw new WebApplicationException(errorMessage, 500);
            }

            ByteArrayInputStream messageContent;
            try {
                messageContent = (ByteArrayInputStream) decompressedPart.getContent();
            } catch (IOException e) {
                String errorMessage = "Encountered IOException when try to read content of the decompressedPart.";
                log.error(errorMessage, e);
                throw new WebApplicationException(errorMessage, 500);
            } catch (MessagingException e) {
                String errorMessage = "Encountered MessagingException when try to read content of the decompressedPart.";
                log.error(errorMessage, e);
                throw new WebApplicationException(errorMessage, 500);
            }

            int n = messageContent.available();
            byte[] bytes = new byte[n];
            messageContent.read(bytes, 0, n);
            String finalMessage = new String(bytes, StandardCharsets.UTF_8); // Or any encoding.
            log.info("Got the final message from the decompressedPart.");
            //log.info("The final message is: {}", finalMessage);

        }

        return Response.ok().build();
    }
}
