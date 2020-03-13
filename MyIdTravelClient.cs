using System;
using System.Security.Cryptography;
using System.Threading.Tasks;
using Microsoft.Web.Services2;
using Microsoft.Web.Services2.Security;
using Microsoft.Web.Services2.Security.Tokens;
using Microsoft.Web.Services2.Security.X509;
using MyIdTravelGateway.com.myidtravel;

namespace MyIdTravelGateway
{

    /// <summary>
    /// MyIdTravelClient - Client for MyIdTravel Upload Satff
    /// </summary>
    public class MyIdTravelClient
    {
        /* ==================================================================================
         * = Altere o Metodo do WebService, a classe pricipal                               = 
         * = UploadService : System.Web.Services.Protocols.SoapHttpClientProtocol           = 
         * = UploadService : Microsoft.Web.Services2.WebServicesClientProtocol (WSE 2.0)    = 
         * = Para que possa ser utilizado o certificado digital                             = 
         * ==================================================================================
         */

        private readonly com.myidtravel.GatewayService oWSProxy;
        private readonly Microsoft.Web.Services2.Security.X509.X509Certificate SigningTokenCertificate;
        private readonly Microsoft.Web.Services2.Security.X509.X509Certificate EncryptTokenCertificate;

        /// <summary>
        /// Client for MyIdTravel - Staff Profiles Upload
        /// </summary>
        /// <param name="endPoint">Url for WebService</param>
        /// <param name="signingToken">Certificate for Client pfx</param>
        /// <param name="serverCertificate">Certificate for Server cer</param>
        public MyIdTravelClient(string endPoint,
            System.Security.Cryptography.X509Certificates.X509Certificate2 signingToken,
            System.Security.Cryptography.X509Certificates.X509Certificate2 encryptToken)
            : this(endPoint, new System.Security.Cryptography.X509Certificates.X509Certificate(signingToken),
                  new System.Security.Cryptography.X509Certificates.X509Certificate(encryptToken))
        { }

        /// <summary>
        /// Client for MyIdTravel - Staff Profiles Upload
        /// </summary>
        /// <param name="endPoint">Url for WebService</param>
        /// <param name="signingTokenThumbprint">Thumbprint for Client pfx</param>
        /// <param name="encryptTokenThumbprint">Thumbprint for Server cer</param>
        public MyIdTravelClient(string endPoint,
            string signingTokenThumbprint,
            string encryptTokenThumbprint)
            : this(endPoint, new System.Security.Cryptography.X509Certificates.X509Certificate(X509CertificateByThumbprint(signingTokenThumbprint)),
                  new System.Security.Cryptography.X509Certificates.X509Certificate(X509CertificateByThumbprint(encryptTokenThumbprint)))
        { }

        /// <summary>
        /// Client for MyIdTravel - Staff Profiles Upload
        /// </summary>
        /// <param name="endPoint">Url for WebService</param>
        /// <param name="signingToken">Certificate for Client pfx</param>
        /// <param name="encryptToken">Certificate for Server cer</param>
        public MyIdTravelClient(string endPoint,
            System.Security.Cryptography.X509Certificates.X509Certificate signingToken,
            System.Security.Cryptography.X509Certificates.X509Certificate encryptToken)
        {

            oWSProxy = new com.myidtravel.GatewayService();
            oWSProxy.Url = endPoint;
            oWSProxy.UseDefaultCredentials = false;
            oWSProxy.PreAuthenticate = true;
            oWSProxy.Timeout = 180000;
            oWSProxy.RequestSoapContext.Security.Timestamp.TtlInSeconds = 1800;
            oWSProxy.staffProfilesUploadCompleted += OWSProxy_staffProfilesUploadCompleted;
            oWSProxy.loginByShortenedProfileCompleted += OWSProxy_loginByShortenedProfileCompleted;
            oWSProxy.loginCompleted += OWSProxy_loginCompleted;

            this.SigningTokenCertificate = new X509Certificate(signingToken.Handle);
            this.EncryptTokenCertificate = new X509Certificate(encryptToken.Handle);

            AddSignature(oWSProxy);
            EncryptMessage(oWSProxy);
        }

        private void OWSProxy_loginCompleted(object sender, loginCompletedEventArgs e)
        {
            if (e.Cancelled)
                taskSourceLogin.SetCanceled();

            if (e.Error != null)
                taskSourceLogin.SetException(e.Error);

            if (e.Error == null && !e.Cancelled)
                taskSourceLogin.SetResult(e.Result);
        }

        private void OWSProxy_loginByShortenedProfileCompleted(object sender, loginByShortenedProfileCompletedEventArgs e)
        {
            if (e.Cancelled)
                taskSourceLoginProfile.SetCanceled();

            if (e.Error != null)
                taskSourceLoginProfile.SetException(e.Error);

            if (e.Error == null && !e.Cancelled)
                taskSourceLoginProfile.SetResult(e.Result);
        }

        private void OWSProxy_staffProfilesUploadCompleted(object sender, com.myidtravel.staffProfilesUploadCompletedEventArgs e)
        {
            if (e.Cancelled)
                taskSourceUpload.SetCanceled();

            if (e.Error != null)
                taskSourceUpload.SetException(e.Error);

            if (e.Error == null && !e.Cancelled)
                taskSourceUpload.SetResult(e.Result);
        }
    

        private TaskCompletionSource<UploadProfilesResponse> taskSourceUpload = new TaskCompletionSource<UploadProfilesResponse>();

        /// <summary>
        /// StaffProfilesUploadAsync
        /// </summary>
        /// <param name="StaffProfilesUploadRequest">Request</param>
        /// <returns>UploadProfilesResponse</returns>
        public Task<UploadProfilesResponse> StaffProfilesUploadAsync(StaffProfilesUploadRequest StaffProfilesUploadRequest)
        {

            taskSourceUpload = new TaskCompletionSource<UploadProfilesResponse>();
            try
            {
                oWSProxy.staffProfilesUploadAsync(StaffProfilesUploadRequest);
            }
            catch (Exception ex)
            {
                taskSourceUpload.SetException(ex);
            }
            return taskSourceUpload.Task;
        }

        /// <summary>
        /// StaffProfilesUpload
        /// </summary>
        /// <param name="StaffProfilesUploadRequest">Request</param>
        /// <returns>UploadProfilesResponse</returns>
        public UploadProfilesResponse StaffProfilesUpload(StaffProfilesUploadRequest StaffProfilesUploadRequest)
        {
            return oWSProxy.staffProfilesUpload(StaffProfilesUploadRequest);
        }

        private TaskCompletionSource<MyIDTravelLoginResponse> taskSourceLogin = new TaskCompletionSource<MyIDTravelLoginResponse>();

        public MyIDTravelLoginResponse Login(MyIdTravelLoginRequest MyIdTravelLoginRequest) {

            return oWSProxy.login(MyIdTravelLoginRequest);
        }
        public Task<MyIDTravelLoginResponse> LoginAsync(MyIdTravelLoginRequest MyIdTravelLoginRequest) {

            taskSourceLogin = new TaskCompletionSource<MyIDTravelLoginResponse>();
            try
            {
                oWSProxy.loginAsync(MyIdTravelLoginRequest);
            }
            catch (Exception ex)
            {
                taskSourceUpload.SetException(ex);
            }
            return taskSourceLogin.Task;
        }

        private TaskCompletionSource<MyIDTravelLoginResponse> taskSourceLoginProfile = new TaskCompletionSource<MyIDTravelLoginResponse>();

        public MyIDTravelLoginResponse LoginByShortenedProfile(LoginByShortenedProfile1 LoginByShortenedProfile1) {

            return oWSProxy.loginByShortenedProfile(LoginByShortenedProfile1);
        }
        public Task<MyIDTravelLoginResponse> LoginByShortenedProfileAsync(LoginByShortenedProfile1 LoginByShortenedProfile1) 
        {
            taskSourceLoginProfile = new TaskCompletionSource<MyIDTravelLoginResponse>();
            try
            {
                oWSProxy.loginByShortenedProfileAsync(LoginByShortenedProfile1);
            }
            catch (Exception ex)
            {
                taskSourceLoginProfile.SetException(ex);
            }
            return taskSourceLoginProfile.Task;
        }

        private void AddSignature(WebServicesClientProtocol oWSProxy)
        {
            SecurityToken signingToken = new X509SecurityToken(this.SigningTokenCertificate);

            if (!signingToken.SupportsDigitalSignature)
            {
                throw new CryptographicException("Certificate for signature must support digital signatures and have a private key available.");
            }

            if (signingToken.IsExpired)
            {
                throw new CryptographicException("Certificate for signature is expired.");
            }

            //Add the signature element to a security section on the request to sign the request
            oWSProxy.RequestSoapContext.Security.Tokens.Add(signingToken);
            oWSProxy.RequestSoapContext.Security.Elements.Add(new MessageSignature(signingToken));
        }

        private void EncryptMessage(WebServicesClientProtocol oWSProxy)
        {
            X509SecurityToken encryptToken = new X509SecurityToken(this.EncryptTokenCertificate);

            if (!encryptToken.SupportsDataEncryption)
            {
                throw new CryptographicException("Certificate for encryption must support data encryption.");
            }

            if (encryptToken.IsExpired)
            {
                throw new CryptographicException("Certificate for signature is expired.");
            }

            oWSProxy.RequestSoapContext.Security.Tokens.Add(encryptToken);
            oWSProxy.RequestSoapContext.Security.Elements.Add(new EncryptedData(encryptToken));
        }

        private static Microsoft.Web.Services2.Security.X509.X509Certificate X509CertificateByThumbprint(string Thumbprint)
        {
            X509Certificate x509 = null;

            if (string.IsNullOrEmpty(Thumbprint))
                throw new ArgumentNullException("Thumbprint is null or empty", new Exception("Thumbprint is mandatory"));

            Thumbprint = Thumbprint.Replace("\u200e", string.Empty).Replace("\u200f", string.Empty).Replace(" ", string.Empty).Replace(":", string.Empty);

            X509CertificateStore store = new X509CertificateStore(X509CertificateStore.StoreProvider.System, X509CertificateStore.StoreLocation.LocalMachine, X509CertificateStore.RootStore);
            store.OpenRead();
            foreach (X509Certificate cert in store.Certificates)
            {
                if (cert.GetCertHashString().Trim().ToUpper() == Thumbprint.Trim().ToUpper())
                {
                    x509 = cert;
                    break;
                }
            }

            store.Close();

            if (x509 == null)
            {
                store = new X509CertificateStore(X509CertificateStore.StoreProvider.System, X509CertificateStore.StoreLocation.LocalMachine, X509CertificateStore.MyStore);
                store.OpenRead();
                foreach (X509Certificate cert in store.Certificates)
                {
                    if (cert.GetCertHashString().Trim().ToUpper() == Thumbprint.Trim().ToUpper())
                    {
                        x509 = cert;
                        break;
                    }
                }
                store.Close();
            }

            if (x509 == null)
            {
                store = new X509CertificateStore(X509CertificateStore.StoreProvider.System, X509CertificateStore.StoreLocation.CurrentUser, X509CertificateStore.RootStore);
                store.OpenRead();
                foreach (X509Certificate cert in store.Certificates)
                {
                    if (cert.GetCertHashString().Trim().ToUpper() == Thumbprint.Trim().ToUpper())
                    {
                        x509 = cert;
                        break;
                    }
                }
                store.Close();
            }

            if (x509 == null)
            {
                store = new X509CertificateStore(X509CertificateStore.StoreProvider.System, X509CertificateStore.StoreLocation.CurrentUser, X509CertificateStore.MyStore);
                store.OpenRead();
                foreach (X509Certificate cert in store.Certificates)
                {
                    if (cert.GetCertHashString().Trim().ToUpper() == Thumbprint.Trim().ToUpper())
                    {
                        x509 = cert;
                        break;
                    }
                }
                store.Close();
            }

            if (x509 == null)
            {
                if (!string.IsNullOrEmpty(Thumbprint))
                    throw new CryptographicException("A x509 certificate for " + Thumbprint + " was not found");
                else
                    throw new CryptographicException("A x509 certificate was not found");
            }
            return x509;
        }
    }
}
