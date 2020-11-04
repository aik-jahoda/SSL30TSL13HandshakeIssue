using System;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;

namespace SSL30TSL13HandshakeIssue
{
    class Program
    {
        static void Main(string[] args)
        {
            ServerAsyncSslHelper(SslProtocols.Tls13, SslProtocols.Tls13).Wait();
#pragma warning disable CS0618 // Type or member is obsolete
            ServerAsyncSslHelper(SslProtocols.Ssl3, SslProtocols.Ssl3).Wait();
            ServerAsyncSslHelper(SslProtocols.Ssl3 | SslProtocols.Tls13, SslProtocols.Ssl3 | SslProtocols.Tls13).Wait();
            ServerAsyncSslHelper(SslProtocols.None, SslProtocols.None).Wait();
#pragma warning restore CS0618 // Type or member is obsolete
        }

        private static (Socket clientSocket, Socket serverSocket) GetConnectedTcpStreams()
        {
            using (Socket listener = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp))
            {
                listener.Bind(new IPEndPoint(IPAddress.Loopback, 0));
                listener.Listen(1);

                var clientSocket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
                clientSocket.Connect(listener.LocalEndPoint);
                Socket serverSocket = listener.Accept();

                serverSocket.NoDelay = true;
                clientSocket.NoDelay = true;

                return (clientSocket, serverSocket);
            }

        }

        static private X509Certificate2 CreateCert()
        {
            // Create self-signed cert for server.
            using (RSA rsa = RSA.Create())
            {
                var certReq = new CertificateRequest("CN=contoso.com", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
                certReq.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, false));
                certReq.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(new OidCollection { new Oid("1.3.6.1.5.5.7.3.1") }, false));
                certReq.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, false));
                X509Certificate2 cert = certReq.CreateSelfSigned(DateTimeOffset.UtcNow.AddMonths(-1), DateTimeOffset.UtcNow.AddMonths(1));
                if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                {
                    return new X509Certificate2(cert.Export(X509ContentType.Pfx));
                }
                return cert;
            }
        }


        private static X509Certificate2 _serverCertificate = CreateCert();
        private static async Task ServerAsyncSslHelper(
            SslProtocols clientSslProtocols,
            SslProtocols serverSslProtocols)
        {
            Console.WriteLine("=======================================");
            Console.WriteLine(
                "Server: " + serverSslProtocols + "; Client: " + clientSslProtocols);

            (Socket clientSocket, Socket serverSocket) = GetConnectedTcpStreams();
            var clientStream = new NetworkStream(clientSocket, ownsSocket: true);
            var serverStream = new NetworkStream(serverSocket, ownsSocket: true);

            using (SslStream sslServerStream = new SslStream(
                serverStream,
                false,
                AllowEmptyClientCertificate))
            using (SslStream sslClientStream = new SslStream(
                clientStream,
                false,
                AllowEmptyClientCertificate))
            {
                string serverName = _serverCertificate.GetNameInfo(X509NameType.SimpleName, false);

                Console.WriteLine("Connected on {0} {1} ({2} {3})", clientSocket.LocalEndPoint, clientSocket.RemoteEndPoint, clientSocket.Handle, serverSocket.Handle);
                Console.WriteLine("client SslStream#{0} server SslStream#{1}", sslClientStream.GetHashCode(), sslServerStream.GetHashCode());

                try
                {
                    Task clientAuthentication = sslClientStream.AuthenticateAsClientAsync(
                    serverName,
                    null,
                    clientSslProtocols,
                    false);

                Task serverAuthentication = sslServerStream.AuthenticateAsServerAsync(
                    _serverCertificate,
                    true,
                    serverSslProtocols,
                    false);

                    await clientAuthentication;
                    await serverAuthentication;
                }
                catch (Exception ex)
                {
                    Console.WriteLine("Exception : " + ex);
                    return;
                }
                Console.WriteLine(
                    "Server({0}) authenticated with encryption cipher: {1} {2}-bit strength",
                    serverSocket.LocalEndPoint,
                    sslServerStream.CipherAlgorithm,
                    sslServerStream.CipherStrength);

            }
        }

        private static bool AllowEmptyClientCertificate(
          object sender,
          X509Certificate certificate,
          X509Chain chain,
          SslPolicyErrors sslPolicyErrors)
        {
            return true;  // allow everything
        }

    }
}
