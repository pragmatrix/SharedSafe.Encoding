using System;
using System.Security.Cryptography.X509Certificates;

namespace SharedSafe.Encoding.Cryptography
{
	public static class CertificateHelper
	{
		public static string serialize(X509Certificate2 certificate)
		{
			var data = certificate.GetRawCertData();
			return Convert.ToBase64String(data);
		}

		public static X509Certificate2 deserialize(string rawData)
		{
			var raw = Convert.FromBase64String(rawData);
			var cert = new X509Certificate2();
			cert.Import(raw);
			return cert;
		}

		public static string getSimpleNameOfSubject(X509Certificate2 cert)
		{
			return cert.GetNameInfo(X509NameType.SimpleName, false);
		}
	}
}
