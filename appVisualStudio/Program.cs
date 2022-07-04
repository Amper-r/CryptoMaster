using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Text;
using System.Xml;

namespace WebServerCert4
{
    class Prop
    {
        public string task;
        public string data;
        public string thumbprint;
    }
    class Program
    {
        static void Main(string[] args)
        {

            OpenStandardStreamIn();
        }
        static private string GetCertsJsonString()
        {
            X509Store store = new X509Store(StoreName.My, StoreLocation.CurrentUser);
            store.Open(OpenFlags.ReadOnly);
            List<X509Certificate2> certs = new List<X509Certificate2>();
            foreach (X509Certificate2 certificate in store.Certificates)
            {
                certs.Add(certificate);
            }
            return System.Text.Json.JsonSerializer.Serialize(certs);
        }
        async static public void WriteToFile(string data)
        {
            using (StreamWriter writer = new StreamWriter(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData) + "\\CryptoMaster\\logs.txt", true))
            {
                await writer.WriteLineAsync($"[{DateTime.Now.ToString("hh:mm:ss")}] {data}");
            }
        }

        private static void OpenStandardStreamIn()
        {
            using (Stream stdin = Console.OpenStandardInput())
            {
                using (Stream stdout = Console.OpenStandardOutput())
                {
                    byte[] bytes = new byte[32768];
                    int outputLength = stdin.Read(bytes, 0, 32768);
                    char[] chars = Encoding.UTF8.GetChars(bytes, 4, outputLength);
                    try
                    {
                        List<Prop> list = JsonConvert.DeserializeObject<List<Prop>>(new string(chars));
                        string task = list[0].task;
                        string data = list[0].data;
                        string thumbprint = list[0].thumbprint;

                        string appName = "CryptoMaster";
                        string directoryAppPath = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData) + "\\" + appName;
                        string pathTempXmlFiles = directoryAppPath + "\\" + "tempXml";

                        WriteToFile("Task: " + task);
                        if(task == "get_certs")
                        {
                            OpenStandardStreamOut(Base64Encode(GetCertsJsonString()), stdout);
                        }
                        else if(task == "sign_xml")
                        {
                            X509Certificate2 cert = GetCertFromThumbprint(thumbprint);
                            SaveXml(data, pathTempXmlFiles, "xml.xml");

                            //RSA key = cert.GetRSAPublicKey();

                            //string b64publicKey = Convert.ToBase64String(key.ExportRSAPublicKey());

                            //RSA publicKey = RSA.Create();
                            //publicKey.ImportRSAPublicKey(Convert.FromBase64String(b64publicKey), out int a);

                            string b64SignedXml = SignXmlFile(pathTempXmlFiles + "\\xml.xml", pathTempXmlFiles + "\\signedXml.xml", cert.GetRSAPrivateKey(), cert.GetRSAPublicKey());
                            //WriteToFile(VerifyXmlFile(pathTempXmlFiles + "\\signedXml.xml", publicKey).ToString());
                            OpenStandardStreamOut(b64SignedXml, stdout);
                        }
                        else if(task == "verify_xml")
                        {
                            string verify;
                            try
                            {
                                SaveXml(data, pathTempXmlFiles, "check.xml");
                                verify = VerifyXmlFile(pathTempXmlFiles + "\\check.xml");
                            }
                            catch (Exception)
                            {
                                verify = "not_sign";
                            }
                            OpenStandardStreamOut(verify, stdout);
                        }
                    }
                    catch (Exception ex)
                    {
                        WriteToFile(ex.Message);
                        WriteToFile(ex.StackTrace);
                        throw;
                    }
                }
            }
        }
        private static void OpenStandardStreamOut(string b64strData, Stream stdout)
        {
            // We need to send the 4 btyes of length information
            //string msgdata = "{\"data\":\"" + GetUnicodeString(new string(stringData.Where(c => !char.IsControl(c)).ToArray())) + "\"}";
            string msgdata = "{\"data\":\"" + b64strData + "\"}";
            WriteToFile(msgdata);
            int DataLength = msgdata.Length;
            stdout.WriteByte((byte)((DataLength >> 0) & 0xFF));
            stdout.WriteByte((byte)((DataLength >> 8) & 0xFF));
            stdout.WriteByte((byte)((DataLength >> 16) & 0xFF));
            stdout.WriteByte((byte)((DataLength >> 24) & 0xFF));
            //Available total length : 4,294,967,295 ( FF FF FF FF )
            Console.Write(msgdata);
        }
        private static string GetUnicodeString(string s)
        {
            StringBuilder sb = new StringBuilder();
            foreach (char c in s)
            {
                sb.Append("\\u");
                sb.Append(String.Format("{0:x4}", (int)c));
            }
            return sb.ToString();
        }

        public static string Base64Encode(string plainText)
        {
            var plainTextBytes = System.Text.Encoding.UTF8.GetBytes(plainText);
            return System.Convert.ToBase64String(plainTextBytes);
        }

        private static string SignXmlFile(string FileName, string SignedFileName, RSA privateKey, RSA publicKey)
        {
            // Create a new XML document.
            XmlDocument doc = new XmlDocument();

            // Load the passed XML file using its name.
            doc.Load(new XmlTextReader(FileName));

            string b64publicKey = Convert.ToBase64String(publicKey.ExportRSAPublicKey());
            XmlElement xmlPublicKeyEl = doc.CreateElement("publickey");
            XmlText xmlPublicKeyValue = doc.CreateTextNode(b64publicKey);
            doc.DocumentElement.AppendChild(xmlPublicKeyEl);
            doc.DocumentElement.LastChild.AppendChild(xmlPublicKeyValue);

            //XmlElement xmlPublicKey = GetElement(publicKey.ToXmlString(false));
            //doc.DocumentElement.AppendChild(doc.ImportNode(xmlPublicKey, true));

            // Create a SignedXml object.
            SignedXml signedXml = new SignedXml(doc);

            // Add the key to the SignedXml document. 
            signedXml.SigningKey = privateKey;

            // Create a reference to be signed.
            Reference reference = new Reference();
            reference.Uri = "";

            // Add an enveloped transformation to the reference.
            XmlDsigEnvelopedSignatureTransform env = new XmlDsigEnvelopedSignatureTransform();
            reference.AddTransform(env);

            // Add the reference to the SignedXml object.
            signedXml.AddReference(reference);

            // Compute the signature.
            signedXml.ComputeSignature();

            // Get the XML representation of the signature and save
            // it to an XmlElement object.
            XmlElement xmlDigitalSignature = signedXml.GetXml();
            

            // Append the element to the XML document.
            doc.DocumentElement.AppendChild(doc.ImportNode(xmlDigitalSignature, true));

            if (doc.FirstChild is XmlDeclaration)
            {
                doc.RemoveChild(doc.FirstChild);
            }

            // Save the signed XML document to a file specified
            // using the passed string.
            XmlTextWriter xmltw = new XmlTextWriter(SignedFileName, new UTF8Encoding(false));
            doc.WriteTo(xmltw);
            xmltw.Close();

            return GetB64FromXmlFile(SignedFileName);
        }
        private static XmlElement GetElement(string xml)
        {
            XmlDocument doc = new XmlDocument();
            doc.LoadXml(xml);
            return doc.DocumentElement;
        }


        static private X509Certificate2 GetCertFromThumbprint(string thumbprint)
        {
            X509Store store = new X509Store(StoreName.My, StoreLocation.CurrentUser);
            store.Open(OpenFlags.MaxAllowed);
            foreach (X509Certificate2 certificate in store.Certificates)
            {
                if(certificate.Thumbprint == thumbprint)
                {
                    return certificate;
                }
            }
            return null;
        }
        static private string GetB64FromXmlFile(string path)
        {
            byte[] bytes = File.ReadAllBytes(path);
            string b64 = Convert.ToBase64String(bytes);
            return b64;
        }
        static private void SaveXml(string strbase64, string path, string filename)
        {
            Directory.CreateDirectory(path);
            Byte[] bytes = Convert.FromBase64String(strbase64);
            File.WriteAllBytes(path + "\\" + filename, bytes);
        }

        public static string VerifyXmlFile(string XmlSigFileName)
        {
            // Create a new XML document.
            XmlDocument xmlDocument = new XmlDocument();

            // Load the passed XML file into the document.
            xmlDocument.Load(XmlSigFileName);

            RSA publickey = RSA.Create();
            string b64publickey = xmlDocument.GetElementsByTagName("publickey")[0].InnerText;
            XmlNodeList nodeList = xmlDocument.GetElementsByTagName("Signature");

            if (b64publickey == "" || nodeList.Count == 0)
            {
                return "not_sign";
            }
            publickey.ImportRSAPublicKey(Convert.FromBase64String(b64publickey), out int a);

            // Create a new SignedXMl object.
            SignedXml signedXml = new SignedXml(xmlDocument);

            // Load the signature node.
            signedXml.LoadXml((XmlElement)nodeList[0]);

            // Check the signature and return the result.
            return signedXml.CheckSignature(publickey).ToString();
        }

    }
}
