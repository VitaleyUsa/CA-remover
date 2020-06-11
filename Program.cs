using System;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace CA_remover
{
    class Program
    {
        static void Main()
        {
            

            RemoveCerts(StoreName.My);
            RemoveCerts(StoreName.Root);
            RemoveCerts(StoreName.CertificateAuthority);
            RemoveCerts(StoreName.AuthRoot);
            RemoveCerts(StoreName.TrustedPublisher);
            RemoveCerts(StoreName.TrustedPeople);
            RemoveCerts(StoreName.AddressBook);
            
        }

        static void RemoveCerts(StoreName local_store){
            string[] files = Directory.GetFiles("certs");

            X509Store store = new X509Store(local_store, StoreLocation.CurrentUser);
            store.Open(OpenFlags.ReadWrite | OpenFlags.IncludeArchived);
                foreach(string cert in files){
                    // Берём серийные номера сертификатов из нашей папки с сертификатами
                    X509Certificate2 certificate = new X509Certificate2 (cert);
                    String serialHex = certificate.SerialNumber;
                    certificate.Dispose();

                    // Находим данный сертификат в хранилище и удаляем его
                    X509Certificate2Collection col = store.Certificates.Find(X509FindType.FindBySerialNumber, serialHex, false);
                    foreach (var cur_cert in col)
                    {
                        // Remove the certificate
                        store.Remove(cur_cert);        
                    }
                }
            store.Close();
            Console.WriteLine(local_store + " store is cleaned.");
        }
    }
}
