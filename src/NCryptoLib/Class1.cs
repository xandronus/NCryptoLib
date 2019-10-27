using System;
using System.Security.Cryptography;

namespace NCryptoLib
{
    public class Class1
    {

        public void doit()
        {
            using (ECDsaCng dsa = new ECDsaCng())
            {
                //dsa.HashAlgorithm = CngAlgorithm.Sha256;
                //bob.key = dsa.Key.Export(CngKeyBlobFormat.EccPublicBlob);

                //byte[] data = new byte[] { 21, 5, 8, 12, 207 };

                //byte[] signature = dsa.SignData(data);

                //bob.Receive(data, signature);
            }
        }
    }
}