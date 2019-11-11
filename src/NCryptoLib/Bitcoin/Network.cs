using System;
using System.Collections.Generic;
using System.Text;

namespace NCryptoLib.Bitcoin.Network
{ 
    public static class TestNet
    {
        public static byte[] P2PKHAddressVersion = new byte[] { (111) };
    }

    public static class MainNet
    {
        public static byte[] P2PKHAddressVersion = new byte[] { (0) };
    }

    public static class RegTest
    {
        public static byte[] P2PKHAddressVersion = new byte[] { (111) };
    }
}
