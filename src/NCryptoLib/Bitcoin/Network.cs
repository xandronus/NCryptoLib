using System;
using System.Collections.Generic;
using System.Text;

namespace NCryptoLib.Bitcoin.Network
{ 
    public static class TestNet
    {
        public static byte[] P2PKHAddressVersion = new byte[] { 0x6F };
    }

    public static class MainNet
    {
        public static byte[] P2PKHAddressVersion = new byte[] { 0x00 };
    }

    public static class RegTest
    {
        public static byte[] P2PKHAddressVersion = new byte[] { 0x6F };
    }
}
