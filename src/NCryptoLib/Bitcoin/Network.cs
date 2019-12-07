using System;
using System.Collections.Generic;
using System.Text;

namespace NCryptoLib.Bitcoin.Network
{
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Performance", "CA1819:Properties should not return arrays", Justification = "Temporary until network structure is defined")]
    public static class TestNet
    {
        public static byte[] P2PKHAddressVersion => new byte[] { 0x6F };
    }

    [System.Diagnostics.CodeAnalysis.SuppressMessage("Performance", "CA1819:Properties should not return arrays", Justification = "Temporary until network structure is defined")]
    public static class MainNet
    {       
        public static byte[] P2PKHAddressVersion => new byte[] { 0x00 };
    }

    [System.Diagnostics.CodeAnalysis.SuppressMessage("Performance", "CA1819:Properties should not return arrays", Justification = "Temporary until network structure is defined")]
    public static class RegTest
    {
        public static byte[] P2PKHAddressVersion => new byte[] { 0x6F };
    }
}
