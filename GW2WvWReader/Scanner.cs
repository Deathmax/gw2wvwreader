using System;
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace GW2WvWReader
{
    public class SigScan
    {
        private readonly IntPtr m_vAddress; //The starting address we want to begin reading at. 
        private readonly Process m_vProcess; //The process we want to read the memory of. 
        private readonly Int32 m_vSize; //The number of bytes we wish to read from the process. 
        private byte[] m_vDumpedRegion; //The memory dumped from the external process. 

        public SigScan(IntPtr addr, int size)
        //Overloaded class constructor that sets the class properties during construction.
        {
            Process proc = Process.GetProcessById(Function.FindpID());
            m_vProcess = proc; //The process to dump the memory from.
            m_vAddress = addr; //The started address to begin the dump.
            m_vSize = size; //The size of the dump
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, [Out] byte[] lpBuffer,
                                                     int dwSize, out int lpNumberOfBytesRead);

        private bool DumpMemory()
        {
            try
            {
                // Checks to ensure we have valid data. 
                if (m_vProcess == null)
                    return false;
                if (m_vProcess.HasExited)
                    return false;
                if (m_vAddress == IntPtr.Zero)
                    return false;
                if (m_vSize == 0)
                    return false;

                // Create the region space to dump into. 
                m_vDumpedRegion = new byte[m_vSize];

                bool bReturn = false;
                int nBytesRead = 0;

                // Dump the memory. 
                bReturn = ReadProcessMemory(m_vProcess.Handle, m_vAddress, m_vDumpedRegion, m_vSize, out nBytesRead);

                // Validation checks. 
                if (bReturn == false || nBytesRead != m_vSize)
                    return false;
                return true;
            }
            catch (Exception ex)
            {
                return false;
            }
        }

        private bool MaskCheck(int nOffset, byte[] btPattern, string strMask)
        // Compares the current pattern byte to the current memory dump byte to check for a match. Uses wildcards to skip bytes that are deemed unneeded in the compares. 
        {
            for (int x = 0; x < btPattern.Length; x++) // Loop the pattern and compare to the mask and dump. 
            {
                if (strMask[x] == '?') // If the mask char is a wildcard, just continue. 
                    continue;
                if ((strMask[x] == 'x') && (btPattern[x] != m_vDumpedRegion[nOffset + x]))
                    // If the mask char is not a wildcard, ensure a match is made in the pattern. 
                    return false;
            }
            return true; // The loop was successful so we found the pattern. 
        }

        public IntPtr FindPattern(byte[] btPattern, string strMask, int nOffset)
        //Attempts to locate the given pattern inside the dumped memory region compared against the given mask. If the pattern is found, the offset is added to the located address and returned to the user.
        {
            try
            {
                if (m_vDumpedRegion == null || m_vDumpedRegion.Length == 0)
                // Dump the memory region if we have not dumped it yet. 
                {
                    if (!DumpMemory())
                        return IntPtr.Zero;
                }
                if (strMask.Length != btPattern.Length) // Ensure the mask and pattern lengths match. 
                    return IntPtr.Zero;

                for (int x = 0; x < m_vDumpedRegion.Length; x++) // Loop the region and look for the pattern. 
                {
                    if (MaskCheck(x, btPattern, strMask))
                    {
                        return new IntPtr((int)m_vAddress + (x + nOffset)); // The pattern was found, return it. 
                    }
                }
                return IntPtr.Zero;
            }
            catch (Exception ex)
            {
                return IntPtr.Zero;
            }
        }
    }
}