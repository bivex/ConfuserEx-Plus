using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;

namespace Confuser.Runtime
{
    internal static class EraseHeaders
    {
        [DllImport("kernel32.dll")]
        public static extern IntPtr ZeroMemory(IntPtr addr, IntPtr size);

        [DllImport("kernel32.dll")]
        public static extern IntPtr VirtualProtect(IntPtr lpAddress, IntPtr dwSize, IntPtr flNewProtect, ref IntPtr lpflOldProtect);
        
        static unsafe void Initialize()
        {
            if (Environment.OSVersion.Platform != PlatformID.Win32NT)
                return; // Protection requires Windows APIs

            try 
            {
                var sectiontabledwords = new List<int>() { 0x8, 0xC, 0x10, 0x14, 0x18, 0x1C, 0x24 };
                var peheaderbytes = new List<int>() { 0x1A, 0x1B };
                var peheaderwords = new List<int>() { 0x4, 0x16, 0x18, 0x40, 0x42, 0x44, 0x46, 0x48, 0x4A, 0x4C, 0x5C, 0x5E };
                
                var process = System.Diagnostics.Process.GetCurrentProcess();
                var base_address = process.MainModule.BaseAddress;
                if (base_address == IntPtr.Zero) return;

                // Fixed 64-bit overflow vulnerability by using ToInt64
                long baseAddressVal = base_address.ToInt64();
                var dwpeheader = Marshal.ReadInt32((IntPtr)(baseAddressVal + 0x3C));
                var wnumberofsections = Marshal.ReadInt16((IntPtr)(baseAddressVal + dwpeheader + 0x6));

                for (int i = 0; i < peheaderwords.Count; i++)
                {
                    EraseSection((IntPtr)(baseAddressVal + dwpeheader + peheaderwords[i]), 1);
                }
                for (int i = 0; i < peheaderbytes.Count; i++)
                {
                    EraseSection((IntPtr)(baseAddressVal + dwpeheader + peheaderbytes[i]), 2);
                }

                int x = 0;
                int y = 0;

                while (x <= wnumberofsections)
                {
                    if (y == 0)
                    {
                        EraseSection((IntPtr)(baseAddressVal + dwpeheader + 0xFA + (0x28 * x) + 0x20), 2);
                    }

                    y++;

                    if (y == sectiontabledwords.Count)
                    {
                        x++;
                        y = 0;
                    }
                }
            } catch { }
        }
        
        public static void EraseSection(IntPtr address, int size)
        {
            try 
            {
                IntPtr sz = (IntPtr)size;
                IntPtr dwOld = default(IntPtr);
                VirtualProtect(address, sz, (IntPtr)0x40, ref dwOld);
                ZeroMemory(address, sz);
                IntPtr temp = default(IntPtr);
                VirtualProtect(address, sz, dwOld, ref temp);
            } catch { }
        }
    }
}