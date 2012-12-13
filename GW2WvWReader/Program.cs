using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;

namespace GW2WvWReader
{
    class Program
    {
        static void Main(string[] args)
        {
            const string redname = "Isle of Janthir";
            const string bluename = "Sanctum of Rall";
            const string greenname = "Blackgate";
            while (true)
            {
                if (Process.GetProcessesByName("Gw2").Length > 0)
                {
                    //long pointer = 0x06FF5A20;
                    var sigscan = new SigScan(new IntPtr(0x6000000), 0xFFFFFFF);
                    var pointer = sigscan.FindPattern(new byte[]
                                                          {
                                                              0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
                                                              0x03, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00,
                                                              0x02, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 
                                                              0x00, 0x00, 0x00, 0x00, 0x00, 0x5B, 0xFF, 0x06
                                                          },
                                                      "????????xxxxxxxxxxxxxxxx?????xxx", 0).ToInt64();
                    var red = new ServerStat(Function.ReadBytes("gw2", pointer, 32));
                    var blue = new ServerStat(Function.ReadBytes("gw2", pointer + 32, 32));
                    var green = new ServerStat(Function.ReadBytes("gw2", pointer + 64, 32));
                    Console.WriteLine(DateTime.UtcNow);
                    Console.WriteLine("Red: {0}", red);
                    Console.WriteLine("Blue: {0}", blue);
                    Console.WriteLine("Green: {0}", green);
                    var write = new[]
                                    {
                                        ((int)DateTimeToUnixTimestamp(DateTime.UtcNow)).ToString(),
                                        string.Format("{2}|{0}|{1}", red.Score, red.PotentialPoints, redname),
                                        string.Format("{2}|{0}|{1}", blue.Score, blue.PotentialPoints, bluename),
                                        string.Format("{2}|{0}|{1}", green.Score, green.PotentialPoints, greenname)
                                    };
                    File.AppendAllLines("log.txt", write);
                    var client = new WebClient();
                    client.Headers.Add("Content-Type","binary/octet-stream");
                    var result = client.UploadFile("", "log.txt");
                    Console.WriteLine(Encoding.UTF8.GetString(result, 0, result.Length));
                    sigscan.Dispose();
                    sigscan = null;
                    GC.Collect();
                }
                Thread.Sleep(60000);
            }
        }

        public static double DateTimeToUnixTimestamp(DateTime dateTime)
        {
            return (dateTime - new DateTime(1970, 1, 1)).TotalSeconds;
        }
    }

    class ServerStat
    {
        public int Score;
        public int PotentialPoints;
        public int Unknown1;
        public int Unknown2;
        public int Unknown3;
        public int Unknown4;
        public int Unknown5;
        public int Unknown6;

        public ServerStat(byte[] array)
        {
            using (var stream = new MemoryStream(array))
            {
                using (var reader = new BinaryReader(stream))
                {
                    Score = reader.ReadInt32();
                    PotentialPoints = reader.ReadInt32();
                    Unknown1 = reader.ReadInt32();
                    Unknown2 = reader.ReadInt32();
                    Unknown3 = reader.ReadInt32();
                    Unknown4 = reader.ReadInt32();
                    Unknown5 = reader.ReadInt32();
                    Unknown6 = reader.ReadInt32();
                }
            }
        }

        public override string ToString()
        {
            return string.Format("{0} {1} {2} {3} {4} {5} {6} {7}", Score, PotentialPoints, Unknown1, Unknown2, Unknown3,
                                 Unknown4, Unknown5, Unknown6);
        }
    }

    public class Function
    {
        private const int PROCESS_ALL_ACCESS = 0x1F0FFF;
        private static int Handle;

        [DllImport("kernel32")]
        private static extern int OpenProcess(int AccessType, int InheritHandle, int pID);

        [DllImport("user32")]
        private static extern int FindWindow(string sClassName, string sAppName);

        [DllImport("user32")]
        private static extern int GetWindowThreadProcessId(int HWND, out int processId);

        [DllImport("kernel32", EntryPoint = "WriteProcessMemory")]
        private static extern byte WriteProcessMemoryByte(int Handle, int Address, byte[] lpBuffer, uint nSize,
                                                          int BytesWritten = 0);

        [DllImport("kernel32", EntryPoint = "WriteProcessMemory")]
        private static extern float WriteProcessMemoryFloat(int Handle, int Address, ref float Value, int Size,
                                                            int BytesWritten = 0);


        [DllImport("kernel32", EntryPoint = "ReadProcessMemory")]
        private static extern int ReadProcessMemoryInteger(int Handle, int Address, ref int Value, int Size,
                                                           ref int BytesRead);

        [DllImport("kernel32")]
        private static extern int CloseHandle(int Handle);

        [DllImport("kernel32", EntryPoint = "ReadProcessMemory")]
        private static extern byte ReadProcessMemoryByte(int Handle, int Address, ref byte Value, int Size,
                                                         ref int BytesRead);

        [DllImport("kernel32", EntryPoint = "WriteProcessMemory")]
        private static extern float WriteProcessMemoryFloat(int Handle, int Address, ref float Value, int Size,
                                                            ref int BytesWritten);

        [DllImport("kernel32", EntryPoint = "ReadProcessMemory")]
        private static extern float ReadProcessMemoryFloat(int Handle, int Address, ref float Value, int Size,
                                                           ref int BytesRead);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool ReadProcessMemory(
          IntPtr hProcess,
          IntPtr lpBaseAddress,
          [Out] byte[] lpBuffer,
          int dwSize,
          out int lpNumberOfBytesRead
         );

        public static byte[] ReadBytes(string EXENAME, long Pointer, int length)
        {
            try
            {
                Process[] Proc = Process.GetProcessesByName(EXENAME);
                if (Proc.Length != 0)
                {
                    int Handle = OpenProcess(PROCESS_ALL_ACCESS, 0, Proc[0].Id);
                    var array = new byte[length];
                    var read = 0;
                    ReadProcessMemory(new IntPtr(Handle), new IntPtr(Pointer), array, length, out read);
                    return array;
                }
                return new byte[length];
            }
            catch (Exception)
            {
                return new byte[length];
            }
        }

        public static byte ReadPointerByte(string EXENAME, int Pointer, int[] Offset)
        {
            byte Value = 0;
            checked
            {
                try
                {
                    Process[] Proc = Process.GetProcessesByName(EXENAME);
                    if (Proc.Length != 0)
                    {
                        int Bytes = 0;
                        int Handle = OpenProcess(PROCESS_ALL_ACCESS, 0, Proc[0].Id);
                        if (Handle != 0)
                        {
                            foreach (int i in Offset)
                            {
                                ReadProcessMemoryInteger(Handle, Pointer, ref Pointer, 4, ref Bytes);
                                Pointer += i;
                                //Process.Handle 
                            }
                            ReadProcessMemoryByte(Handle, Pointer, ref Value, 2, ref Bytes);
                            CloseHandle(Handle);
                        }
                    }
                }
                catch
                {
                }
            }
            return Value;
        }

        public static int ReadPointerInteger(string EXENAME, int Pointer)
        {
            return ReadPointerInteger(EXENAME, Pointer, new[] {0});
        }
        public static int ReadPointerInteger(string EXENAME, int Pointer, int[] Offset)
        {
            int Value = 0;
            checked
            {
                try
                {
                    Process[] Proc = Process.GetProcessesByName(EXENAME);
                    if (Proc.Length != 0)
                    {
                        int Bytes = 0;
                        int Handle = OpenProcess(PROCESS_ALL_ACCESS, 0, Proc[0].Id);
                        if (Handle != 0)
                        {
                            foreach (int i in Offset)
                            {
                                ReadProcessMemoryInteger(Handle, Pointer, ref Pointer, 4, ref Bytes);
                                Pointer += i;
                            }
                            ReadProcessMemoryInteger(Handle, Pointer, ref Value, 4, ref Bytes);
                            CloseHandle(Handle);
                        }
                    }
                }
                catch
                {
                }
            }
            return Value;
        }

        public static float ReadPointerFloat(string EXENAME, int Pointer, int[] Offset)
        {
            float Value = 0;
            checked
            {
                try
                {
                    Process[] Proc = Process.GetProcessesByName(EXENAME);
                    if (Proc.Length != 0)
                    {
                        int Bytes = 0;
                        int Handle = OpenProcess(PROCESS_ALL_ACCESS, 0, Proc[0].Id);
                        if (Handle != 0)
                        {
                            foreach (int i in Offset)
                            {
                                ReadProcessMemoryInteger(Handle, Pointer, ref Pointer, 4, ref Bytes);
                                Pointer += i;
                            }
#if DEBUG
                            if ((new StackTrace()).GetFrame(2).GetMethod().Name.Contains("Click"))
                                Debug.WriteLine(string.Format("Pointer is at: {0:X8} called by {1}", Pointer, (new StackTrace()).GetFrame(2).GetMethod().Name));
#endif
                            ReadProcessMemoryFloat(Handle, Pointer, ref Value, 4, ref Bytes);
                            CloseHandle(Handle);
                        }
                    }
                }
                catch
                {
                }
            }
            return Value;
        }

        public static void WritePointerFloat(string EXENAME, int Pointer, int[] Offset, float Value)
        {
            checked
            {
                try
                {
                    Process[] Proc = Process.GetProcessesByName(EXENAME);
                    if (Proc.Length != 0)
                    {
                        int Handle = OpenProcess(PROCESS_ALL_ACCESS, 0, Proc[0].Id);
                        if (Handle != 0)
                        {
                            int Bytes = 0;
                            foreach (int i in Offset)
                            {
                                ReadProcessMemoryInteger(Handle, Pointer, ref Pointer, 4, ref Bytes);
                                Pointer += i;
                            }
                            WriteProcessMemoryFloat(Handle, Pointer, ref Value, 4, ref Bytes);
                        }
                        CloseHandle(Handle);
                    }
                }
                catch
                {
                }
            }
        }

        public static int FindProcess() //Find Process
        {
            {
                try
                {
                    if (Handle == 0)
                    {
                        Process[] pID = Process.GetProcessesByName("gw2");
                        if (pID.Length != 1)
                            return 0;
                        Handle = OpenProcess(PROCESS_ALL_ACCESS, 0, pID[0].Id);
                    }
                    return Handle;
                }
                catch (Exception ex)
                {
                    return 0;
                }
            }
        }

        public static void ClearHandle() //Find Process
        {
            Handle = 0;
        }

        public static int FindpID() //Find Process
        {
            int pID;
            int HWND = FindWindow(null, "Guild Wars 2");
            GetWindowThreadProcessId(HWND, out pID);
            return pID;
        }

        public static void WriteByteArray(int Address, uint BytesWritten, byte[] Array) //Write Byte Array
        {
            WriteProcessMemoryByte(FindProcess(), Address, Array, BytesWritten);
        }

        public static void WriteFloat(int Address, float Value)
        {
            WriteProcessMemoryFloat(FindProcess(), Address, ref Value, 4);
        }
    }
}
