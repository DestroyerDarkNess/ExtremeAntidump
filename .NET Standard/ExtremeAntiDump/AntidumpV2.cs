using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Runtime.ExceptionServices;
using System.Runtime.InteropServices;
using System.Runtime.InteropServices.ComTypes;
using System.Threading;
using System.Threading.Tasks;
using dnlib.DotNet;
using dnlib.PE;
using NativeSharp;

namespace Antidump
{

    [AttributeUsage(AttributeTargets.All, Inherited = false, AllowMultiple = false)]
    public class HydraOperator_DontObfuscate : Attribute { }


    [HydraOperator_DontObfuscate]
    public class Dump { }
    public class AntidumpV2 : Dump
    {

        [DllImport("kernel32.dll", CharSet = CharSet.Auto)]
        private static extern IntPtr GetModuleHandle(string lpModuleName);

        // Marshal.GetHINSTANCE(Module m);
        public static IntPtr GetHINSTANCE(Module m)
        {
            if (m == null)
              return IntPtr.Zero;

            string moduleName = m.ScopeName;
            return GetModuleHandle(moduleName);
        }

        public unsafe static void Initialize()
        {

            Module injectedAssembly = Assembly.GetCallingAssembly()?.ManifestModule;
            if (injectedAssembly == null) { injectedAssembly = typeof(AntidumpV2).Module; }
            IntPtr handleModule = GetHINSTANCE(injectedAssembly);
            AntiDumpModule(handleModule, injectedAssembly);

            Thread myThread = new Thread(() => {
                try
                {

                    //System.Threading.Thread.Sleep(3000);
                    Process CurrentProcess = Process.GetCurrentProcess();
                    NativeProcess process = NativeProcess.Open((uint)CurrentProcess.Id, ProcessAccess.MemoryRead | ProcessAccess.QueryInformation);

                    Dictionary<IntPtr, string> Adress = new Dictionary<IntPtr, string>();

                    Parallel.ForEach(process.EnumeratePageInfos(), pageInfo => {
                        try
                        {
                            Console.ForegroundColor = ConsoleColor.White;
                            if (!IsValidPage(pageInfo))
                                return;
                            var page = new byte[Math.Min((int)pageInfo.Size, 0x40000000)];
                            // 0x40000000 bytes = 1 giga bytes
                            if (!process.TryReadBytes(pageInfo.Address, page))
                                return;

                            for (int i = 0; i < page.Length - 0x200; i++)
                            {
                                fixed (byte* p = page)
                                {
                                    if (!MaybePEImage(p + i, page.Length - i))
                                        continue;
                                }

                                var imageLayout = i == 0 ? GetProbableImageLayout(page) : ImageLayout.File;
                                uint baseAddress = (uint)pageInfo.Address + (uint)i;
                                IntPtr baseAddressIntPtr = (IntPtr)(ulong)baseAddress;



                                var peImage = DumpDotNetModule(process, baseAddress, imageLayout, out var fileName);
                                if (peImage is null && i == 0)
                                {
                                    // 也许判断有误，尝试一下另一种格式。如果不是页面起始位置，必须是文件布局。
                                    imageLayout = imageLayout == ImageLayout.File ? ImageLayout.Memory : ImageLayout.File;
                                    peImage = DumpDotNetModule(process, baseAddress, ImageLayout.File, out fileName);
                                }

                                if (peImage is null)
                                    continue;

                                try
                                {
                                    if (BuiltInAssemblyHelper.IsBuiltInAssembly(peImage))
                                        continue;
                                }
                                catch
                                {
                                    continue;
                                }

                                //Console.WriteLine($"Found assembly '{fileName}' at {FormatHex(baseAddress)} and image layout is {imageLayout}");

                                if (Adress.ContainsKey(baseAddressIntPtr) == false) { Adress.Add(baseAddressIntPtr, fileName); }
                            }
                        }
                        catch { }
                    });

                    Console.ForegroundColor = ConsoleColor.White;

                    Module typeofAssembly = typeof(AntidumpV2).Module;
                    Module ExecutingAssembly = Assembly.GetExecutingAssembly()?.ManifestModule;
                    Module CallingAssembly = Assembly.GetCallingAssembly()?.ManifestModule;
                    IntPtr hModule = GetModuleHandle(null);

                    var sortedAddress = Adress.OrderBy(pair => Path.GetExtension(pair.Value).Equals(".exe", StringComparison.OrdinalIgnoreCase)).ToDictionary(pair => pair.Key, pair => pair.Value);

                    ApplyAntiDump(sortedAddress, IntPtr.Zero);

                    Adress.Clear();
                    // Console.WriteLine(Environment.NewLine + "Getting New Address ..." + Environment.NewLine );
                    //if (Adress.ContainsKey(Marshal.GetHINSTANCE(typeofAssembly)) == false) { Adress.Add(Marshal.GetHINSTANCE(typeofAssembly), typeofAssembly.Name); }
                    //if (Adress.ContainsKey(Marshal.GetHINSTANCE(ExecutingAssembly)) == false) { Adress.Add(Marshal.GetHINSTANCE(ExecutingAssembly), ExecutingAssembly.Name); }
                    //if (Adress.ContainsKey(Marshal.GetHINSTANCE(CallingAssembly)) == false) { Adress.Add(Marshal.GetHINSTANCE(CallingAssembly), CallingAssembly.Name); }
                    //if (Adress.ContainsKey(hModule) == false) { Adress.Add(hModule, "ModuleHandle"); }
                    //if (Adress.ContainsKey(CurrentProcess.MainModule.BaseAddress) == false) { Adress.Add(CurrentProcess.MainModule.BaseAddress, CurrentProcess.MainModule.ModuleName); }

                    //ApplyAntiDump(Adress, IntPtr.Zero);


                }
                catch { }
            });

            myThread.Start();
        }

        public static void ApplyAntiDump(Dictionary<IntPtr, string> Adress, IntPtr hModule)
        {
            foreach (var address in Adress)
            {
                try
                {
                    if (hModule == address.Key) continue;

                    if (address.Value.ToLower().EndsWith(".dll")) continue;
                    AntiDumpInMemory(address.Key);
                    //Console.WriteLine("File: " + address.Value + " Adress zero: " + FormatHex((uint)address.Key) + " MainAssembly: " + FormatHex((uint)hModule));

                }
                catch { }
            }
        }

        public static string FormatHex(uint value)
        {
            return sizeof(uint) == 4 ? $"0x{(uint)value:X8}" : $"0x{(ulong)value:X16}";
        }

        private unsafe static bool IsValidPage(PageInfo pageInfo)
        {
            return pageInfo.Protection != 0 && (pageInfo.Protection & NativeSharp.MemoryProtection.NoAccess) == 0 && (ulong)pageInfo.Size <= int.MaxValue;
        }

        [HandleProcessCorruptedStateExceptions]
        private unsafe static bool MaybePEImage(byte* p, int size)
        {
            try
            {
                byte* pEnd = p + size;

                if (*(ushort*)p != 0x5A4D)
                    return false;

                ushort ntHeadersOffset = *(ushort*)(p + 0x3C);
                p += ntHeadersOffset;
                if (p > pEnd - 4)
                    return false;
                if (*(uint*)p != 0x00004550)
                    return false;
                p += 0x04;
                // NT headers Signature

                if (p + 0x10 > pEnd - 2)
                    return false;
                if (*(ushort*)(p + 0x10) == 0)
                    return false;
                p += 0x14;
                // File header SizeOfOptionalHeader

                if (p > pEnd - 2)
                    return false;
                if (*(ushort*)p != 0x010B && *(ushort*)p != 0x020B)
                    return false;
                // Optional header Magic

                return true;
            }
            catch
            {
                return false;
            }
        }

        [HandleProcessCorruptedStateExceptions]
        static ImageLayout GetProbableImageLayout(byte[] firstPage)
        {
            try
            {
                uint imageSize = PEImageDumper.GetImageSize(firstPage, ImageLayout.File);
                // 获取文件格式大小
                var imageLayout = imageSize >= (uint)firstPage.Length ? ImageLayout.Memory : ImageLayout.File;
                // 如果文件格式大小大于页面大小，说明在内存中是内存格式的，反之为文件格式
                // 这种判断不准确，如果文件文件大小小于最小页面大小，判断会出错
                return imageLayout;
            }
            catch
            {
                return ImageLayout.Memory;
            }
        }

        [HandleProcessCorruptedStateExceptions]
        public static byte[] DumpDotNetModule(NativeProcess process, uint address, ImageLayout imageLayout, out string fileName)
        {
            fileName = string.Empty;
            try
            {
                var data = PEImageDumper.Dump(process, address, ref imageLayout);
                if (data is null)
                    return null;

                data = PEImageDumper.ConvertImageLayout(data, imageLayout, ImageLayout.File);
                var peImage = new PEImage(data, true);
                // 确保为有效PE文件
                if (peImage.ImageNTHeaders.OptionalHeader.DataDirectories[14].VirtualAddress == 0)
                    return null;
                try
                {
                    var moduleDef = dnlib.DotNet.ModuleDefMD.Load(peImage);
                    // 再次验证是否为.NET程序集
                    if (moduleDef is null)
                        return null;
                    if (moduleDef.Assembly != null ? moduleDef.Assembly.Name.Length == 0 : moduleDef.Name.Length == 0)
                        return null;
                    if (string.IsNullOrEmpty(fileName))
                        fileName = moduleDef.Assembly != null ? (moduleDef.Assembly.Name.ToString() + (moduleDef.EntryPoint is null ? ".dll" : ".exe")) : moduleDef.Name.ToString();

                    moduleDef.Dispose();
                }
                catch
                {
                    return null;
                }
                if (string.IsNullOrEmpty(fileName))
                    fileName = address.ToString();

                peImage.Dispose();
                return data;
            }
            catch
            {
                return null;
            }
        }

        #region "Erase PE Header"

        [System.Runtime.InteropServices.DllImport("kernel32.dll")]
        public static extern IntPtr ZeroMemory(IntPtr addr, IntPtr size);

        [System.Runtime.InteropServices.DllImport("kernel32.dll")]
        public static extern IntPtr VirtualProtect(IntPtr lpAddress, IntPtr dwSize, IntPtr flNewProtect, ref IntPtr lpflOldProtect);

        public static bool EraseHeader(IntPtr base_address)
        {
            try
            {
                if (base_address == IntPtr.Zero || (long)base_address == -1) { return false; }

                List<int> sectiontabledwords = new List<int>() { 0x8, 0xC, 0x10, 0x14, 0x18, 0x1C, 0x24 };
                List<int> peheaderbytes = new List<int>() { 0x1A, 0x1B };
                List<int> peheaderwords = new List<int>() { 0x4, 0x16, 0x18, 0x40, 0x42, 0x44, 0x46, 0x48, 0x4A, 0x4C, 0x5C, 0x5E };
                List<int> peheaderdwords = new List<int>() { 0x0, 0x8, 0xC, 0x10, 0x16, 0x1C, 0x20, 0x28, 0x2C, 0x34, 0x3C, 0x4C, 0x50, 0x54, 0x58, 0x60, 0x64, 0x68, 0x6C, 0x70, 0x74, 0x104, 0x108, 0x10C, 0x110, 0x114, 0x11C };

                long baseAddr = base_address.ToInt64();
                int dwpeheader = 0;
                int wnumberofsections = 0;

                try
                {
                    dwpeheader = System.Runtime.InteropServices.Marshal.ReadInt32((IntPtr)(baseAddr + 0x3C));
                    wnumberofsections = System.Runtime.InteropServices.Marshal.ReadInt16((IntPtr)(baseAddr + dwpeheader + 0x6));
                }
                catch { }

                for (int i = 0; i < peheaderwords.Count; i++)
                {
                    EraseSection((IntPtr)(baseAddr + dwpeheader + peheaderwords[i]), 2);
                }
                for (int i = 0; i < peheaderbytes.Count; i++)
                {
                    EraseSection((IntPtr)(baseAddr + dwpeheader + peheaderbytes[i]), 1);
                }

                int x = 0;
                int y = 0;

                while (x <= wnumberofsections)
                {
                    if (y == 0)
                    {
                        EraseSection((IntPtr)((baseAddr + dwpeheader + 0xFA + (0x28 * x)) + 0x20), 2);
                    }

                    y++;

                    if (y == sectiontabledwords.Count)
                    {
                        x++;
                        y = 0;
                    }
                }
                return true;
            }
            catch { return false; }
        }

        private static void EraseSection(IntPtr address, int size)
        {
            try
            {
                IntPtr sz = (IntPtr)size;
                IntPtr dwOld = default(IntPtr);
                VirtualProtect(address, sz, (IntPtr)0x40, ref dwOld);
                ZeroMemory(address, sz);
                IntPtr temp = default(IntPtr);
                VirtualProtect(address, sz, dwOld, ref temp);
            }
            catch { }
        }

        #endregion

        #region " AntiDump From Module "

        private enum MemoryProtection
        {
            ExecuteReadWrite = 0x40,
        }

        private static unsafe void CopyBlock(void* destination, void* source, uint byteCount) { }

        private static unsafe void InitBlock(void* startAddress, byte value, uint byteCount) { }

        [DllImport("kernel32.dll")]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool VirtualProtect(
                IntPtr lpAddress,
                uint dwSize,
                [MarshalAs(UnmanagedType.U4)] MemoryProtection flNewProtect,
                [MarshalAs(UnmanagedType.U4)] out MemoryProtection lpflOldProtect);

        private static unsafe void AntiDumpModule(IntPtr hModule, Module injectedAssembly)
        {
            try
            {
                var module = injectedAssembly;
                var bas = (byte*)hModule;
                var ptr = bas + 0x3c;
                ptr = bas + *(uint*)ptr;
                ptr += 0x6;
                var sectNum = *(ushort*)ptr;
                ptr += 14;
                var optSize = *(ushort*)ptr;
                ptr = ptr + 0x4 + optSize;
                var @new = stackalloc byte[11];
                MemoryProtection _;
                if (module.FullyQualifiedName[0] != '<')
                {
                    var mdDir = bas + *(uint*)(ptr - 16);
                    if (*(uint*)(ptr - 0x78) != 0)
                    {
                        var importDir = bas + *(uint*)(ptr - 0x78);
                        var oftMod = bas + *(uint*)importDir;
                        var modName = bas + *(uint*)(importDir + 12);
                        var funcName = bas + *(uint*)oftMod + 2;
                        VirtualProtect(new IntPtr(modName), 11, MemoryProtection.ExecuteReadWrite, out _);
                        *(uint*)@new = 0x6c64746e;
                        *((uint*)@new + 1) = 0x6c642e6c;
                        *((ushort*)@new + 4) = 0x006c;
                        *(@new + 10) = 0;
                        CopyBlock(modName, @new, 11);
                        VirtualProtect(new IntPtr(funcName), 11, MemoryProtection.ExecuteReadWrite, out _);
                        *(uint*)@new = 0x6f43744e;
                        *((uint*)@new + 1) = 0x6e69746e;
                        *((ushort*)@new + 4) = 0x6575;
                        *(@new + 10) = 0;
                        CopyBlock(funcName, @new, 11);
                    }

                    for (var i = 0; i < sectNum; i++)
                    {
                        VirtualProtect(new IntPtr(ptr), 8, MemoryProtection.ExecuteReadWrite, out _);
                        InitBlock(ptr, 0, 8);
                        ptr += 0x28;
                    }

                    VirtualProtect(new IntPtr(mdDir), 0x48, MemoryProtection.ExecuteReadWrite, out _);
                    var mdHdr = bas + *(uint*)(mdDir + 8);
                    InitBlock(mdDir, 0, 16);
                    VirtualProtect(new IntPtr(mdHdr), 4, MemoryProtection.ExecuteReadWrite, out _);
                    *(uint*)mdHdr = 0;
                    mdHdr += 12;
                    mdHdr += *(uint*)mdHdr;
                    mdHdr = (byte*)(((ulong)mdHdr + 7) & ~3UL);
                    mdHdr += 2;
                    ushort numOfStream = *mdHdr;
                    mdHdr += 2;
                    for (var i = 0; i < numOfStream; i++)
                    {
                        VirtualProtect(new IntPtr(mdHdr), 8, MemoryProtection.ExecuteReadWrite, out _);
                        mdHdr += 4;
                        mdHdr += 4;
                        for (var ii = 0; ii < 8; ii++)
                        {
                            VirtualProtect(new IntPtr(mdHdr), 4, MemoryProtection.ExecuteReadWrite, out _);
                            *mdHdr = 0;
                            mdHdr++;
                            if (*mdHdr == 0)
                            {
                                mdHdr += 3;
                                break;
                            }
                            *mdHdr = 0;
                            mdHdr++;
                            if (*mdHdr == 0)
                            {
                                mdHdr += 2;
                                break;
                            }
                            *mdHdr = 0;
                            mdHdr++;
                            if (*mdHdr == 0)
                            {
                                mdHdr += 1;
                                break;
                            }
                            *mdHdr = 0;
                            mdHdr++;
                        }
                    }
                }
                else
                {
                    ZeroAdress(hModule);
                }

            }
            catch { }

        }

        public unsafe static void ZeroAdress(IntPtr hModule)
        {
            var bas = (byte*)hModule;
            var ptr = bas + 0x3c;
            ptr = bas + *(uint*)ptr;
            ptr += 0x6;
            var sectNum = *(ushort*)ptr;
            ptr += 14;
            var optSize = *(ushort*)ptr;
            ptr = ptr + 0x4 + optSize;
            var @new = stackalloc byte[11];
            MemoryProtection _;

            var mdDir = *(uint*)(ptr - 16);
            var importDir = *(uint*)(ptr - 0x78);

            var vAdrs = new uint[sectNum];
            var vSizes = new uint[sectNum];
            var rAdrs = new uint[sectNum];
            for (var i = 0; i < sectNum; i++)
            {
                VirtualProtect(new IntPtr(ptr), 8, MemoryProtection.ExecuteReadWrite, out _);
                Marshal.Copy(new byte[8], 0, (IntPtr)ptr, 8);
                vAdrs[i] = *(uint*)(ptr + 12);
                vSizes[i] = *(uint*)(ptr + 8);
                rAdrs[i] = *(uint*)(ptr + 20);
                ptr += 0x28;
            }

            if (importDir != 0)
            {
                for (var i = 0; i < sectNum; i++)
                    if (vAdrs[i] <= importDir && importDir < vAdrs[i] + vSizes[i])
                    {
                        importDir = importDir - vAdrs[i] + rAdrs[i];
                        break;
                    }

                var importDirPtr = bas + importDir;
                var oftMod = *(uint*)importDirPtr;
                for (var i = 0; i < sectNum; i++)
                    if (vAdrs[i] <= oftMod && oftMod < vAdrs[i] + vSizes[i])
                    {
                        oftMod = oftMod - vAdrs[i] + rAdrs[i];
                        break;
                    }

                var oftModPtr = bas + oftMod;
                var modName = *(uint*)(importDirPtr + 12);
                for (var i = 0; i < sectNum; i++)
                    if (vAdrs[i] <= modName && modName < vAdrs[i] + vSizes[i])
                    {
                        modName = modName - vAdrs[i] + rAdrs[i];
                        break;
                    }

                var funcName = *(uint*)oftModPtr + 2;
                for (var i = 0; i < sectNum; i++)
                    if (vAdrs[i] <= funcName && funcName < vAdrs[i] + vSizes[i])
                    {
                        funcName = funcName - vAdrs[i] + rAdrs[i];
                        break;
                    }

                VirtualProtect(new IntPtr(bas + modName), 11, MemoryProtection.ExecuteReadWrite, out _);

                *(uint*)@new = 0x6c64746e;
                *((uint*)@new + 1) = 0x6c642e6c;
                *((ushort*)@new + 4) = 0x006c;
                *(@new + 10) = 0;

                CopyBlock(bas + modName, @new, 11);

                VirtualProtect(new IntPtr(bas + funcName), 11, MemoryProtection.ExecuteReadWrite, out _);

                *(uint*)@new = 0x6f43744e;
                *((uint*)@new + 1) = 0x6e69746e;
                *((ushort*)@new + 4) = 0x6575;
                *(@new + 10) = 0;

                CopyBlock(bas + funcName, @new, 11);
            }

            for (var i = 0; i < sectNum; i++)
                if (vAdrs[i] <= mdDir && mdDir < vAdrs[i] + vSizes[i])
                {
                    mdDir = mdDir - vAdrs[i] + rAdrs[i];
                    break;
                }

            var mdDirPtr = bas + mdDir;
            VirtualProtect(new IntPtr(mdDirPtr), 0x48, MemoryProtection.ExecuteReadWrite, out _);
            var mdHdr = *(uint*)(mdDirPtr + 8);
            for (var i = 0; i < sectNum; i++)
                if (vAdrs[i] <= mdHdr && mdHdr < vAdrs[i] + vSizes[i])
                {
                    mdHdr = mdHdr - vAdrs[i] + rAdrs[i];
                    break;
                }

            InitBlock(mdDirPtr, 0, 16);

            var mdHdrPtr = bas + mdHdr;
            VirtualProtect(new IntPtr(mdHdrPtr), 4, MemoryProtection.ExecuteReadWrite, out _);
            *(uint*)mdHdrPtr = 0;
            mdHdrPtr += 12;
            mdHdrPtr += *(uint*)mdHdrPtr;
            mdHdrPtr = (byte*)(((ulong)mdHdrPtr + 7) & ~3UL);
            mdHdrPtr += 2;
            ushort numOfStream = *mdHdrPtr;
            mdHdrPtr += 2;
            for (var i = 0; i < numOfStream; i++)
            {
                VirtualProtect(new IntPtr(mdHdrPtr), 8, MemoryProtection.ExecuteReadWrite, out _);
                mdHdrPtr += 4;
                mdHdrPtr += 4;
                for (var ii = 0; ii < 8; ii++)
                {
                    VirtualProtect(new IntPtr(mdHdrPtr), 4, MemoryProtection.ExecuteReadWrite, out _);
                    *mdHdrPtr = 0;
                    mdHdrPtr++;
                    if (*mdHdrPtr == 0)
                    {
                        mdHdrPtr += 3;
                        break;
                    }

                    *mdHdrPtr = 0;
                    mdHdrPtr++;
                    if (*mdHdrPtr == 0)
                    {
                        mdHdrPtr += 2;
                        break;
                    }

                    *mdHdrPtr = 0;
                    mdHdrPtr++;
                    if (*mdHdrPtr == 0)
                    {
                        mdHdrPtr += 1;
                        break;
                    }

                    *mdHdrPtr = 0;
                    mdHdrPtr++;
                }
            }
        }

        #endregion

        #region " AntiDumpInMemory "

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, UIntPtr nSize, out UIntPtr lpNumberOfBytesWritten);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, uint dwProcessId);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CloseHandle(IntPtr hObject);

        private const uint PROCESS_VM_WRITE = 0x0020;
        private const uint PROCESS_VM_OPERATION = 0x0008;

        private static bool AntiDumpInMemory(IntPtr myMod)
        {
            if (myMod == IntPtr.Zero)
            {
                return false;
            }

            uint processId = (uint)Process.GetCurrentProcess().Id;
            IntPtr hProcess = OpenProcess(PROCESS_VM_WRITE | PROCESS_VM_OPERATION, false, processId);

            if (hProcess == IntPtr.Zero)
            {
                return false;
            }

            UIntPtr size = (UIntPtr)(IntPtr.Size == 8 ? 0x1000UL : 0x1000U);
            UIntPtr zeroBytesSize = (UIntPtr)(IntPtr.Size == 8 ? 8UL : 4U);
            byte[] zeroBytes = new byte[IntPtr.Size];

            // Change the protection of the memory to make it writable
            if (!VirtualProtect(myMod, size, 0x40, out uint oldProtect))
            {
                CloseHandle(hProcess);
                return false;
            }

            // Erase MS-DOS Header
            if (!WriteProcessMemory(hProcess, myMod, zeroBytes, zeroBytesSize, out _))
            {
                VirtualProtect(myMod, size, oldProtect, out _);
                CloseHandle(hProcess);
                return false;
            }

            // Erase PE Header offset
            if (!WriteProcessMemory(hProcess, myMod + 0x3C, zeroBytes, zeroBytesSize, out _))
            {
                VirtualProtect(myMod, size, oldProtect, out _);
                CloseHandle(hProcess);
                return false;
            }

            // Restore the original protection
            if (!VirtualProtect(myMod, size, oldProtect, out _))
            {
                CloseHandle(hProcess);
                return false;
            }

            CloseHandle(hProcess);

            return true;
        }

        #endregion

        #region " PE Image Dumpper "

        static unsafe class PEImageDumper
        {
            /// <summary>
            /// 直接从内存中复制模块，不执行格式转换操作
            /// </summary>
            /// <param name="processId"></param>
            /// <param name="address"></param>
            /// <param name="imageLayout"></param>
            /// <returns></returns>
            public static byte[] Dump(uint processId, uint address, ref ImageLayout imageLayout)
            {
                if (processId == 0)
                    throw new ArgumentNullException(nameof(processId));
                if (address == 0)
                    throw new ArgumentNullException(nameof(address));

                var process = NativeProcess.Open(processId);
                byte[] DumpBytes = Dump(process, address, ref imageLayout);
                process.Dispose();
                return DumpBytes;
            }

            /// <summary>
            /// 直接从内存中复制模块，不执行格式转换操作
            /// </summary>
            /// <param name="process"></param>
            /// <param name="address"></param>
            /// <param name="imageLayout"></param>
            /// <returns></returns>
            public static byte[] Dump(NativeProcess process, uint address, ref ImageLayout imageLayout)
            {
                var pageInfos = process.EnumeratePageInfos((void*)address, (void*)address).ToArray();
                if (pageInfos.Length == 0)
                    return null;

                var firstPageInfo = pageInfos[0];
                if (!IsValidPage(firstPageInfo))
                    return null;
                // 判断内存页是否有效

                bool atPageHeader = address == (uint)firstPageInfo.Address;
                if (!atPageHeader)
                    imageLayout = ImageLayout.File;
                // 如果不在内存页头部，只可能是文件布局

                var peHeader = new byte[(int)((byte*)firstPageInfo.Address + (int)firstPageInfo.Size - (byte*)address)];
                process.ReadBytes((void*)address, peHeader);
                uint imageSize = GetImageSize(peHeader, imageLayout);
                // 获取模块在内存中的大小

                var peImage = new byte[imageSize];
                switch (imageLayout)
                {
                    case ImageLayout.File:
                        if (!process.TryReadBytes((void*)address, peImage, 0, imageSize))
                            return null;
                        break;
                    case ImageLayout.Memory:
                        pageInfos = process.EnumeratePageInfos((void*)address, (byte*)address + imageSize).Where(t => IsValidPage(t)).ToArray();
                        if (pageInfos.Length == 0)
                            return null;

                        foreach (var pageInfo in pageInfos)
                        {
                            uint offset = (uint)((ulong)pageInfo.Address - address);
                            if (!process.TryReadBytes(pageInfo.Address, peImage, offset, (uint)pageInfo.Size))
                                return null;
                        }
                        break;
                    default:
                        throw new NotSupportedException();
                }
                // 转储

                return peImage;
            }

            static bool IsValidPage(PageInfo pageInfo)
            {
                return pageInfo.Protection != 0 && (pageInfo.Protection & NativeSharp.MemoryProtection.NoAccess) == 0 && (ulong)pageInfo.Size <= int.MaxValue;
            }

            /// <summary>
            /// 转换模块布局
            /// </summary>
            /// <param name="peImage"></param>
            /// <param name="fromImageLayout"></param>
            /// <param name="toImageLayout"></param>
            /// <returns></returns>
            public static byte[] ConvertImageLayout(byte[] peImage, ImageLayout fromImageLayout, ImageLayout toImageLayout)
            {
                switch (fromImageLayout)
                {
                    case ImageLayout.File:
                    case ImageLayout.Memory:
                        break;
                    default:
                        throw new ArgumentOutOfRangeException(nameof(fromImageLayout));
                }
                switch (toImageLayout)
                {
                    case ImageLayout.File:
                    case ImageLayout.Memory:
                        break;
                    default:
                        throw new ArgumentOutOfRangeException(nameof(toImageLayout));
                }
                if (peImage is null)
                    throw new ArgumentNullException(nameof(peImage));

                if (fromImageLayout == toImageLayout)
                    return peImage;
                var newPEImageData = new byte[GetImageSize(peImage, toImageLayout)];
                var peHeader = new PEImage(peImage, false);
                Buffer.BlockCopy(peImage, 0, newPEImageData, 0, (int)peHeader.ImageSectionHeaders.Last().EndOffset);
                // 复制PE头
                foreach (var sectionHeader in peHeader.ImageSectionHeaders)
                {
                    switch (toImageLayout)
                    {
                        case ImageLayout.File:
                            // ImageLayout.Memory -> ImageLayout.File
                            Buffer.BlockCopy(peImage, (int)sectionHeader.VirtualAddress, newPEImageData, (int)sectionHeader.PointerToRawData, (int)sectionHeader.SizeOfRawData);
                            break;
                        case ImageLayout.Memory:
                            // ImageLayout.File -> ImageLayout.Memory
                            Buffer.BlockCopy(peImage, (int)sectionHeader.PointerToRawData, newPEImageData, (int)sectionHeader.VirtualAddress, (int)sectionHeader.SizeOfRawData);
                            break;
                        default:
                            throw new NotSupportedException();
                    }
                }
                peHeader.Dispose();
                return newPEImageData;
            }

            /// <summary>
            /// 获取模块大小
            /// </summary>
            /// <param name="peHeader"></param>
            /// <param name="imageLayout"></param>
            /// <returns></returns>
            public static uint GetImageSize(byte[] peHeader, ImageLayout imageLayout)
            {
                if (peHeader is null)
                    throw new ArgumentNullException(nameof(peHeader));

                var peImage = new PEImage(peHeader, false);
                uint Result = GetImageSize(peImage, imageLayout);
                peImage.Dispose();
                return Result;
                // PEImage构造器中的imageLayout参数无关紧要，因为只需要解析PEHeader
            }

            /// <summary>
            /// 获取模块大小
            /// </summary>
            /// <param name="peHeader"></param>
            /// <param name="imageLayout"></param>
            /// <returns></returns>
            public static uint GetImageSize(PEImage peHeader, ImageLayout imageLayout)
            {
                var lastSectionHeader = peHeader.ImageSectionHeaders.Last();
                uint alignment;
                uint imageSize;
                switch (imageLayout)
                {
                    case ImageLayout.File:
                        alignment = peHeader.ImageNTHeaders.OptionalHeader.FileAlignment;
                        imageSize = lastSectionHeader.PointerToRawData + lastSectionHeader.SizeOfRawData;
                        break;
                    case ImageLayout.Memory:
                        alignment = peHeader.ImageNTHeaders.OptionalHeader.SectionAlignment;
                        imageSize = (uint)lastSectionHeader.VirtualAddress + lastSectionHeader.VirtualSize;
                        break;
                    default:
                        throw new NotSupportedException();
                }
                if (imageSize % alignment != 0)
                    imageSize = imageSize - (imageSize % alignment) + alignment;
                return imageSize;
            }
        }


        #endregion

        #region " AssemblyCheck "
        public static class BuiltInAssemblyHelper
        {
            public static HashSet<string> FullNames { get; } = new HashSet<string>(StringComparer.OrdinalIgnoreCase) {
        "Accessibility, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a",
        "Accessibility, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a",
        "AddInProcess, Version=3.5.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089",
        "AddInProcess32, Version=3.5.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089",
        "AddInUtil, Version=3.5.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089",
        "ComSvcConfig, Version=3.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a",
        "CustomMarshalers, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a",
        "CustomMarshalers, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a",
        "DataSvcUtil, Version=3.5.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089",
        "EdmGen, Version=3.5.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089",
        "infocard, Version=3.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089",
        "ISymWrapper, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a",
        "ISymWrapper, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a",
        "Microsoft.Activities.Build, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35",
        "Microsoft.Build, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a",
        "Microsoft.Build.Conversion.v3.5, Version=3.5.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a",
        "Microsoft.Build.Conversion.v4.0, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a",
        "Microsoft.Build.Engine, Version=3.5.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a",
        "Microsoft.Build.Engine, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a",
        "Microsoft.Build.Framework, Version=3.5.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a",
        "Microsoft.Build.Framework, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a",
        "Microsoft.Build.Tasks.v3.5, Version=3.5.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a",
        "Microsoft.Build.Tasks.v4.0, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a",
        "Microsoft.Build.Utilities.v3.5, Version=3.5.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a",
        "Microsoft.Build.Utilities.v4.0, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a",
        "Microsoft.CSharp, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a",
        "Microsoft.Data.Entity.Build.Tasks, Version=3.5.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a",
        "Microsoft.JScript, Version=10.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a",
        "Microsoft.JScript, Version=8.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a",
        "Microsoft.Transactions.Bridge, Version=3.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a",
        "Microsoft.Transactions.Bridge.Dtc, Version=3.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a",
        "Microsoft.VisualBasic, Version=10.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a",
        "Microsoft.VisualBasic, Version=8.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a",
        "Microsoft.VisualBasic.Compatibility, Version=10.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a",
        "Microsoft.VisualBasic.Compatibility.Data, Version=10.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a",
        "Microsoft.VisualC, Version=10.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a",
        "Microsoft.VisualC, Version=8.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a",
        "Microsoft.VisualC.STLCLR, Version=1.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a",
        "Microsoft.VisualC.STLCLR, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a",
        "Microsoft.Vsa, Version=8.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a",
        "Microsoft.Win32.Primitives, Version=4.0.3.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a",
        "MSBuild, Version=3.5.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a",
        "mscorlib, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089",
        "mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089",
        "netstandard, Version=2.0.0.0, Culture=neutral, PublicKeyToken=cc7b13ffcd2ddd51",
        "PresentationBuildTasks, Version=3.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35",
        "PresentationBuildTasks, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35",
        "PresentationCFFRasterizer, Version=3.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35",
        "PresentationCore, Version=3.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35",
        "PresentationCore, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35",
        "PresentationFramework, Version=3.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35",
        "PresentationFramework, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35",
        "PresentationFramework.Aero, Version=3.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35",
        "PresentationFramework.Aero, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35",
        "PresentationFramework.Aero2, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35",
        "PresentationFramework.AeroLite, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35",
        "PresentationFramework.Classic, Version=3.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35",
        "PresentationFramework.Classic, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35",
        "PresentationFramework.Luna, Version=3.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35",
        "PresentationFramework.Luna, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35",
        "PresentationFramework.Royale, Version=3.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35",
        "PresentationFramework.Royale, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35",
        "PresentationUI, Version=3.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35",
        "ReachFramework, Version=3.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35",
        "ReachFramework, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35",
        "Sentinel.v3.5Client, Version=3.5.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a",
        "ServiceModelReg, Version=3.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a",
        "SMSvcHost, Version=3.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a",
        "sysglobl, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a",
        "System, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089",
        "System, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089",
        "System.Activities, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35",
        "System.Activities.Core.Presentation, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35",
        "System.Activities.DurableInstancing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35",
        "System.Activities.Presentation, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35",
        "System.Activities.Statements, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35",
        "System.AddIn, Version=3.5.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089",
        "System.AddIn, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089",
        "System.AddIn.Contract, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a",
        "System.AddIn.Contract, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a",
        "System.AppContext, Version=4.1.2.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a",
        "System.Collections, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a",
        "System.Collections, Version=4.0.10.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a",
        "System.Collections, Version=4.0.11.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a",
        "System.Collections.Concurrent, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a",
        "System.Collections.Concurrent, Version=4.0.10.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a",
        "System.Collections.Concurrent, Version=4.0.11.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a",
        "System.Collections.NonGeneric, Version=4.0.3.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a",
        "System.Collections.Specialized, Version=4.0.3.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a",
        "System.ComponentModel, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a",
        "System.ComponentModel, Version=4.0.1.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a",
        "System.ComponentModel.Annotations, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a",
        "System.ComponentModel.Annotations, Version=4.0.10.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a",
        "System.ComponentModel.Composition, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089",
        "System.ComponentModel.Composition.Registration, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089",
        "System.ComponentModel.DataAnnotations, Version=3.5.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35",
        "System.ComponentModel.DataAnnotations, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35",
        "System.ComponentModel.EventBasedAsync, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a",
        "System.ComponentModel.EventBasedAsync, Version=4.0.10.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a",
        "System.ComponentModel.EventBasedAsync, Version=4.0.11.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a",
        "System.ComponentModel.Primitives, Version=4.1.2.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a",
        "System.ComponentModel.TypeConverter, Version=4.1.2.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a",
        "System.Configuration, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a",
        "System.Configuration, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a",
        "System.Configuration.Install, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a",
        "System.Configuration.Install, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a",
        "System.Console, Version=4.0.2.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a",
        "System.Core, Version=3.5.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089",
        "System.Core, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089",
        "System.Data, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089",
        "System.Data, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089",
        "System.Data.Common, Version=4.1.2.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a",
        "System.Data.Common, Version=4.2.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a",
        "System.Data.DataSetExtensions, Version=3.5.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089",
        "System.Data.DataSetExtensions, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089",
        "System.Data.Entity, Version=3.5.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089",
        "System.Data.Entity, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089",
        "System.Data.Entity.Design, Version=3.5.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089",
        "System.Data.Entity.Design, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089",
        "System.Data.Linq, Version=3.5.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089",
        "System.Data.Linq, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089",
        "System.Data.OracleClient, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089",
        "System.Data.Services, Version=3.5.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089",
        "System.Data.Services, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089",
        "System.Data.Services.Client, Version=3.5.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089",
        "System.Data.Services.Client, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089",
        "System.Data.Services.Design, Version=3.5.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089",
        "System.Data.Services.Design, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089",
        "System.Data.SqlXml, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089",
        "System.Data.SqlXml, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089",
        "System.Deployment, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a",
        "System.Deployment, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a",
        "System.Design, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a",
        "System.Device, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089",
        "System.Diagnostics.Contracts, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a",
        "System.Diagnostics.Contracts, Version=4.0.1.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a",
        "System.Diagnostics.Debug, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a",
        "System.Diagnostics.Debug, Version=4.0.10.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a",
        "System.Diagnostics.Debug, Version=4.0.11.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a",
        "System.Diagnostics.FileVersionInfo, Version=4.0.2.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a",
        "System.Diagnostics.Process, Version=4.1.2.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a",
        "System.Diagnostics.StackTrace, Version=4.0.4.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a",
        "System.Diagnostics.StackTrace, Version=4.1.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a",
        "System.Diagnostics.TextWriterTraceListener, Version=4.0.2.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a",
        "System.Diagnostics.Tools, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a",
        "System.Diagnostics.Tools, Version=4.0.1.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a",
        "System.Diagnostics.TraceSource, Version=4.0.2.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a",
        "System.Diagnostics.Tracing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a",
        "System.Diagnostics.Tracing, Version=4.0.10.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a",
        "System.Diagnostics.Tracing, Version=4.0.20.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a",
        "System.Diagnostics.Tracing, Version=4.1.2.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a",
        "System.Diagnostics.Tracing, Version=4.2.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a",
        "System.DirectoryServices, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a",
        "System.DirectoryServices, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a",
        "System.DirectoryServices.AccountManagement, Version=3.5.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089",
        "System.DirectoryServices.AccountManagement, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089",
        "System.DirectoryServices.Protocols, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a",
        "System.Drawing, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a",
        "System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a",
        "System.Drawing.Design, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a",
        "System.Drawing.Primitives, Version=4.0.2.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a",
        "System.Dynamic, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a",
        "System.Dynamic.Runtime, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a",
        "System.Dynamic.Runtime, Version=4.0.10.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a",
        "System.Dynamic.Runtime, Version=4.0.11.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a",
        "System.EnterpriseServices, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a",
        "System.EnterpriseServices, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a",
        "System.Globalization, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a",
        "System.Globalization, Version=4.0.10.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a",
        "System.Globalization, Version=4.0.11.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a",
        "System.Globalization.Calendars, Version=4.0.3.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a",
        "System.Globalization.Extensions, Version=4.0.3.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a",
        "System.Globalization.Extensions, Version=4.1.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a",
        "System.IdentityModel, Version=3.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089",
        "System.IdentityModel, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089",
        "System.IdentityModel.Selectors, Version=3.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089",
        "System.IdentityModel.Selectors, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089",
        "System.IdentityModel.Services, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089",
        "System.IO, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a",
        "System.IO, Version=4.0.10.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a",
        "System.IO, Version=4.1.2.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a",
        "System.IO.Compression, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089",
        "System.IO.Compression, Version=4.2.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089",
        "System.IO.Compression.FileSystem, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089",
        "System.IO.Compression.ZipFile, Version=4.0.3.0, Culture=neutral, PublicKeyToken=b77a5c561934e089",
        "System.IO.FileSystem, Version=4.0.3.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a",
        "System.IO.FileSystem.DriveInfo, Version=4.0.2.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a",
        "System.IO.FileSystem.Primitives, Version=4.0.3.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a",
        "System.IO.FileSystem.Watcher, Version=4.0.2.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a",
        "System.IO.IsolatedStorage, Version=4.0.2.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a",
        "System.IO.Log, Version=3.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a",
        "System.IO.Log, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a",
        "System.IO.MemoryMappedFiles, Version=4.0.2.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a",
        "System.IO.Pipes, Version=4.0.2.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a",
        "System.IO.UnmanagedMemoryStream, Version=4.0.3.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a",
        "System.Linq, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a",
        "System.Linq, Version=4.1.2.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a",
        "System.Linq.Expressions, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a",
        "System.Linq.Expressions, Version=4.0.10.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a",
        "System.Linq.Expressions, Version=4.1.2.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a",
        "System.Linq.Parallel, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a",
        "System.Linq.Parallel, Version=4.0.1.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a",
        "System.Linq.Queryable, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a",
        "System.Linq.Queryable, Version=4.0.1.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a",
        "System.Management, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a",
        "System.Management, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a",
        "System.Management.Instrumentation, Version=3.5.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089",
        "System.Management.Instrumentation, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089",
        "System.Messaging, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a",
        "System.Messaging, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a",
        "System.Net, Version=3.5.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a",
        "System.Net, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a",
        "System.Net.Http, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a",
        "System.Net.Http, Version=4.2.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a",
        "System.Net.Http.Rtc, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a",
        "System.Net.Http.WebRequest, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a",
        "System.Net.NameResolution, Version=4.0.2.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a",
        "System.Net.NetworkInformation, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a",
        "System.Net.NetworkInformation, Version=4.0.10.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a",
        "System.Net.NetworkInformation, Version=4.1.2.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a",
        "System.Net.Ping, Version=4.0.2.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a",
        "System.Net.Primitives, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a",
        "System.Net.Primitives, Version=4.0.10.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a",
        "System.Net.Primitives, Version=4.0.11.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a",
        "System.Net.Requests, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a",
        "System.Net.Requests, Version=4.0.10.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a",
        "System.Net.Requests, Version=4.0.11.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a",
        "System.Net.Security, Version=4.0.2.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a",
        "System.Net.Sockets, Version=4.1.2.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a",
        "System.Net.Sockets, Version=4.2.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a",
        "System.Net.WebHeaderCollection, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a",
        "System.Net.WebHeaderCollection, Version=4.0.1.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a",
        "System.Net.WebSockets, Version=4.0.2.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a",
        "System.Net.WebSockets.Client, Version=4.0.2.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a",
        "System.Numerics, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089",
        "System.Numerics.Vectors, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a",
        "System.ObjectModel, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a",
        "System.ObjectModel, Version=4.0.10.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a",
        "System.ObjectModel, Version=4.0.11.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a",
        "System.Printing, Version=3.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35",
        "System.Printing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35",
        "System.Reflection, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a",
        "System.Reflection, Version=4.0.10.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a",
        "System.Reflection, Version=4.1.2.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a",
        "System.Reflection.Context, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089",
        "System.Reflection.Emit, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a",
        "System.Reflection.Emit.ILGeneration, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a",
        "System.Reflection.Emit.Lightweight, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a",
        "System.Reflection.Extensions, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a",
        "System.Reflection.Extensions, Version=4.0.1.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a",
        "System.Reflection.Primitives, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a",
        "System.Reflection.Primitives, Version=4.0.1.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a",
        "System.Resources.Reader, Version=4.0.2.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a",
        "System.Resources.ResourceManager, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a",
        "System.Resources.ResourceManager, Version=4.0.1.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a",
        "System.Resources.Writer, Version=4.0.2.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a",
        "System.Runtime, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a",
        "System.Runtime, Version=4.0.10.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a",
        "System.Runtime, Version=4.0.20.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a",
        "System.Runtime, Version=4.1.2.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a",
        "System.Runtime.Caching, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a",
        "System.Runtime.CompilerServices.VisualC, Version=4.0.2.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a",
        "System.Runtime.DurableInstancing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35",
        "System.Runtime.Extensions, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a",
        "System.Runtime.Extensions, Version=4.0.10.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a",
        "System.Runtime.Extensions, Version=4.1.2.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a",
        "System.Runtime.Handles, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a",
        "System.Runtime.Handles, Version=4.0.1.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a",
        "System.Runtime.InteropServices, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a",
        "System.Runtime.InteropServices, Version=4.0.10.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a",
        "System.Runtime.InteropServices, Version=4.0.20.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a",
        "System.Runtime.InteropServices, Version=4.1.2.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a",
        "System.Runtime.InteropServices.RuntimeInformation, Version=4.0.2.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a",
        "System.Runtime.InteropServices.WindowsRuntime, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a",
        "System.Runtime.Numerics, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a",
        "System.Runtime.Numerics, Version=4.0.1.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a",
        "System.Runtime.Remoting, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089",
        "System.Runtime.Remoting, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089",
        "System.Runtime.Serialization, Version=3.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089",
        "System.Runtime.Serialization, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089",
        "System.Runtime.Serialization.Formatters, Version=4.0.2.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a",
        "System.Runtime.Serialization.Formatters.Soap, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a",
        "System.Runtime.Serialization.Formatters.Soap, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a",
        "System.Runtime.Serialization.Json, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a",
        "System.Runtime.Serialization.Json, Version=4.0.1.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a",
        "System.Runtime.Serialization.Primitives, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a",
        "System.Runtime.Serialization.Primitives, Version=4.0.10.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a",
        "System.Runtime.Serialization.Primitives, Version=4.1.3.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a",
        "System.Runtime.Serialization.Primitives, Version=4.2.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a",
        "System.Runtime.Serialization.Xml, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a",
        "System.Runtime.Serialization.Xml, Version=4.0.10.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a",
        "System.Runtime.Serialization.Xml, Version=4.1.3.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a",
        "System.Runtime.WindowsRuntime, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089",
        "System.Runtime.WindowsRuntime.UI.Xaml, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089",
        "System.Security, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a",
        "System.Security, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a",
        "System.Security.Claims, Version=4.0.3.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a",
        "System.Security.Cryptography.Algorithms, Version=4.2.2.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a",
        "System.Security.Cryptography.Algorithms, Version=4.3.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a",
        "System.Security.Cryptography.Csp, Version=4.0.2.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a",
        "System.Security.Cryptography.Encoding, Version=4.0.2.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a",
        "System.Security.Cryptography.Primitives, Version=4.0.2.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a",
        "System.Security.Cryptography.X509Certificates, Version=4.1.2.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a",
        "System.Security.Principal, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a",
        "System.Security.Principal, Version=4.0.1.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a",
        "System.Security.SecureString, Version=4.0.2.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a",
        "System.Security.SecureString, Version=4.1.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a",
        "System.ServiceModel, Version=3.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089",
        "System.ServiceModel, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089",
        "System.ServiceModel.Activation, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35",
        "System.ServiceModel.Activities, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35",
        "System.ServiceModel.Channels, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35",
        "System.ServiceModel.Discovery, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35",
        "System.ServiceModel.Duplex, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a",
        "System.ServiceModel.Http, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a",
        "System.ServiceModel.Http, Version=4.0.10.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a",
        "System.ServiceModel.Install, Version=3.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089",
        "System.ServiceModel.NetTcp, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a",
        "System.ServiceModel.Primitives, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a",
        "System.ServiceModel.Routing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35",
        "System.ServiceModel.Security, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a",
        "System.ServiceModel.WasHosting, Version=3.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089",
        "System.ServiceModel.Web, Version=3.5.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35",
        "System.ServiceModel.Web, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35",
        "System.ServiceProcess, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a",
        "System.ServiceProcess, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a",
        "System.Speech, Version=3.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35",
        "System.Speech, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35",
        "System.Text.Encoding, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a",
        "System.Text.Encoding, Version=4.0.10.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a",
        "System.Text.Encoding, Version=4.0.11.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a",
        "System.Text.Encoding.Extensions, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a",
        "System.Text.Encoding.Extensions, Version=4.0.10.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a",
        "System.Text.Encoding.Extensions, Version=4.0.11.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a",
        "System.Text.RegularExpressions, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a",
        "System.Text.RegularExpressions, Version=4.0.10.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a",
        "System.Text.RegularExpressions, Version=4.1.1.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a",
        "System.Threading, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a",
        "System.Threading, Version=4.0.10.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a",
        "System.Threading, Version=4.0.11.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a",
        "System.Threading.Overlapped, Version=4.0.3.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a",
        "System.Threading.Overlapped, Version=4.1.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a",
        "System.Threading.Tasks, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a",
        "System.Threading.Tasks, Version=4.0.10.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a",
        "System.Threading.Tasks, Version=4.0.11.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a",
        "System.Threading.Tasks.Parallel, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a",
        "System.Threading.Tasks.Parallel, Version=4.0.1.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a",
        "System.Threading.Thread, Version=4.0.2.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a",
        "System.Threading.ThreadPool, Version=4.0.12.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a",
        "System.Threading.Timer, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a",
        "System.Threading.Timer, Version=4.0.1.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a",
        "System.Transactions, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089",
        "System.Transactions, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089",
        "System.ValueTuple, Version=4.0.2.0, Culture=neutral, PublicKeyToken=cc7b13ffcd2ddd51",
        "System.Web, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a",
        "System.Web.Abstractions, Version=3.5.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35",
        "System.Web.Abstractions, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35",
        "System.Web.ApplicationServices, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35",
        "System.Web.DataVisualization, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35",
        "System.Web.DataVisualization.Design, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35",
        "System.Web.DynamicData, Version=3.5.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35",
        "System.Web.DynamicData, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35",
        "System.Web.DynamicData.Design, Version=3.5.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35",
        "System.Web.DynamicData.Design, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35",
        "System.Web.Entity, Version=3.5.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089",
        "System.Web.Entity, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089",
        "System.Web.Entity.Design, Version=3.5.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089",
        "System.Web.Entity.Design, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089",
        "System.Web.Extensions, Version=3.5.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35",
        "System.Web.Extensions, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35",
        "System.Web.Extensions.Design, Version=3.5.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35",
        "System.Web.Extensions.Design, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35",
        "System.Web.Mobile, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a",
        "System.Web.RegularExpressions, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a",
        "System.Web.Routing, Version=3.5.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35",
        "System.Web.Routing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35",
        "System.Web.Services, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a",
        "System.Web.Services, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a",
        "System.Windows, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a",
        "System.Windows.Controls.Ribbon, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35",
        "System.Windows.Forms, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089",
        "System.Windows.Forms, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089",
        "System.Windows.Forms.DataVisualization, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35",
        "System.Windows.Forms.DataVisualization.Design, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35",
        "System.Windows.Input.Manipulations, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089",
        "System.Windows.Presentation, Version=3.5.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089",
        "System.Windows.Presentation, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089",
        "System.Workflow.Activities, Version=3.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35",
        "System.Workflow.Activities, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35",
        "System.Workflow.ComponentModel, Version=3.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35",
        "System.Workflow.ComponentModel, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35",
        "System.Workflow.Runtime, Version=3.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35",
        "System.Workflow.Runtime, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35",
        "System.WorkflowServices, Version=3.5.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35",
        "System.WorkflowServices, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35",
        "System.Xaml, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089",
        "System.Xml, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089",
        "System.Xml, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089",
        "System.Xml.Linq, Version=3.5.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089",
        "System.Xml.Linq, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089",
        "System.Xml.ReaderWriter, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a",
        "System.Xml.ReaderWriter, Version=4.0.10.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a",
        "System.Xml.ReaderWriter, Version=4.1.1.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a",
        "System.Xml.Serialization, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089",
        "System.Xml.XDocument, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a",
        "System.Xml.XDocument, Version=4.0.10.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a",
        "System.Xml.XDocument, Version=4.0.11.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a",
        "System.Xml.XmlDocument, Version=4.0.3.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a",
        "System.Xml.XmlSerializer, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a",
        "System.Xml.XmlSerializer, Version=4.0.10.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a",
        "System.Xml.XmlSerializer, Version=4.0.11.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a",
        "System.Xml.XPath, Version=4.0.3.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a",
        "System.Xml.XPath.XDocument, Version=4.0.3.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a",
        "System.Xml.XPath.XDocument, Version=4.1.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a",
        "UIAutomationClient, Version=3.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35",
        "UIAutomationClient, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35",
        "UIAutomationClientsideProviders, Version=3.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35",
        "UIAutomationClientsideProviders, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35",
        "UIAutomationProvider, Version=3.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35",
        "UIAutomationProvider, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35",
        "UIAutomationTypes, Version=3.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35",
        "UIAutomationTypes, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35",
        "WindowsBase, Version=3.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35",
        "WindowsBase, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35",
        "WindowsFormsIntegration, Version=3.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35",
        "WindowsFormsIntegration, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35",
        "WsatConfig, Version=3.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a",
        "XamlBuildTask, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35"
    };

            public static bool IsBuiltInAssembly(byte[] data)
            {
                if (data is null)
                    return false;

                var module = ModuleDefMD.Load(data);
                bool Result = IsBuiltInAssembly(module.Assembly);
                module.Dispose();
                return Result;
            }

            public static bool IsBuiltInAssembly(IAssembly assembly)
            {
                if (assembly is null)
                    return false;

                string name = assembly.Name;
                if (name.EndsWith(".resources", StringComparison.Ordinal))
                    name = name.Substring(0, name.Length - 10);
                string fullName = $"{name}, Version={assembly.Version}, Culture=neutral, PublicKeyToken={assembly.PublicKeyOrToken.Token}";
                // ignore neutral for built assembly. if it is resource assembly, 'Culture' is not 'neutral'.
                return FullNames.Contains(fullName);
            }
        }

        #endregion

    }
}
