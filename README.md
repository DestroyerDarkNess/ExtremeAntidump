# ExtremeAntidump
A powerful anti-dump, which works even on packaged assemblies.

how to use: 

```C#
//Csharp
Antidump.AntidumpV2.Initialize();
```
```VB
'VB
Antidump.AntidumpV2.Initialize()
```

Or create your own implementation with dnlib.

## Frequently asked question:

- **Why should I use this antidump instead of the usual one? (ConfuserEx, general public antidumps)**

The traditional antidump works fine on applications that are not packed. But when you pack your assembly, the traditional antidump doesn't work, so dumping your application is a problem.

That's where Extreme Antidump was born, which is based on the original Extreme Dumpper code (credits to [wwh1004](https://github.com/wwh1004/ExtremeDumper) for his excellent work).

My private protector Hydra Protector, has different packers, some of my own. In particular my native Packer, in which the traditional antidump didn't work.

That's why I decided to do this, and I share it so that anyone can use it as they like. If you want, give the repository a star. ✨✨

## Extreme Antidump Test Images :

**Assembly :**

![image](https://github.com/user-attachments/assets/914805c2-264f-4cb3-bd7b-96c4e77dd6e8)

**Protector Preset :**

![image](https://github.com/user-attachments/assets/e3f7dad3-0245-45f8-91cb-2340c3800a10)

![image](https://github.com/user-attachments/assets/327d29e8-1cec-4be6-b638-ea8adb9cf7c5)

**Output**

![image](https://github.com/user-attachments/assets/4a7a8119-d644-43d2-829f-791ab00120ac)

![image](https://github.com/user-attachments/assets/dd586be2-c85c-4b01-a4f3-7efc3e6b6387)

**DUMP Folder**

![image](https://github.com/user-attachments/assets/27929fbd-a108-40b3-81ea-6cd00638f547)

