# Corrupted Notes
## Question:
No idea what the question is. So I used ChatGPT to create a storyline that sounds cool.
</br>
***A catastrophic security breach has corrupted the VANGUARD authentication system, but our cyber-forensics team successfully obtained a memory dump from the compromised module before the final lockdown. Now we need you to investigate this digital crime scene and uncover what OBLIVION tried to hide.***
## Solution:
Download `corrupted_notes`. It's an ELF 64-bit executable. Disassemble it in Ghidra.

<img width="1911" height="848" alt="image" src="https://github.com/user-attachments/assets/e7922bc8-bf11-4e56-98c0-9de80db65a41" />

The executable starts with function **FUN_00101080**. Analyse that function.

<img width="1916" height="876" alt="image" src="https://github.com/user-attachments/assets/98751931-823c-4568-b1d3-415bd1d965c3" />

If we check **FUN_00101220**, it leads us to two decoy flags.

<img width="1919" height="877" alt="image" src="https://github.com/user-attachments/assets/7a1abdc2-586d-412c-b29a-7972fbc5fbb6" />

If we look further in the functions list, we can find something interesting at **FUN_00101260**.

<img width="1910" height="868" alt="image" src="https://github.com/user-attachments/assets/2a115a39-df4d-432b-84fd-48cc302c74d0" />

```
  do {
    local_38[lVar1] = (&DAT_00104040)[lVar1] ^ 0x42;
    lVar1 = lVar1 + 1;
  } while (lVar1 != 0x2a);
  local_e = 0;
```

This part here does a XOR decryption with the key `0x42`. It takes the contents of **DAT_00104040** and performs the decryption. We should trace the contents of **DAT_00104040**.

<img width="1909" height="878" alt="image" src="https://github.com/user-attachments/assets/5fc844ac-a9e4-496b-b6aa-37cb1ddaff15" />

The data starts at address **00104040** with the hex data `18`. It continues being stored with the data `07`, `10`, `0d`, `01`, `0d`, `06`, `07`, etc.

If we XOR each of the hex values from start (`18`) to end (`3f`) with the key `0x42`, we get the flag.

The flag is `ZEROCODEKEY{auth_m0dul3_r3v3rs3d_v4nguard}`.
