# KeyAuth-CPP-Example
KeyAuth CPP Example

Video on how to add KeyAuth to your own application https://youtu.be/GB4XW_TsHqA

Video to use Web Loader (control loader from customer panel) https://youtu.be/9-qgmsUUCK4

If you get an *The object or library file '' was created by a different version of the compiler* error, replace the library_x64.lib with this one https://cdn.keyauth.win/library_x64.lib

**For other issues, join Discord server https://keyauth.win/discord and look at the select menu for C++ common issues inside the message in the #faq-common-issues channel**

**Security practices**

* Utilize obfuscation provided by companies such as VMProtect or Themida (utilize their SDKs too for greater protection)
* Preform frequent integrity checks to ensure the memory of the program has not been modified
* Don't write the bytes of a file you've downloaded to disk if you don't want that file to be retrieved by the user. Rather, execute the file in memory and erase it from memory the moment execution finishes

*KeyAuth is provided in Source Code Form. The burden of client-side protection is on you the software developer, as it would be with any authentication system.*

**What is KeyAuth?**

KeyAuth is an Open source authentication system with cloud hosting plans as well. Client SDKs available for C++, C#, Python, Rust, PHP, and VB.NET.
KeyAuth several unique features such as memory streaming, webhook function where you can send requests to API without leaking the API, discord webhook notifications, ban the user securely through the application at your discretion.
Feel free to join https://keyauth.win/discord/ if you have questions or suggestions.
