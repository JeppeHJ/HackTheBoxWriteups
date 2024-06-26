Description: 
```
After struggling to secure our secret strings for a long time, we finally figured out the solution to our problem: Make decompilation harder. It should now be impossible to figure out how our programs work!
```

We start running the binary, and it yields

```
./behindthescenes 
./challenge <password>
```

So we can safely assume that we need to find the password.

Lets try running the infamous strings on the binary:
![[Pasted image 20230516105831.png]]
We see the >HTB{%s} which is unsurprising.
Lets try running ltrace to check the system calls by the binary
![[Pasted image 20230516105951.png]]
Looks like anti-debugging measures which makes sense given the description of the challenge. Lets check hexeditor and search for the string password:
![[Pasted image 20230516110101.png]]
We strip the dots and that gives us the flag.

