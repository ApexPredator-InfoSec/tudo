# tudo
Solution for bmdyy's tudo challenge

The challenge can be found here: https://github.com/bmdyy/tudo

Clone bmdyy's repo and follow his instructions to setup the contianer. The repo contains his solution's that are more elegant than mine.

This repo contains one solution with an auth bypass for normal user and 1 RCE. It skips the elevate from normal user to admin portion of the challenge as this RCE does not require admin rights in the web applicaiton.

The auth bypass exploits a SQLi in the username parameter of the forgotusername.php page. After recovering a username it then sends a password reset request for the user account. It then leverages the username SQLi again to recover the password reset token to then reset the user acocunt's password.

The RCE bypasses file exentison checks in upload_image.php to upload a PHP reverse shell. This page fails to properly implement checks to ensure the user is an admin and can be exploited by a normal user.

A PoC to retrieve the admin user's cookie is included. This would allow an attacker to use the admin's cookie to log to the web application as the admin. It exploits a lack of input sanitization in the description field of user accounts to perform XSS.
