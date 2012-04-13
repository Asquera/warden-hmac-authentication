Changelog

0.6.0
    Fix failing tests on travis.
	Fix crash on jruby >= 1.6.6
	Short circuit signature validation if no authentication parameters were given (Thanks to skade)
    Add `:ignore_params` to instruct the signer to drop parameters (Thanks to skade)	

0.5.5
    issue 12: fixes errors in header-based authentication

0.5.4
	added :method option for Signer#sign_request (https://github.com/Asquera/warden-hmac-authentication/pull/11) (Thanks to neerfri)
