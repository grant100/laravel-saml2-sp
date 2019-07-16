<?php

//This is variable is an example - Just make sure that the urls in the 'idp' config are ok.
$idp_host = env('SAML2_IDP_HOST', 'https://samltest.id');

return $settings = array(

    /**
     * If 'useRoutes' is set to true, the package defines five new routes:
     *
     *    Method | URI                      | Name
     *    -------|--------------------------|------------------
     *    POST   | {routesPrefix}/acs       | saml_acs
     *    GET    | {routesPrefix}/login     | saml_login
     *    GET    | {routesPrefix}/logout    | saml_logout
     *    GET    | {routesPrefix}/metadata  | saml_metadata
     *    GET    | {routesPrefix}/sls       | saml_sls
     */
    'useRoutes' => true,

    'routesPrefix' => '/saml2',

    /**
     * which middleware group to use for the saml routes
     * Laravel 5.2 will need a group which includes StartSession
     */
    'routesMiddleware' => [],

    /**
     * Indicates how the parameters will be
     * retrieved from the sls request for signature validation
     */
    'retrieveParametersFromServer' => false,

    /**
     * Where to redirect after logout
     */
    'logoutRoute' => '/',

    /**
     * Where to redirect after login if no other option was provided
     */
    'loginRoute' => '/',


    /**
     * Where to redirect after login if no other option was provided
     */
    'errorRoute' => '/',




    /*****
     * One Login Settings
     */



    // If 'strict' is True, then the PHP Toolkit will reject unsigned
    // or unencrypted messages if it expects them signed or encrypted
    // Also will reject the messages if not strictly follow the SAML
    // standard: Destination, NameId, Conditions ... are validated too.
    'strict' => true, //@todo: make this depend on laravel config

    // Enable debug mode (to print errors)
    'debug' => env('APP_DEBUG', false),

    // If 'proxyVars' is True, then the Saml lib will trust proxy headers
    // e.g X-Forwarded-Proto / HTTP_X_FORWARDED_PROTO. This is useful if
    // your application is running behind a load balancer which terminates
    // SSL.
    'proxyVars' => false,

    // Service Provider Data that we are deploying
    'sp' => array(

        // Specifies constraints on the name identifier to be used to
        // represent the requested subject.
        // Take a look on lib/Saml2/Constants.php to see the NameIdFormat supported
        'NameIDFormat' => 'urn:oasis:names:tc:SAML:2.0:nameid-format:persistent',

        // Usually x509cert and privateKey of the SP are provided by files placed at
        // the certs folder. But we can also provide them with the following parameters
        'x509cert' => env('SAML2_SP_x509',
        'MIIDnTCCAoWgAwIBAgIJAPI1H6HsvD6tMA0GCSqGSIb3DQEBCwUAMGUxCzAJBgNV
        BAYTAlVTMQswCQYDVQQIDAJVVDENMAsGA1UEBwwET3JlbTESMBAGA1UECgwJbG9j
        YWxob3N0MRIwEAYDVQQLDAlsb2NhbGhvc3QxEjAQBgNVBAMMCWxvY2FsaG9zdDAe
        Fw0xOTA3MTYxNDUyMjJaFw0xOTA4MTUxNDUyMjJaMGUxCzAJBgNVBAYTAlVTMQsw
        CQYDVQQIDAJVVDENMAsGA1UEBwwET3JlbTESMBAGA1UECgwJbG9jYWxob3N0MRIw
        EAYDVQQLDAlsb2NhbGhvc3QxEjAQBgNVBAMMCWxvY2FsaG9zdDCCASIwDQYJKoZI
        hvcNAQEBBQADggEPADCCAQoCggEBAL7P7yf+XXFJAs+B5pZY90WCHWY2+VsjpYZI
        aUY051z6fyb2z5UmVtk6MFhBAYeUBuwCecVLSrkec0SP8OXgO2cLRZOMICQ/Sho3
        pqS1IIbVMFMHXZhuzUqaic6KeC28R67ZC+L6HlYUFVVWyaFAtzxOYx2W4hK2oNKv
        WIMlxSNXAAoSox1FgUQW2KSF9MUlEpv8Fg8THc4T467JI0I2yoBgKkNZZEznKp3D
        o4RCvCkljDY76quJh26PnSR324xchCxsFwTrIyHd3jbVNL9ZgYAUP+vb8K+daop3
        sQBx/TonJ7EgGxOB/KyVrNWLBbo9fQGxdx/zLh5xNFl2Zza/wskCAwEAAaNQME4w
        HQYDVR0OBBYEFNhwZOJQROTBC0lb0b0d1R9gIg9zMB8GA1UdIwQYMBaAFNhwZOJQ
        ROTBC0lb0b0d1R9gIg9zMAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEB
        AIOqGfKwrR7Tkzr3p229Mk+JUa+qzcYfoVQvYAN3ySwLgS8N0syZFxslfC6/xc3t
        0AZtvO+2gH0FNCkbb1CVHc8BVSZpO2UKYCjSLy8/vxV6r1JR9xZa73aj633l7+WT
        cgobXXZ+o2l/ZGt8lj86Th+nR5tqrEPXCWmjj9S56KUYxYZfE3Yt76GRzrvTEhKp
        x75qXA5u6QEQj4j0Ddppmg30ol3DePOvV3YQDyBZY5+N+MYHzpYtop5+eDRv7jxv
        yHnZjod1ATrok0GD9ZCfZoED5EA0XCE0ZNeYZNGEwvvCrlVF3V6EsPYwnyW7H5+e
        FVlAWxZI3wyzfmh+YA3JF8U='),

        'privateKey' => env('SAML2_SP_PRIVATEKEY',
        'MIIEpAIBAAKCAQEAvs/vJ/5dcUkCz4Hmllj3RYIdZjb5WyOlhkhpRjTnXPp/JvbP
        lSZW2TowWEEBh5QG7AJ5xUtKuR5zRI/w5eA7ZwtFk4wgJD9KGjempLUghtUwUwdd
        mG7NSpqJzop4LbxHrtkL4voeVhQVVVbJoUC3PE5jHZbiErag0q9YgyXFI1cAChKj
        HUWBRBbYpIX0xSUSm/wWDxMdzhPjrskjQjbKgGAqQ1lkTOcqncOjhEK8KSWMNjvq
        q4mHbo+dJHfbjFyELGwXBOsjId3eNtU0v1mBgBQ/69vwr51qinexAHH9OicnsSAb
        E4H8rJWs1YsFuj19AbF3H/MuHnE0WXZnNr/CyQIDAQABAoIBAFWx2w2SHnM3QAzj
        oSSatgrAgeWbAOgenUMumCEQt2u5kIt2QwoQGucaTAYGw+IY5/bssbWat+dltozv
        PFhxGRyRImE+iFzfE6+smKnWMtJ7QmW3pCBGeuprd0KMS6b2rRbooX8Bp8gu4tnd
        zVYfU2vBJKBwV/3hiV61o0HbH6tbq72TBJJr/z+oGOuqvaHJGEWM/Hp8Nyps8Tk8
        D+2HfBguRAqYvPNyYZWu3ype3pUbfuPH1RKo/CCl3sqkZqK7jOS+G9TgcO++wTLY
        7VQI6zCtLrv5or56bcSuQIA5JdgTjxN4YvKcDtY6GE55EtZ3fdSdp4/jKlu0Wy9d
        xc6HX5ECgYEA4A9/I28iEhkNagzNU6yFZ0rAT+2mT1XF9DhN9wEyPRcjbO46XsuE
        UtV7hwNdddUPaMBj9SLZgkTeuvyrk57gD5ee7MtAl+wiLI43Rj2PYwQ+Lj2yNvM6
        JUU6SQ/1cy092RvNyDUgmIdgsLEdmmaQ/MePV/0odWByWoOdiC9k1C0CgYEA2gMg
        zPbfXCzgtEofgxNmFMNLDAEC44NJ6VIYmaYU6oOvE+/YypXgAvLV7dIbHTA+FBbM
        HTVqRCweHUCD5WhOF1JeQ5aDEQOVtiZv4mimpddXeF0+sIGxrasSlecYk2YGUjxv
        gDxrjhDdFMTwxzjmPhJAAWTIqrbAtyJEBFSkPo0CgYEA0dMRT+CZ+nLFkiOtAQfV
        4hYppHA8R51ehMdZk8/l+Tm67h7mQLG8GEpdpOEs29UL2iAZO45IPOs73cYS82pc
        D54AsWXh9qOmmS0RbFDn/2UQygLy6uy57f83hwZP6G1ctv2Hp07BWLWmgbFLtLUK
        X/6OKWslQU5xqHwKwWcIuH0CgYEAlHQ62rdlI6w/myU6ThRgl9Tgfp0VrX1SUDoi
        HEaWyZbAGpBhjJoAP6HCgT5oTjjynNVlSqJ76U4td3feGNItEv54yAdu2qAZSz7j
        Q0ZF7Ho1yvWb4a9/ISZz8nW6K2z28vrKZoU+LDBZi3IMD200g6IDya8qYe0uT8Za
        kKReb2UCgYAi43T9Mab3DSgTNpTRTXj8MR417xDFFP1C7FHO1kvkrhciA9RuvjOR
        tex0LvSg6iiCQqRioVFwfi3G/kHeDiHLBPMq+3GLD+qXYl9ysgMyRsv4z/CXMcBS
        E32S4U/ITOQfO+4f8sa6rq0mopl2sXZK6+1sv0BwLvOwc9p0ufjzxg=='),

        // Identifier (URI) of the SP entity.
        // Leave blank to use the 'saml_metadata' route.
        'entityId' => env('SAML2_SP_ENTITYID','php:saml2:test:1'),

        // Specifies info about where and how the <AuthnResponse> message MUST be
        // returned to the requester, in this case our SP.
        'assertionConsumerService' => array(
            // URL Location where the <Response> from the IdP will be returned,
            // using HTTP-POST binding.
            // Leave blank to use the 'saml_acs' route
            'url' => '',
        ),
        // Specifies info about where and how the <Logout Response> message MUST be
        // returned to the requester, in this case our SP.
        // Remove this part to not include any URL Location in the metadata.
        'singleLogoutService' => array(
            // URL Location where the <Response> from the IdP will be returned,
            // using HTTP-Redirect binding.
            // Leave blank to use the 'saml_sls' route
            'url' => '',
        ),
    ),

    // Identity Provider Data that we want connect with our SP
    'idp' => array(
        // Identifier of the IdP entity  (must be a URI)
        'entityId' => env('SAML2_IDP_ENTITYID', $idp_host . '/saml/idp'),
        // SSO endpoint info of the IdP. (Authentication Request protocol)
        'singleSignOnService' => array(
            // URL Target of the IdP where the SP will send the Authentication Request Message,
            // using HTTP-Redirect binding.
            'url' => $idp_host . '/idp/profile/SAML2/Redirect/SSO',
        ),
        // SLO endpoint info of the IdP.
        'singleLogoutService' => array(
            // URL Location of the IdP where the SP will send the SLO Request,
            // using HTTP-Redirect binding.
            'url' => $idp_host . '/idp/profile/SAML2/Redirect/SLO',
        ),
        // Public x509 certificate of the IdP
        'x509cert' => env('SAML2_IDP_x509', 
        'MIIDEjCCAfqgAwIBAgIVAMECQ1tjghafm5OxWDh9hwZfxthWMA0GCSqGSIb3DQEB
        CwUAMBYxFDASBgNVBAMMC3NhbWx0ZXN0LmlkMB4XDTE4MDgyNDIxMTQwOVoXDTM4
        MDgyNDIxMTQwOVowFjEUMBIGA1UEAwwLc2FtbHRlc3QuaWQwggEiMA0GCSqGSIb3
        DQEBAQUAA4IBDwAwggEKAoIBAQC0Z4QX1NFKs71ufbQwoQoW7qkNAJRIANGA4iM0
        ThYghul3pC+FwrGv37aTxWXfA1UG9njKbbDreiDAZKngCgyjxj0uJ4lArgkr4AOE
        jj5zXA81uGHARfUBctvQcsZpBIxDOvUUImAl+3NqLgMGF2fktxMG7kX3GEVNc1kl
        bN3dfYsaw5dUrw25DheL9np7G/+28GwHPvLb4aptOiONbCaVvh9UMHEA9F7c0zfF
        /cL5fOpdVa54wTI0u12CsFKt78h6lEGG5jUs/qX9clZncJM7EFkN3imPPy+0HC8n
        spXiH/MZW8o2cqWRkrw3MzBZW3Ojk5nQj40V6NUbjb7kfejzAgMBAAGjVzBVMB0G
        A1UdDgQWBBQT6Y9J3Tw/hOGc8PNV7JEE4k2ZNTA0BgNVHREELTArggtzYW1sdGVz
        dC5pZIYcaHR0cHM6Ly9zYW1sdGVzdC5pZC9zYW1sL2lkcDANBgkqhkiG9w0BAQsF
        AAOCAQEASk3guKfTkVhEaIVvxEPNR2w3vWt3fwmwJCccW98XXLWgNbu3YaMb2RSn
        7Th4p3h+mfyk2don6au7Uyzc1Jd39RNv80TG5iQoxfCgphy1FYmmdaSfO8wvDtHT
        TNiLArAxOYtzfYbzb5QrNNH/gQEN8RJaEf/g/1GTw9x/103dSMK0RXtl+fRs2nbl
        D1JJKSQ3AdhxK/weP3aUPtLxVVJ9wMOQOfcy02l+hHMb6uAjsPOpOVKqi3M8XmcU
        ZOpx4swtgGdeoSpeRyrtMvRwdcciNBp9UZome44qZAYH1iqrpmmjsfI9pJItsgWu
        3kXPjhSfj1AJGR1l9JGvJrHki1iHTA=='),
        /*
         *  Instead of use the whole x509cert you can use a fingerprint
         *  (openssl x509 -noout -fingerprint -in "idp.crt" to generate it)
         */
        // 'certFingerprint' => '',
    ),



    /***
     *
     *  OneLogin advanced settings
     *
     *
     */
    // Security settings
    'security' => array(

        /** signatures and encryptions offered */

        // Indicates that the nameID of the <samlp:logoutRequest> sent by this SP
        // will be encrypted.
        'nameIdEncrypted' => false,

        // Indicates whether the <samlp:AuthnRequest> messages sent by this SP
        // will be signed.              [The Metadata of the SP will offer this info]
        'authnRequestsSigned' => true,

        // Indicates whether the <samlp:logoutRequest> messages sent by this SP
        // will be signed.
        'logoutRequestSigned' => false,

        // Indicates whether the <samlp:logoutResponse> messages sent by this SP
        // will be signed.
        'logoutResponseSigned' => false,

        /* Sign the Metadata
         False || True (use sp certs) || array (
                                                    keyFileName => 'metadata.key',
                                                    certFileName => 'metadata.crt'
                                                )
        */
        'signMetadata' => false,


        /** signatures and encryptions required **/

        // Indicates a requirement for the <samlp:Response>, <samlp:LogoutRequest> and
        // <samlp:LogoutResponse> elements received by this SP to be signed.
        'wantMessagesSigned' => false,

        // Indicates a requirement for the <saml:Assertion> elements received by
        // this SP to be signed.        [The Metadata of the SP will offer this info]
        'wantAssertionsSigned' => false,

        // Indicates a requirement for the NameID received by
        // this SP to be encrypted.
        'wantNameIdEncrypted' => false,

        // Authentication context.
        // Set to false and no AuthContext will be sent in the AuthNRequest,
        // Set true or don't present thi parameter and you will get an AuthContext 'exact' 'urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport'
        // Set an array with the possible auth context values: array ('urn:oasis:names:tc:SAML:2.0:ac:classes:Password', 'urn:oasis:names:tc:SAML:2.0:ac:classes:X509'),
        'requestedAuthnContext' => true,
    ),

    // Contact information template, it is recommended to suply a technical and support contacts
    'contactPerson' => array(
        'technical' => array(
            'givenName' => 'name',
            'emailAddress' => 'no@reply.com'
        ),
        'support' => array(
            'givenName' => 'Support',
            'emailAddress' => 'no@reply.com'
        ),
    ),

    // Organization information template, the info in en_US lang is recomended, add more if required
    'organization' => array(
        'en-US' => array(
            'name' => 'Name',
            'displayname' => 'Display Name',
            'url' => 'http://url'
        ),
    ),

/* Interoperable SAML 2.0 Web Browser SSO Profile [saml2int]   http://saml2int.org/profile/current

   'authnRequestsSigned' => false,    // SP SHOULD NOT sign the <samlp:AuthnRequest>,
                                      // MUST NOT assume that the IdP validates the sign
   'wantAssertionsSigned' => true,
   'wantAssertionsEncrypted' => true, // MUST be enabled if SSL/HTTPs is disabled
   'wantNameIdEncrypted' => false,
*/

);
