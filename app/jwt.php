<?php

function createToken()
{
    $key1 = JWKFactory::createFromKeyFile(
        '/home/zrhm7232/MyFiles/DevTools/rsa_pass.prv',
        'zrhm7232',
        [
            'kid' => 'MIIEpAIBAAKCAQEA9hykVJO/GZtYvuXXVtvVVzx+l9yJmZz97ULo6NCwkA16GF20sL0I6z/TeKkezlTmhruedh+rpuC3S/X68KbZ7hYJIl+D+AeOPUhFf1+IOwh4bHRYbgPl1vP43J9Bag4J7SQ1f7dI4aasyTosoJCBZmXV6WN8JjZGQjzOzVrOYdmRWWQBkBU9eLkGlX3aIt/esSwY+s4HXFe/q8tGqFX3qu1ADAvrF+1gjByuVtAuJetZRHFf7SysfhLCqVVBZY943Jj7nulsH7cYEmo3VYZNyOURCw4XGHpAlX+qkIwyYsIBBaRqGbpLz7IZEJoUgaVfeJ7iDNnf/LZSoIDCIhn0mwIDAQABAoIBACnjAgzrAHFJQTdsQtQjohGw2BLclAay83y4EI/fRM2fnZIcEK6r3aK8QC+fCQEw7fMsZ3HPPhWu1UN2X/kpTJn64h8ZhopmLs07Sai+B5+Ud3pt6sb+ntWQvGBAMo/sR8A2k2xjM2JETdAJuKKzNXLKDjgkmHKgdiC73K6Sr+FzIphBTRPfBDc4q3boK5vTBmb+SlYr86Q84cr0nCCpKji6Hb1Dz9NKOk18vEWU5WvBaQc5VhU8SiBlV0QQjhcBZz+yjDZeQQWfO1Jzui5ISfR83RN7uf7xSWfvkv7xeWv5U/xsWQh6vu3Pcnko+0qu83+IZOZNMefVwhWr78uE8RECgYEA/uZdhexLZjsBGS5IG58ezOR3zF3axqe2OhJiPyl0DjKw4jXrPWTpRHeXc+Aq7PknFUSaC0n52AoVPhl6tBov5bBuQftguODU5JjcmFGpvQkqXUGQrXi/XEwNqfWftUibW4lJ53yy+pPgUFOJPX6nsfTTOb5edrkw6lkJV7elV8cCgYEA9yyRH/HpsgIphWWoWgiVFuT4kndw5J7E6YiOAIj/UMDkZ/MCxVBeo68BZqkcn/MAeN1n2TzTpGCKK/uu/JKsCwugYEp4yTCl3PSMdYTKtCsIAzykQiHVyGVU7KvlpApX2uwehxfHHORGL+oEY82lcstEyPkxRfyb5sznzEsKhI0CgYEAw9jX7rgZTpjzRResS5y8m4zHBvztxUjC2GebmRAOnYIRKh1neyp3mCWS9nM8SAs/HjYxbY8PKhDFNYt6HbspJf+jF4s/S41jxag1hcro8deC91gTA1YNIatFrFqOtUjuJSyc3gGPuru307/7aIZR7oc/a9R63Bl6HfT/Gqh9n60CgYAw/P9CYpLbufv6uVw1g+/wmq79cHjKhwEl+++RAZYArkpWo95Ptw8ax+uyKiBHP0U/rzoO3zRfJtcbwoU6/+LjSYmerAPmdCLbeQiBnjECpmivI4y2orgZQKQlSCh6a6Zf+F5QjhDjlAapJmt6UF7TMqBOaL0wTtGjW8cxQUozXQKBgQCeCYEv9NWmt8/b7riaK95QI2DRbgC9ZnaS5ebd+zcr3ci9DkWnxGdYnaWeA3ExxSdYZSt6x+7hyiCS8ObhK7wKpTr0Q/rzZ0i124ueprVTUqNR5zg4pJeOYmWvQBOuEVbKdQxfym6BtKtZZuf82ofeR+EVqwWPkEQrJjYdzq/SsQ==',
            'alg' => 'RS256',
            'use' => 'sig',
        ]
    );

    // We want to sign the following claims
    $claims = [
        'nbf'     => time(),        // Not before
        'iat'     => time(),        // Issued at
        'exp'     => time() + env('TOKEN_TTL')*60*60, // Expires at
        'iss'     => 'Me',          // Issuer
        'aud'     => 'You',         // Audience
        'sub'     => 'My friend',   // Subject
        'is_root' => true,           // Custom claim
        'username' => 'my'
    ];

    // We have to create a JWS class using the JWSFactory.
    // The payload of this object contains our claims.
    $jws = \Jose\Factory\JWSFactory::createJWS($claims);

    // We add information to create the first signature
    $jws = $jws->addSignatureInformation(
        $key1,
        [
            'alg' => 'RS256',
        ]
    );

    // We create a Signer object with the signature algorithms we want to use
    $signer = \Jose\Signer::createSigner(['RS256']);

    // Then we sign
    $signer->sign($jws);

    $jws = $jws->toCompactJSON(0);

    return $jws;
}