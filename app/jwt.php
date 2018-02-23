<?php

    function createToken($custom_claims = [])
    {
        $key = \Jose\Factory\JWKFactory::createFromKeyFile(
            env('PRIVATE_KEYGEN_PATH'),
            env('KEYGEN_PASS_PHRASE'),
            [
                'alg' => 'RS256',
                'use' => 'sig',
            ]
        );

        // We want to sign the following claims
        $claims = [
            'nbf'     => time(),        // Not before
            'iat'     => time(),        // Issued at
            'exp'     => time() + env('TOKEN_TTL')*60*60, // Expires at
        ];

        $claims = array_merge($claims, $custom_claims);

        // We have to create a JWS class using the JWSFactory.
        // The payload of this object contains our claims.
        $jws = \Jose\Factory\JWSFactory::createJWS($claims);

        // We add information to create the first signature
        $jws = $jws->addSignatureInformation(
            $key,
            [
                'alg' => 'RS256',
            ]
        );

        // We create a Signer object with the signature algorithms we want to use
        $signer = \Jose\Signer::createSigner(['RS256']);

        // Then we sign
        $signer->sign($jws);

        $jws = $jws->toCompactJSON(0);

        return [
            'data' => $jws
        ];
    }

    function checkToken($input)
    {
        $key = \Jose\Factory\JWKFactory::createFromKeyFile(
            env('PRIVATE_KEYGEN_PATH'),
            env('KEYGEN_PASS_PHRASE'),
            [
                'alg' => 'RS256',
                'use' => 'sig',
            ]
        );

        $claim_checker_list = [
            'exp',
            'iat',
            'nbf'
        ];
        $header_checker_list = [
            'crit'
        ];

        $checker_manager = \Jose\Factory\CheckerManagerFactory::createClaimCheckerManager($claim_checker_list, $header_checker_list);

        $loader = new \Jose\Loader();
        try {
            $jws_raw = $loader->loadAndVerifySignatureUsingKey(
                $input,
                $key,
                ['RS256'],
                $signature_index
            );
        } catch (\InvalidArgumentException $ex) {
            return [
                'status' => false,
                'message' => $ex->getMessage()
            ];
        }

        try {
            $checker_manager->checkJWS($jws_raw, $signature_index);
        } catch (\InvalidArgumentException $ex) {
            return [
                'status' => false,
                'message' => $ex->getMessage()
            ];
        }

        if (\Illuminate\Support\Facades\Cache::has($input)) {
            $invalid = \Illuminate\Support\Facades\Cache::get($input);
            if ($invalid) {
                return [
                    'status' => false,
                    'message' => 'token is invalid'
                ];
            }
        }
        return [
            'status' => true,
            'claims' => $jws_raw->getClaims()
        ];
    }

    function invalidateToken($input)
    {
        \Illuminate\Support\Facades\Cache::forever($input, true);

        return [
            'status' => true,
            'message' => 'successfully invalidated'
        ];
    }