<?php

namespace App\Http\Controllers;

use Illuminate\Support\Facades\Cache;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Zrhm7232\Jwt\JWT;
//require_once __DIR__ . '/vendor/autoload.php';

class ExampleController extends Controller
{
    /**
     * Create a new controller instance.
     *
     * @return void
     */
    public function __construct()
    {
        //
    }

    public function generate()
    {
        $jwt = new \Zrhm7232\Jwt\JWT();
        return new JsonResponse($jwt->createToken([
            'username' => 'me'
        ]));
    }

    public function check(Request $request)
    {
        $jwt = new JWT();
        return new JsonResponse($jwt->checkToken($request->input('token')));
    }

    public function invalidate(Request $request)
    {
        $jwt = new JWT();
        return new JsonResponse($jwt->invalidateToken($request->input('token')));
    }

    public function refresh(Request $request)
    {
        $jwt = new JWT();
        return new JsonResponse($jwt->refreshToken($request->input('token')));
    }
}
