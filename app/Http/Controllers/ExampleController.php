<?php

namespace App\Http\Controllers;

use Illuminate\Support\Facades\Cache;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;

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
        return new JsonResponse(createToken([
            'username' => 'me'
        ]));
    }

    public function check(Request $request)
    {
        return new JsonResponse(checkToken($request->input('token')));
    }

    public function invalidate(Request $request)
    {
        return new JsonResponse(invalidateToken($request->input('token')));
    }
}
