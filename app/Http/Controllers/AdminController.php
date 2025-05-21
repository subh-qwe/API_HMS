<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;

class AdminController extends Controller
{
    public function __construct()
    {
        // The jwt.auth middleware ensures that the requests to these routes are authenticated using a JWT token.
        // It is necessary to implement this if you want to protect the routes from unauthorized access.
        $this->middleware('jwt.auth');
    }

    public function adminActions()
    {
      
        if(Auth::user()->role == 'admin') {
        return response()->json([
            'status' => 'success',
            'message' => 'This is admin dashboard'
        ]);
      }
      else {
        return response()->json([
            'status' => 'error',
            'message' => 'Unauthorized access'
        ], 401);
      }
    }


    public function logout()
    {
        Auth::logout();
        return response()->json([
            'status' => 'success',
            'message' => 'Successfully logged out'
        ], 200);
    }
}
