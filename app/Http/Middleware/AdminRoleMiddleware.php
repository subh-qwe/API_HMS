<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;

class AdminRoleMiddleware
{
    public function handle($request, Closure $next)
    {
         // Check if user is authenticated
        if (!Auth::check()) 
        {
            return response()->json([
                'status' => 'error',
                'message' => 'Authentication required'
            ], 401);
        }

        // Check if user has admin role
        if (Auth::user()->role !== 'admin') {
            return response()->json([
                'status' => 'error',
                'message' => 'Unauthorized access. Admin role required.'
            ], 403);
        }

        $response = $next($request);


        return $response;
    }
}
