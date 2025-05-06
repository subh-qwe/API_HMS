<?php

namespace App\Http\Middleware;

use Closure;
use Exception;
use App\Models\UserRegistration;
use Auth;

class JwtMiddleware
{
    public function handle($request, Closure $next, $guard = null)
    {
        try {
            $user = Auth::payload();
        } catch (Exception $e) {
            return response()->json([
                'status' => 'error',
                'message' => 'Unauthorized: ' . $e->getMessage()
            ], 401);
        }

        return $next($request);
    }
}
