<?php

namespace App\Http\Middleware;

use Closure;
use Tymon\JWTAuth\Facades\JWTAuth;

class JwtMiddleware
{
    public function handle($request, Closure $next, $role = null)
    {
        try {
            $user = JWTAuth::parseToken()->authenticate(); 

            if (!$user) {
                return response()->json(['error' => 'User not found'], 401);
            }

            if ($role && $user->role !== $role) {
                return response()->json(['error' => 'Unauthorized role access'], 403);
            }

            // You can attach user to request if needed
            $request->auth_user = $user;

        } catch (\Exception $e) {
            return response()->json(['error' => 'Unauthorized', 'message' => $e->getMessage()], 401);
        }

        return $next($request);
    }
}
